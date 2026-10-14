package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

func recoveredTempName(parent string) string {
	return filepath.Join(parent, ".stl-handoff-"+strings.Repeat("a", 32)+".tmp")
}

func stagedCrashWireGuard(t *testing.T) (*runtimeOptions, string, string, domain.Link, string) {
	t.Helper()
	root, parent, fake, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "b", "10.70.21.0/31")
	source := recoveredTempName(parent)
	opts.writeHandoff = func(_ string, body []byte) error {
		if err := os.WriteFile(source, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return errors.New("injected crash after staging private temporary")
	}
	code, stdout, _ := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output",
		filepath.Join(parent, "unfinished.stl"), "--json"}, creatorRequest(t, link), opts)
	if code == 0 || strings.Contains(stdout, "stl://") {
		t.Fatal("sender crash fixture unexpectedly succeeded or leaked URL")
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snap.PendingSenders) != 1 || len(snap.Links) != 0 || len(fake.applies) != 0 {
		t.Fatalf("sender crash fixture did not preserve pending without host mutation: %v", err)
	}
	return opts, source, filepath.Join(parent, "recovered.stl"), link, root
}

func TestRecoverWireGuardOriginalCrashTemporaryWithExactPendingAndKey(t *testing.T) {
	opts, source, output, link, root := stagedCrashWireGuard(t)
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := creatorRun([]string{"link", "recover-handoff", "--source", source,
		"--output", output, "--confirm", string(link.ID), "--json"}, "", opts)
	if code != 0 || stderr != "" {
		t.Fatalf("exact crash recovery denied: %d %q %q", code, stdout, stderr)
	}
	var got handoffRecoveryResult
	if err := json.Unmarshal([]byte(stdout), &got); err != nil ||
		got.SchemaVersion != 1 || !got.Recovered || got.LinkID != link.ID ||
		got.Backend != domain.BackendWireGuard || got.HandoffFile != output {
		t.Fatalf("incorrect redacted recovery result: %+v %v", got, err)
	}
	if strings.Contains(stdout, "stl://") || strings.Contains(stdout, "recipient_secret") {
		t.Fatal("SENSITIVE pairing material leaked from recovery JSON")
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery did not preserve EXACT original protected handoff bytes")
	}
	if _, err = os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovered original crash temporary was not atomically moved")
	}
	file, err := os.Lstat(output)
	if err != nil || file.Mode().Perm() != 0o600 || !file.Mode().IsRegular() {
		t.Fatal("recovered handoff lost protected regular-file mode")
	}
	if _, err := state.NewFileStore(root).Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Recovery only renamed the original handoff; normal sender Resume still
	// requires the original digest and confirms the canonical Engine converge.
	encoded := strings.TrimSuffix(string(after), "\n")
	code, stdout, stderr = creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm",
		setupLinkConfirmation(encoded), "--json"}, string(after), opts)
	if code != 0 || stderr != "" {
		t.Fatalf("recovered original cannot resume: %d %q %q", code, stdout, stderr)
	}
	committed, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(committed.PendingSenders) != 0 || len(committed.Links) != 1 ||
		committed.Links[0].Desired.ID != link.ID {
		t.Fatal("recovered sender did not converge after explicit Resume", err)
	}
}

func TestRecoverHandoffRefusesAmbiguousOrUnsafeFilesWithoutMoving(t *testing.T) {
	for _, kind := range []string{"different-confirm", "wrong-source-name", "world-readable",
		"symlink", "hardlink", "occupied-target", "modified-original", "missing-sender-key",
		"committed-sender", "no-pending", "different-directory"} {
		t.Run(kind, func(t *testing.T) {
			opts, source, output, link, root := stagedCrashWireGuard(t)
			switch kind {
			case "different-confirm":
				link.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "wrong-source-name":
				bad := filepath.Join(filepath.Dir(source), ".stl-handoff-not-a-nonce.tmp")
				if err := os.Rename(source, bad); err != nil {
					t.Fatal(err)
				}
				source = bad
			case "world-readable":
				if err := os.Chmod(source, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				bad := filepath.Join(filepath.Dir(source), ".stl-handoff-"+strings.Repeat("b", 32)+".tmp")
				if err := os.Symlink(source, bad); err != nil {
					t.Fatal(err)
				}
				source = bad
			case "hardlink":
				second := filepath.Join(filepath.Dir(source), "other-private-file")
				if err := os.Link(source, second); err != nil {
					t.Fatal(err)
				}
			case "occupied-target":
				if err := os.WriteFile(output, []byte("NO CLOBBER"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "modified-original":
				data, _ := os.ReadFile(source)
				data[15] ^= 1
				if err := os.WriteFile(source, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing-sender-key":
				if err := os.Remove(filepath.Join(root, "credentials", string(link.ID)+".wgkey")); err != nil {
					t.Fatal(err)
				}
			case "committed-sender":
				data, _ := os.ReadFile(source)
				encoded := strings.TrimSuffix(string(data), "\n")
				code, _, _ := creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm",
					setupLinkConfirmation(encoded), "--json"}, string(data), opts)
				if code != 0 {
					t.Fatal("could not create committed recovery fixture")
				}
			case "no-pending":
				if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
					s.DeletePendingSender(link.ID)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case "different-directory":
				other := filepath.Join(t.TempDir(), "private")
				if err := os.Mkdir(other, 0o700); err != nil {
					t.Fatal(err)
				}
				output = filepath.Join(other, "recovered.stl")
			}
			code, stdout, stderr := creatorRun([]string{"link", "recover-handoff", "--source", source,
				"--output", output, "--confirm", string(link.ID), "--json"}, "", opts)
			if code == 0 || strings.Contains(stdout+stderr, "stl://") ||
				strings.Contains(stdout+stderr, "recipient_secret") {
				t.Fatalf("unsafe recovery case unexpectedly succeeded or leaked: %s %q %q", kind, stdout, stderr)
			}
			if kind == "occupied-target" {
				original, err := os.ReadFile(output)
				if err != nil || string(original) != "NO CLOBBER" {
					t.Fatal("failed recovery overwrote an existing file")
				}
			}
			if kind != "different-confirm" && kind != "different-directory" {
				if _, err := os.Lstat(source); err != nil {
					t.Fatal("failed recovery deleted the protected temporary")
				}
			}
		})
	}
}

func TestRecoverIPsecSenderHandoffRequiresExactOriginAndProtectedPSK(t *testing.T) {
	for _, kind := range []string{"sender", "recipient-origin", "missing-psk", "wrong-digest"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			parent := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			source, output := recoveredTempName(parent), filepath.Join(parent, "recovered-ipsec.stl")
			registry, err := backend.NewRegistry()
			if err != nil {
				t.Fatal(err)
			}
			engine, err := app.New(registry, state.NewFileStore(root), state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			keys, err := ipsecbackend.NewPSKStore(root)
			if err != nil {
				t.Fatal(err)
			}
			link := domain.Link{
				ID:      "lnk_cccccccccccccccccccccccccccccccc",
				Backend: domain.BackendIPsec, Encapsulation: domain.EncapESP,
				Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("192.0.2.11")},
				Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.90.42.0/31"), Peer: netip.MustParsePrefix("10.90.42.1/31")},
			}
			offer, err := pairing.NewQuickOffer(link, bytes.Repeat([]byte{0x55}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer offer.ClearRecipientCredential()
			url, err := offer.EncodeSetupLink()
			if err != nil {
				t.Fatal(err)
			}
			if kind == "recipient-origin" {
				if err := engine.StageIPsecRecipient(context.Background(), url, setupLinkConfirmation(url), keys); err != nil {
					t.Fatal(err)
				}
			} else {
				err := engine.StageIPsecSender(context.Background(), offer, keys, func(actual string) error {
					if actual != url {
						t.Fatal("unexpected staged URL")
					}
					return errors.New("simulated crash before handoff publication")
				})
				if err == nil {
					t.Fatal("test must stop before IPsec activation")
				}
			}
			if err := os.WriteFile(source, []byte(url+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "missing-psk" {
				if err := os.Remove(filepath.Join(root, "credentials", string(link.ID)+".ipsecpsk")); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "wrong-digest" {
				other, _ := pairing.NewQuickOffer(link, bytes.Repeat([]byte{0x56}, 32))
				different, _ := other.EncodeSetupLink()
				other.ClearRecipientCredential()
				if err := os.WriteFile(source, []byte(different+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			opts := &runtimeOptions{stateRoot: root}
			code, stdout, stderr := creatorRun([]string{"link", "recover-handoff", "--source", source, "--output",
				output, "--confirm", string(link.ID), "--json"}, "", opts)
			if kind == "sender" {
				if code != 0 || stderr != "" {
					t.Fatalf("original IPsec sender recovery refused: %d %q %q", code, stdout, stderr)
				}
				data, err := os.ReadFile(output)
				if err != nil || string(data) != url+"\n" {
					t.Fatal("IPsec recovery did not preserve exact PSK handoff", err)
				}
			} else {
				if code == 0 || strings.Contains(stdout+stderr, url) {
					t.Fatalf("unsafe IPsec sender recovery accepted or leaked: %s %d %q", kind, code, stdout)
				}
				if _, err := os.Stat(source); err != nil {
					t.Fatal("unsafe recovery discarded original temporary", err)
				}
			}
			after, err := state.NewFileStore(root).Load(context.Background())
			if err != nil || len(after.Links) != 0 || len(after.PendingIPsec) != 1 {
				t.Fatal("handoff-only recovery mutated canonical IPsec Link state", err)
			}
		})
	}
}

// Assert that known non-crash states do not acquire sender authority merely
// because a protected file and a matching public link appear to exist.
func TestRecoverHandoffOrphanWireGuardCredentialDoesNotAuthorizePublish(t *testing.T) {
	root, parent, _, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "d", "10.70.23.0/31")
	local, ownPub, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer local.Zeroize()
	receiver, peerPub, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Zeroize()
	link.Backend, link.Encapsulation = domain.BackendWireGuard, domain.EncapUDP
	link.WireGuard = domain.WireGuardOptions{LocalPublicKey: ownPub, PeerPublicKey: peerPub,
		ListenPort: 51843, PeerPort: 51844}
	keys, err := wgbackend.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.PutRecipient(link.ID, []byte(local.SecretWireValue()), ownPub); err != nil {
		t.Fatal(err)
	}
	offer, err := pairing.NewQuickOffer(link, []byte(receiver.SecretWireValue()))
	if err != nil {
		t.Fatal(err)
	}
	defer offer.ClearRecipientCredential()
	url, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	source, output := recoveredTempName(parent), filepath.Join(parent, "orphan.stl")
	if err := os.WriteFile(source, []byte(url+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := creatorRun([]string{"link", "recover-handoff", "--source", source, "--output",
		output, "--confirm", string(link.ID), "--json"}, "", opts)
	if code == 0 || strings.Contains(stdout, "stl://") {
		t.Fatal("orphan protected key without durable intent authorized a handoff")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan key recovery created a public handoff")
	}
}

// A same-owner process can change an untrusted staging inode while an
// operator is confirming it. Publishing must recheck content inside the
// original file descriptor, not only size/inode/path identity.
func TestRecoverHandoffRejectsInPlaceContentRewriteBeforePublish(t *testing.T) {
	_, source, output, _, _ := stagedCrashWireGuard(t)
	initial, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	err = withVerifiedHandoffTemporary(source, output, func(raw string, publish func() error) error {
		if raw != strings.TrimSuffix(string(initial), "\n") {
			t.Fatal("incorrect initial protected temporary data")
		}
		changed := bytes.Clone(initial)
		changed[12] ^= 1
		if err := os.WriteFile(source, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		return publish()
	})
	if err == nil {
		t.Fatal("same-inode same-size rewritten handoff was published")
	}
	if _, err := os.Lstat(source); err != nil {
		t.Fatal("failed recovery lost the modified source", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed recovery created a destination")
	}
}

// Legacy snapshots may contain an IPsec tombstone and a WireGuard pending
// sender for the same Link ID. Such snapshots now fail validation. Recovery
// must preserve the original sensitive crash file, not claim success.
func TestRecoverWireGuardIPsecRetirementOverlapLeavesOriginalSource(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "receipt_not_retired"
		if retired {
			name = "receipt_retired"
		}
		t.Run(name, func(t *testing.T) {
			opts, source, target, link, root := stagedCrashWireGuard(t)
			store := state.NewFileStore(root)
			snap, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte("legacy-IPsec-retirement-test"))
			snap.IPsecRemovalReceipts = append(snap.IPsecRemovalReceipts, state.IPsecRemovalReceipt{
				LinkID: link.ID, PSKSHA256: hex.EncodeToString(sum[:]), Retired: retired,
			})
			// Simulate a *historical* durable snapshot that slipped through the
			// previous cross-backend validator, without using the now-protected
			// state Update (which rightly refuses this overlap).
			serialized, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "state.json"), serialized, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(context.Background()); err == nil {
				t.Fatal("cross-backend retired+pending collision was still considered valid state")
			}
			before, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := creatorRun([]string{
				"link", "recover-handoff", "--source", source, "--output", target, "--confirm", string(link.ID), "--json",
			}, "", opts)
			if code == 0 || stderr != "" || strings.Contains(stdout, "stl://") ||
				strings.Contains(stdout, "recipient_secret") {
				t.Fatalf("IPsec retired Link ID authorized recovery or leaked secret: %d %q %q", code, stdout, stderr)
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected legacy overlap modified or removed private crash handoff", err)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid same-ID legacy state published a SENSITIVE target")
			}
		})
	}
}

// A FIFO with an otherwise canonical temporary name must never hang the
// CLI while waiting for a writer. Keep the test itself bounded so a future
// accidental removal of O_NONBLOCK gives prompt, actionable CI feedback.
func TestRecoverCanonicalNamedFIFORejectsPromptlyWithoutDisclosure(t *testing.T) {
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := recoveredTempName(privateDir)
	target := filepath.Join(privateDir, "must-not-publish.stl")
	if err := unix.Mkfifo(source, 0o600); err != nil {
		t.Fatal(err)
	}
	id := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	root := filepath.Join(t.TempDir(), "state")
	type response struct {
		code           int
		stdout, stderr string
	}
	finished := make(chan response, 1)
	go func() {
		code, stdout, stderr := creatorRun([]string{
			"link", "recover-handoff", "--source", source, "--output", target, "--confirm", string(id), "--json",
		}, "", &runtimeOptions{stateRoot: root})
		finished <- response{code: code, stdout: stdout, stderr: stderr}
	}()
	var got response
	select {
	case got = <-finished:
	case <-time.After(2 * time.Second):
		// If a regressed blocking FIFO reader exists, opening a writer can
		// free it so the test does not strand a blocked goroutine.
		if fd, err := unix.Open(source, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err == nil {
			unix.Close(fd)
		}
		t.Fatal("canonical-name FIFO blocked recovery before regular-file validation")
	}
	if got.code == 0 || got.stderr != "" ||
		strings.Contains(got.stdout, "stl://") ||
		strings.Contains(got.stdout, "recipient_secret") ||
		strings.Contains(got.stdout, "private_key") {
		t.Fatalf("FIFO recovery unsafe or disclosed material: code=%d out=%q err=%q", got.code, got.stdout, got.stderr)
	}
	var payload linkReadErrorResponse
	if err := json.Unmarshal([]byte(got.stdout), &payload); err != nil ||
		payload.Error == nil || payload.Error.Code == "" {
		t.Fatal("FIFO did not produce a bounded redacted error envelope", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("FIFO unexpectedly generated a SENSITIVE destination")
	}
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("FIFO source was changed or removed during rejected recovery", err)
	}
}
