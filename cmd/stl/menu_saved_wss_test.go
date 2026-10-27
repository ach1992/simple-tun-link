//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func savedExternalWSSFixture(t *testing.T) (*runtimeOptions, domain.Link, domain.Link, string, string) {
	t.Helper()
	request := testWSSCreateRequest()
	senderKey, senderPub, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer senderKey.Zeroize()
	peerKey, peerPub, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer peerKey.Zeroize()
	sender, receiver, err := makeWSSPair(request, request.LinkID, senderPub, peerPub)
	if err != nil {
		t.Fatal(err)
	}
	server, client, err := wss.GeneratePair(sender.ID, "198.51.100.21")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	defer client.Clear()
	offer := wssOffer{SchemaVersion: 1, Sender: sender, Receiver: receiver,
		ReceiverWGKey: peerKey.SecretWireValue(), ReceiverTLS: client}
	b, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.clear()
	root := filepath.Join(t.TempDir(), "state")
	opts := &runtimeOptions{stateRoot: root}
	digest := strings.Repeat("a", 64)
	if err := state.NewFileStore(root).Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: sender, WSSOrigin: strings.Repeat("b", 32),
			WSSFiles: state.WSSFileIdentity{Certificate: digest, TLSKey: digest, TrustCA: digest, Authorization: digest, Restrictions: digest}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "cli")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(external, "receiver-original.json")
	if err := writeSensitiveHandoff(path, append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	if mode, err := os.Stat(path); err != nil || mode.Mode().Perm() != 0o600 {
		t.Fatal("external offer not private")
	}
	return opts, sender, receiver, path, string(b)
}

func TestExternalWSSOriginalOfferMatchesSavedSenderAndCannotBeReissuedOnReceiver(t *testing.T) {
	opts, sender, receiver, path, raw := savedExternalWSSFixture(t)
	got, err := validatedExternalWSSMenuOffer(opts, sender, path)
	if err != nil || got != raw {
		t.Fatal("exact original CLI sender offer was not accepted", err)
	}
	if _, err := validatedSavedProtectedMenuOffer(opts, sender); !errors.Is(err, errProtectedMenuOfferMissing) {
		t.Fatalf("absent menu-owned offer was incorrectly reported as untrusted or present: %v", err)
	}
	if _, err := validatedExternalWSSMenuOffer(opts, receiver, path); err == nil {
		t.Fatal("receiver incorrectly allowed to re-export the sender's private offer")
	}
	if _, err := validatedExternalWSSMenuOffer(opts, sender, filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing private offer accepted")
	}
	symlink := path + "-symlink"
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedExternalWSSMenuOffer(opts, sender, symlink); err == nil {
		t.Fatal("symlink private offer accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedExternalWSSMenuOffer(opts, sender, path); err == nil {
		t.Fatal("world-readable private offer accepted")
	}
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(bytes.TrimSuffix(b, []byte{'\n'}), []byte(raw)) {
		t.Fatal("failed disclosure safety checks modified the original offer")
	}
}

func TestWSSMenuSenderCanShowOriginalExternalCLIFileAfterFreshTTYSHOW(t *testing.T) {
	opts, _, _, path, raw := savedExternalWSSFixture(t)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("3")
	tty.expect("Type SHOW to confirm")
	if strings.Contains(tty.all, raw) {
		t.Fatal("WSS credential disclosed before fresh SHOW")
	}
	tty.send("SHOW")
	tty.expect("Original sender-private file path (Enter=back): ")
	if strings.Contains(tty.all, raw) {
		t.Fatal("WSS credential disclosed before private-file validation")
	}
	tty.send(path)
	tty.expect("Keep this credential private.")
	if !strings.Contains(tty.all, raw) {
		t.Fatal("exact validated CLI handoff not displayed after explicit SHOW")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("show action removed sender original")
	}
	if _, err := os.Stat(filepath.Join(opts.stateRoot, protectedMenuHandoffDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CLI offer was silently duplicated into menu-owned storage")
	}
}

func TestWSSMenuDeleteMissingOfferDoesNotChangeWorkingLinkOrCreateSecrets(t *testing.T) {
	opts, sender, _, path, raw := savedExternalWSSFixture(t)
	tty, done := startManageTTY(t, opts)
	tty.expect("Choose a task: ")
	tty.send("3")
	tty.expect("Choose tunnel number: ")
	tty.send("1")
	tty.expect("Choose an action: ")
	tty.send("6")
	tty.expect("Type DELETE to confirm")
	tty.send("DELETE")
	tty.expect("No original receiver offer was saved by the menu")
	if strings.Contains(tty.all, raw) {
		t.Fatal("private offer disclosed during no-op delete")
	}
	tty.expect("Press Enter to continue... ")
	tty.send("")
	tty.expect("Choose an action: ")
	tty.send("0")
	tty.expect("Choose a task: ")
	tty.send("8")
	manageTTYDone(t, done, 0)
	snap, err := state.NewFileStore(opts.stateRoot).Load(context.Background())
	if err != nil || len(snap.Links) != 1 || snap.Links[0].Desired != sender {
		t.Fatalf("no-op Delete changed live desired WSS Link: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("no-op Delete modified original CLI output")
	}
}

// A noninteractive caller cannot select the private-filename fallback or
// bypass the protected confirmation. Automation uses private file operations
// and the versioned CLI, not the human menu transcript.
func TestWSSMenuOriginalPrivateCLIFileNotDisclosedToScriptedInput(t *testing.T) {
	opts, _, _, _, raw := savedExternalWSSFixture(t)
	var output, errs bytes.Buffer
	_ = runWithRuntimeInput([]string{"menu"}, strings.NewReader("3\n1\n3\nSHOW\n8\n"), &output, &errs, opts)
	if strings.Contains(output.String()+errs.String(), raw) ||
		!strings.Contains(errs.String(), "real interactive terminal") {
		t.Fatal("nonTTY private output was disclosed")
	}
}

// Public per-link details must not fall through to an unsupported Native
// branch or tempt a receiver to regenerate a private handoff.
func TestWSSConnectionDetailsAreExplicitSafeAndRoleAware(t *testing.T) {
	_, sender, receiver, _, secret := savedExternalWSSFixture(t)
	for _, tc := range []struct {
		role string
		link domain.Link
	}{{"listen", sender}, {"dial", receiver}} {
		var out bytes.Buffer
		printManualConnectionDetails(&out, tc.link)
		shown := out.String()
		if !strings.Contains(shown, "WSS role") ||
			!strings.Contains(shown, tc.role+" (this server)") ||
			!strings.Contains(shown, "WSS TLS TCP port") ||
			!strings.Contains(shown, "authenticated WSS/TLS") ||
			!strings.Contains(shown, "ORIGINAL sender's protected receiver offer") ||
			strings.Contains(shown, "backend is not supported for manual setup") ||
			strings.Contains(shown, "private_key") || strings.Contains(shown, secret) {
			t.Fatalf("WSS public details unhelpful or leaked secrets: %q", shown)
		}
	}
}
