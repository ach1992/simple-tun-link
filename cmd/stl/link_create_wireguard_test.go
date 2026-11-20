package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type wireGuardCreatorFake struct{ *lifecycleFakeBackend }

func (*wireGuardCreatorFake) Kind() domain.Backend { return domain.BackendWireGuard }

func creatorRequest(t *testing.T, link domain.Link) string {
	t.Helper()
	obj := wireGuardSenderRequestV1{
		SchemaVersion: 1, LinkID: link.ID,
		Underlay:   desiredUnderlayV1{Local: link.Underlay.Local, Peer: link.Underlay.Peer},
		Addresses:  desiredLinkAddressesV1{Local: link.Addresses.Local, Peer: link.Addresses.Peer},
		ListenPort: 51840, PeerPort: 51841, LocalKeepalive: 25, PeerKeepalive: 0,
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func newCreatorTest(t *testing.T) (string, string, *wireGuardCreatorFake, *runtimeOptions) {
	t.Helper()
	base := t.TempDir()
	parent := filepath.Join(base, "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := &wireGuardCreatorFake{newLifecycleFake()}
	root := filepath.Join(base, "state")
	return root, parent, fake, &runtimeOptions{stateRoot: root, backends: []backend.Backend{fake}}
}
func creatorRun(args []string, input string, opts *runtimeOptions) (int, string, string) {
	var out, errs bytes.Buffer
	code := runWithRuntimeInput(args, strings.NewReader(input), &out, &errs, opts)
	return code, out.String(), errs.String()
}

func TestWireGuardSenderCreatesProtectedOneTimeHandoffAndResumesWithoutRekey(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "8", "10.70.18.0/31")
	output := filepath.Join(parent, "first.stl")
	code, resultText, errorsText := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", output, "--json"}, creatorRequest(t, link), opts)
	if code != 0 || errorsText != "" {
		t.Fatalf("sender failed %d %q %q", code, resultText, errorsText)
	}
	var result wireGuardSenderResult
	if err := json.Unmarshal([]byte(resultText), &result); err != nil {
		t.Fatal(err)
	}
	if result.LinkID != link.ID || !result.Sensitive || !result.Changed || result.Mode != pairing.ModeQuick || result.PairingSchemaVersion != 3 || result.HandoffFile != output {
		t.Fatalf("unexpected safe creator result %+v", result)
	}
	if strings.Contains(resultText, "stl://") || strings.Contains(resultText, "private_key") {
		t.Fatal("sensitive handoff leaked through normal JSON output")
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Sys() == nil {
		t.Fatalf("handoff file is not private 0600: %+v %v", info, err)
	}
	raw, err := os.ReadFile(output)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("incorrect handoff bytes: %v", err)
	}
	encoded := strings.TrimSuffix(string(raw), "\n")
	offer, err := pairing.DecodeSetupLink(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if offer.Link().ID != link.ID || !offer.IsSensitive() || offer.Preview().SchemaVersion != 3 {
		t.Fatal("sender did not create bound v3 Quick Link")
	}
	sender := offer.Link()
	receiver := offer.ReceiverLink()
	if receiver.ID != sender.ID || receiver.WireGuard.LocalPublicKey != sender.WireGuard.PeerPublicKey || receiver.WireGuard.PeerPublicKey != sender.WireGuard.LocalPublicKey {
		t.Fatal("peer inversion/key identity mismatch")
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snap.Links) != 1 || snap.Links[0].Desired != sender {
		t.Fatalf("sender intent not committed: %+v %v", snap, err)
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	own, err := keys.Load(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	ownPub, err := own.PublicKey()
	if err != nil || ownPub != sender.WireGuard.LocalPublicKey {
		t.Fatalf("sender local key misbound: %v", err)
	}
	if own.SecretWireValue() == string(offer.RecipientCredential()) || ownPub == sender.WireGuard.PeerPublicKey {
		t.Fatal("sender accidentally retained receiver private credential as local key")
	}
	if len(fake.applies) != 1 {
		t.Fatal("sender did not use canonical Engine exactly once")
	}
	code, resumeJSON, stderr := creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm", setupLinkConfirmation(encoded), "--json"}, string(raw), opts)
	if code != 0 || stderr != "" {
		t.Fatalf("resume failed: %d %q %q", code, resumeJSON, stderr)
	}
	var resume lifecycleResultResponse
	if err = json.Unmarshal([]byte(resumeJSON), &resume); err != nil || resume.Changed || resume.LinkID != link.ID || len(fake.applies) != 1 {
		t.Fatalf("resume not idempotent: %+v %v applies=%v", resume, err, fake.applies)
	}
	code, _, _ = creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm", strings.Repeat("f", 64), "--json"}, string(raw), opts)
	if code == 0 || len(fake.applies) != 1 {
		t.Fatal("unconfirmed resumed secret mutated Link")
	}
}

func TestWireGuardCreatorRejectsReservedProviderResourcesBeforeStaging(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending bool
		linkID  domain.LinkID
	}{
		{name: "committed interface name", linkID: "lnk_25301300000000000000000000000005"},
		{name: "pending interface name", pending: true, linkID: "lnk_25301300000000000000000000000005"},
		{name: "committed UDP listen port", linkID: "lnk_45678900000000000000000000000005"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, parent, fake, opts := newCreatorTest(t)
			owner, _ := makeLifecycleDesired(t, "3", "10.70.30.0/31")
			owner.ID = "lnk_25301300000000000000000000000002"
			ownerPath := filepath.Join(parent, "owner.stl")
			if code, out, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", ownerPath, "--json"}, creatorRequest(t, owner), opts); code != 0 {
				t.Fatalf("fixture owner not committed: code=%d response=%q stderr=%q", code, out, stderr)
			}
			store := state.NewFileStore(root)
			if err := store.Update(context.Background(), func(s *state.Snapshot) error {
				record, ok := s.Find(owner.ID)
				if !ok {
					return errors.New("fixture owner is not saved")
				}
				claims, err := composition.WireGuardProviderClaims(owner.ID,
					record.Desired.Addresses.Local, record.Desired.WireGuard)
				if err != nil {
					return err
				}
				if tc.pending {
					s.Links = nil
					s.PendingSenders = []state.PendingSender{{Link: record.Desired, HandoffSHA256: strings.Repeat("a", 64)}}
				} else {
					record.OwnedResources = claims
					s.Upsert(record)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wanted, _ := makeLifecycleDesired(t, "4", "10.70.31.0/31")
			wanted.ID = tc.linkID
			req := wireGuardSenderRequestV1{
				SchemaVersion: 1, LinkID: wanted.ID,
				Underlay:   desiredUnderlayV1{Local: wanted.Underlay.Local, Peer: wanted.Underlay.Peer},
				Addresses:  desiredLinkAddressesV1{Local: wanted.Addresses.Local, Peer: wanted.Addresses.Peer},
				ListenPort: 51931, PeerPort: 51932,
			}
			// Only the explicit port-collision case keeps the same reserved
			// port. The interface scenarios use distinct ports and subnets.
			if tc.name == "committed UDP listen port" {
				req.ListenPort = 51840
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(parent, "candidate.stl")
			code, resultText, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", output, "--json"}, string(raw), opts)
			var errorResult linkReadErrorResponse
			if code != 1 || stderr != "" || json.Unmarshal([]byte(resultText), &errorResult) != nil ||
				errorResult.Error == nil || errorResult.Error.Code != "conflict" ||
				errorResult.Error.ReasonCode != "resource_conflict" ||
				errorResult.Error.Evidence == nil || errorResult.Error.Evidence.HostMutation != "not_attempted" ||
				!strings.Contains(errorResult.Error.Detail, "nothing was staged") {
				t.Fatalf("known resource collision was not an actionable pre-staging rejection: code=%d body=%q stderr=%q", code, resultText, stderr)
			}
			if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("denied sender wrote protected handoff: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "credentials", string(wanted.ID)+".wgkey")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("denied sender staged private credential: %v", err)
			}
			after, err := store.Load(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) || len(fake.applies) != 1 {
				t.Fatalf("conflicting sender changed State or host: before=%+v after=%+v err=%v applies=%d", before, after, err, len(fake.applies))
			}
		})
	}
}

func TestWireGuardSenderRejectsUnsafeHandoffBeforeKeyOrHostMutation(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "9", "10.70.19.0/31")
	input := creatorRequest(t, link)
	path := filepath.Join(parent, "exists.stl")
	if err := os.WriteFile(path, []byte("DO_NOT_OVERWRITE"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, path string }{
		{"existing", path},
		{"symlink", filepath.Join(parent, "via-link.stl")},
		{"unsafe-dir", filepath.Join(filepath.Dir(parent), "unsafe", "handoff.stl")},
		{"non-absolute", "relative.stl"},
	}
	if err := os.Symlink(path, cases[1].path); err != nil {
		t.Fatal(err)
	}
	unsafeDir := filepath.Join(filepath.Dir(parent), "unsafe")
	if err := os.Mkdir(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// An inherited restrictive umask can silently turn 0755 into safe 0700.
	// Set the deliberately unsafe fixture mode explicitly before asserting rejection.
	if err := os.Chmod(unsafeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", tc.path, "--json"}, input, opts)
			if code == 0 || stderr != "" || strings.Contains(out, "stl://") || len(fake.applies) != 0 {
				t.Fatalf("unsafe handoff accepted: %d %q %q", code, out, stderr)
			}
		})
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || string(unchanged) != "DO_NOT_OVERWRITE" {
		t.Fatal("existing file was replaced")
	}
	if _, err = os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe export provisioned local key/state: %v", err)
	}
}

func TestWireGuardSenderAfterHandoffFailureAllowsExactResumeWithoutSecretLeaks(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "a", "10.70.20.0/31")
	fake.failApply = true
	output := filepath.Join(parent, "interrupted.stl")
	code, out, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", output, "--json"}, creatorRequest(t, link), opts)
	if code == 0 || stderr != "" || strings.Contains(out, "stl://") || strings.Contains(out, "VERY_SECRET") {
		t.Fatalf("failed creator leaked or reported success: %d %q %q", code, out, stderr)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed activation lost protected retry handoff: %v", err)
	}
	before, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Links) != 0 {
		t.Fatal("failed activation committed desired Link")
	}
	peer, err := pairing.DecodeSetupLink(strings.TrimSuffix(string(raw), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Load(link.ID); err != nil {
		t.Fatalf("failed activation discarded protected sender credential: %v", err)
	}
	fake.failApply = false
	code, out, stderr = creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm", setupLinkConfirmation(strings.TrimSuffix(string(raw), "\n")), "--json"}, string(raw), opts)
	if code != 0 || stderr != "" || strings.Contains(out, string(peer.RecipientCredential())) {
		t.Fatalf("resume after failure did not safely recover: %d %q %q", code, out, stderr)
	}
	after, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(after.Links) != 1 || !reflect.DeepEqual(after.Links[0].Desired, peer.Link()) {
		t.Fatalf("sender resume changed identity: %+v %v", after, err)
	}
}
