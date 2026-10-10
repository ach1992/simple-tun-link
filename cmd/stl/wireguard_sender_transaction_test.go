package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestSenderSameIDCommittedRejectedBeforeSecondHandoffOrRekey(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "1", "10.70.56.0/31")
	input := creatorRequest(t, link)
	first := filepath.Join(parent, "existing.stl")
	code, _, errText := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", first, "--json"}, input, opts)
	if code != 0 || errText != "" {
		t.Fatal("fixture Create failed")
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := keys.Load(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(parent, "must-not-publish.stl")
	code, out, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", second, "--json"}, input, opts)
	if code == 0 || stderr != "" || strings.Contains(out, "stl://") || len(fake.applies) != 1 {
		t.Fatal("committed ID published a competing handoff")
	}
	if _, err = os.Stat(second); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new recipient handoff published for existing ID")
	}
	after, err := keys.Load(link.ID)
	if err != nil || orig.SecretWireValue() != after.SecretWireValue() {
		t.Fatal("committed Link credential replaced")
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.PendingSenders) != 0 || len(snap.Links) != 1 {
		t.Fatal("rejected second creator staged a pending transaction")
	}
}

func TestSenderPublishedHandoffAlwaysHasDurableRecoveryOnWriterFailure(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "2", "10.70.57.0/31")
	path := filepath.Join(parent, "published.stl")
	opts.writeHandoff = func(path string, body []byte) error {
		if err := writeSensitiveHandoff(path, body); err != nil {
			return err
		}
		// A crash/failure directly after visible final handoff publication.
		return errors.New("injected post-publication failure")
	}
	code, out, stderr := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", path, "--json"}, creatorRequest(t, link), opts)
	if code == 0 || stderr != "" || strings.Contains(out, "stl://") || len(fake.applies) != 0 {
		t.Fatalf("post-publication fault incorrectly applied/announced success: %d %q %q", code, out, stderr)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("published handoff did not survive fault", err)
	}
	encoded := strings.TrimSuffix(string(raw), "\n")
	pendingState, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pending, ok := pendingState.FindPendingSender(link.ID)
	if !ok || len(pendingState.Links) != 0 || pending.HandoffSHA256 != setupLinkConfirmation(encoded) {
		t.Fatal("externally published offer lacks durable exact pending intent")
	}
	keys, err := wireguard.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	public, err := keys.LocalPublicIdentity(link.ID)
	if err != nil || public != pending.Link.WireGuard.LocalPublicKey {
		t.Fatal("published offer lacks durable sender private identity")
	}
	opts.writeHandoff = nil
	code, out, stderr = creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm", setupLinkConfirmation(encoded), "--json"}, string(raw), opts)
	if code != 0 || stderr != "" || len(fake.applies) != 1 {
		t.Fatalf("exact postpublication recovery failed: code=%d out=%q stderr=%q", code, out, stderr)
	}
	committed, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(committed.PendingSenders) != 0 || len(committed.Links) != 1 || committed.Links[0].Desired != pending.Link {
		t.Fatal("sender recovery did not atomically consume pending public intent")
	}
}

func TestSenderPendingRejectsRechecksummedModifiedHandoff(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	fake.failApply = true
	link, _ := makeLifecycleDesired(t, "3", "10.70.58.0/31")
	path := filepath.Join(parent, "exact.stl")
	code, _, _ := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", path, "--json"}, creatorRequest(t, link), opts)
	if code == 0 {
		t.Fatal("injected activation failure unexpectedly succeeded")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimSuffix(string(original), "\n")
	offer, err := pairing.DecodeSetupLink(encoded)
	if err != nil {
		t.Fatal(err)
	}
	baseline := offer.Link()
	cases := map[string]func(*domain.Link){
		"sender-underlay":   func(l *domain.Link) { l.Underlay.Local = l.Underlay.Peer.Next() },
		"receiver-underlay": func(l *domain.Link) { l.Underlay.Peer = l.Underlay.Local.Next() },
		"local-Link-address": func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("10.70.60.0/31")
			l.Addresses.Peer = netip.MustParsePrefix("10.70.60.1/31")
		},
		"local-port":                func(l *domain.Link) { l.WireGuard.ListenPort++ },
		"peer-port":                 func(l *domain.Link) { l.WireGuard.PeerPort++ },
		"keepalive":                 func(l *domain.Link) { l.WireGuard.LocalKeepalive++ },
		"display-label":             func(l *domain.Link) { l.DisplayName = "tampered-but-valid" },
		"recipient-public-identity": func(l *domain.Link) {},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			altered := baseline
			// Copy because recipient identity test changes credential content.
			material := offer.RecipientCredential()
			defer clear(material)
			if name == "recipient-public-identity" {
				other, pub, e := wireguard.GenerateKeyPair()
				if e != nil {
					t.Fatal(e)
				}
				altered.WireGuard.PeerPublicKey = pub
				material = []byte(other.SecretWireValue())
			} else {
				change(&altered)
			}
			alternate, err := pairing.NewQuickOffer(altered, material)
			if err != nil {
				t.Fatal("mutated handoff should still be a valid encoded offer", err)
			}
			decoded, err := alternate.EncodeSetupLink()
			if err != nil {
				t.Fatal(err)
			}
			code, out, stderr := creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm", setupLinkConfirmation(decoded), "--json"}, decoded+"\n", opts)
			if code == 0 || stderr != "" || strings.Contains(out, "stl://") {
				t.Fatalf("modified URL accepted as original sender intent: %d %q %q", code, out, stderr)
			}
		})
	}
	if len(fake.applies) != 0 {
		t.Fatal("changed handoff reached backend Apply")
	}
	staged, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(staged.PendingSenders) != 1 || staged.PendingSenders[0].HandoffSHA256 != setupLinkConfirmation(encoded) {
		t.Fatal("modified handoff overwrote exact pending transaction")
	}
	fake.failApply = false
	code, _, stderr := creatorRun([]string{"link", "resume-wireguard", "--stdin", "--confirm", setupLinkConfirmation(encoded), "--json"}, string(original), opts)
	if code != 0 || stderr != "" || len(fake.applies) != 1 {
		t.Fatal("original untampered handoff was not resumable")
	}
}

func TestConcurrentSameIDSenderCreatesPublishAtMostOneHandoff(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	link, _ := makeLifecycleDesired(t, "4", "10.70.59.0/31")
	request := creatorRequest(t, link)
	start := make(chan struct{})
	type outcome struct {
		code int
		path string
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"left.stl", "right.stl"} {
		path := filepath.Join(parent, name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			code, _, _ := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", path, "--json"}, request, opts)
			results <- outcome{code: code, path: path}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	wins, files := 0, 0
	for r := range results {
		if r.code == 0 {
			wins++
		}
		_, err := os.Stat(r.path)
		if err == nil {
			files++
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	if wins != 1 || files != 1 || len(fake.applies) != 1 {
		t.Fatalf("same-ID race created competing offers: successes=%d published=%d applies=%d", wins, files, len(fake.applies))
	}
	stored, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(stored.Links) != 1 || len(stored.PendingSenders) != 0 {
		t.Fatal("concurrent identity collision corrupted committed state")
	}
}

func TestPendingSenderReservationBlocksOrdinaryEnsureAndSecondCreator(t *testing.T) {
	root, parent, fake, opts := newCreatorTest(t)
	fake.failApply = true
	link, _ := makeLifecycleDesired(t, "6", "10.70.62.0/31")
	original := filepath.Join(parent, "pending.stl")
	code, _, _ := creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", original, "--json"}, creatorRequest(t, link), opts)
	if code == 0 {
		t.Fatal("injected activation failure should keep a protected pending sender")
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pending, exists := snap.FindPendingSender(link.ID)
	if !exists || len(snap.Links) != 0 {
		t.Fatal("sender recovery reservation missing after failed Apply")
	}
	fake.failApply = false
	different := filepath.Join(parent, "must-not-publish.stl")
	code, _, _ = creatorRun([]string{"link", "create-wireguard", "--stdin", "--output", different, "--json"}, creatorRequest(t, link), opts)
	if code == 0 {
		t.Fatal("second sender Create reused pending ID")
	}
	if _, err = os.Stat(different); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending sender allowed second handoff publication")
	}
	engine, err := buildRuntimeEngine(*opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Ensure(context.Background(), pending.Link); err == nil {
		t.Fatal("ordinary Ensure bypassed the reserved exact sender Resume")
	}
	if _, err = engine.EnsureImported(context.Background(), pending.Link); err == nil {
		t.Fatal("ordinary pairing import bypassed pending sender reservation")
	}
	after, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(after.PendingSenders) != 1 || len(after.Links) != 0 || len(fake.applies) != 0 {
		t.Fatal("unrelated Ensure mutated still-pending sender intent")
	}
}
