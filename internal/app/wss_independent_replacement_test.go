package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// An interrupted WSS original with surviving host effects must not block a
// resource-disjoint replacement, and must not be erased by that replacement.
func TestWSSIndependentReplacementWithUnresolvedOriginal(t *testing.T) {
	ctx := context.Background()
	host := &crashWSSBackend{fakeBackend: newFakeBackend(), crashAfterHost: true}
	engine, store := crashWSSEngine(t, host)
	host.store = store
	old := journalTestLink(t)
	causeCrash(t, func() { _, _ = engine.Ensure(ctx, old) })
	before := mustLoadCrashSnapshot(t, store)
	oldJournal, exists := before.FindWSSCrashOperation(old.ID)
	if !exists {
		t.Fatal("old WSS crash journal missing")
	}
	if _, err := engine.Ensure(ctx, old); err == nil ||
		stlerr.Public(err).ReasonCode != "wss_crash_quarantined" {
		t.Fatalf("interrupted original was replayed or reason was not machine-typed: %v", err)
	}
	oldHost, exists := host.present[old.ID]
	if !exists {
		t.Fatal("old host effects not exercised")
	}
	fresh := old
	fresh.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fresh.DisplayName = "independent-replacement"
	fresh.Addresses.Local = netip.MustParsePrefix("10.94.0.1/30")
	fresh.Addresses.Peer = netip.MustParsePrefix("10.94.0.2/30")
	fresh.WireGuard.ListenPort = 51822
	fresh.WireGuard.PeerPort = 51823
	fresh.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	fresh.WireGuard.PeerPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	fresh.WSS.TCPPort = 59444
	if err := fresh.Validate(); err != nil {
		t.Fatalf("replacement fixture invalid: %v", err)
	}
	colliding := fresh
	colliding.WireGuard.ListenPort = old.WireGuard.ListenPort
	if _, err := engine.Ensure(ctx, colliding); err == nil {
		t.Fatal("fresh Link stole the old reserved UDP port")
	}
	if _, err := engine.Ensure(ctx, fresh); err != nil {
		t.Fatalf("independent WSS Link blocked by old quarantine: %v", err)
	}
	after := mustLoadCrashSnapshot(t, store)
	journal, exists := after.FindWSSCrashOperation(old.ID)
	if !exists || !reflect.DeepEqual(oldJournal, journal) {
		t.Fatal("fresh Link changed the original crash journal")
	}
	if current, exists := host.present[old.ID]; !exists || !reflect.DeepEqual(oldHost, current) {
		t.Fatal("fresh Link changed the original host resources")
	}
	if _, exists := host.present[fresh.ID]; !exists {
		t.Fatal("new WSS host resources absent")
	}
	if _, exists := after.Find(fresh.ID); !exists {
		t.Fatal("new WSS Link not committed")
	}
	if _, exists := after.FindWSSCrashOperation(fresh.ID); exists {
		t.Fatal("successful new WSS retained a crash journal")
	}
	if _, exists := after.Find(old.ID); exists {
		t.Fatal("interrupted old Ensure falsely committed State")
	}
	if _, exists := after.FindRemovalReceipt(old.ID); exists {
		t.Fatal("new Link forged original credential retirement")
	}
}

// The real Engine denial for a committed locally missing WSS original must
// carry a typed operator reason and must not mutate host or protected State.
func TestWSSMissingCommittedOriginalHasActionableTypedDenial(t *testing.T) {
	ctx := context.Background()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	engine, store := crashWSSEngine(t, host)
	host.store = store
	link := journalTestLink(t)
	if _, err := engine.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	delete(host.present, link.ID) // Simulate a WG hidden in another namespace.
	before := mustLoadCrashSnapshot(t, store)
	applyCount := host.applyCount
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"ensure", func() error { _, err := engine.Ensure(ctx, link); return err }},
		{"remove", func() error { _, err := engine.Remove(ctx, link.ID); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil || stlerr.Public(err).ReasonCode != "wss_original_unverified" ||
				stlerr.CodeOf(err) != stlerr.CodeConflict {
				t.Fatalf("missing original not denied with typed conflict: %v", err)
			}
			if host.applyCount != applyCount || !reflect.DeepEqual(before, mustLoadCrashSnapshot(t, store)) {
				t.Fatal("denied missing original mutated host or State")
			}
		})
	}
}

// A locally invisible committed original is not an excuse to halt boot
// restoration of unrelated, genuinely independent Links. The original
// remains protected without an invented deletion witness.
func TestWSSMissingOriginalDoesNotInterruptIndependentGREBootRestore(t *testing.T) {
	ctx := context.Background()
	wss := &crashWSSBackend{fakeBackend: newFakeBackend()}
	gre := newFakeBackend()
	registry, err := backend.NewRegistry(wss, gre)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	engine, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	engine.SetWSSRetirementStore(fakeWSSIssuance{})
	wss.store = store

	original := journalTestLink(t)
	sibling := linkFor(t, "gre-independent", "10.80.40.0/31", "10.80.40.1/31")
	if _, err := engine.Ensure(ctx, original); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ensure(ctx, sibling); err != nil {
		t.Fatal(err)
	}
	originalBefore := mustLoadCrashSnapshot(t, store)
	originalRecord, exists := originalBefore.Find(original.ID)
	if !exists {
		t.Fatal("original committed WSS identity absent")
	}
	delete(wss.present, original.ID) // Simulated moved-DOWN hidden original.
	gre.present = make(map[domain.LinkID][]domain.ResourceClaim)
	beforeApply := wss.applyCount

	results, restoreErr := engine.RestoreAll(ctx)
	if restoreErr == nil {
		t.Fatal("blocked WSS original incorrectly reported successful restore")
	}
	if len(results) != 1 || results[0].LinkID != sibling.ID {
		t.Fatalf("original failure prevented independent GRE recovery: results=%+v err=%v", results, restoreErr)
	}
	if _, exists := gre.present[sibling.ID]; !exists {
		t.Fatal("independent GRE was not actually restored")
	}
	if wss.applyCount != beforeApply {
		t.Fatal("missing original WSS was silently replayed")
	}
	current := mustLoadCrashSnapshot(t, store)
	retained, exists := current.Find(original.ID)
	if !exists || !reflect.DeepEqual(retained, originalRecord) {
		t.Fatal("blocked WSS original State, ownership or credentials changed")
	}
	if _, receipt := current.FindRemovalReceipt(original.ID); receipt {
		t.Fatal("blocked original gained a fabricated retirement receipt")
	}
	if _, journal := current.FindWSSCrashOperation(original.ID); journal {
		t.Fatal("blocked original gained an unproven replay journal")
	}
}
