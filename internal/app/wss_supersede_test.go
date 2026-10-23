package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type testPerLinkIssuance struct{}

func (testPerLinkIssuance) CaptureIdentity(_ context.Context, link domain.Link) (state.WSSFileIdentity, error) {
	digest := func(which string) string {
		sum := sha256.Sum256([]byte(string(link.ID) + "/" + which))
		return hex.EncodeToString(sum[:])
	}
	files := state.WSSFileIdentity{
		Certificate: digest("cert"), TLSKey: digest("key"),
		TrustCA: digest("ca"), Authorization: digest("auth"),
	}
	if link.WSS.Role == "listen" {
		files.Restrictions = digest("restriction")
	}
	return files, nil
}
func (testPerLinkIssuance) RetireAfterRemove(context.Context, domain.Link, state.WSSFileIdentity) error {
	return nil
}
func (testPerLinkIssuance) VerifyAbsent(context.Context, domain.Link) error { return nil }

func testSupersessionEngine(t *testing.T, root string, host *crashWSSBackend, gre *fakeBackend, boot string) (*Engine, *state.FileStore) {
	t.Helper()
	reg, err := backend.NewRegistry(host, gre)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	e, err := New(reg, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	e.SetWSSRetirementStore(testPerLinkIssuance{})
	e.kernelBootID = func() (string, error) { return boot, nil }
	host.store = store
	return e, store
}

func testIndependentWSSLink(t *testing.T, original domain.Link) domain.Link {
	t.Helper()
	fresh := original
	fresh.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fresh.DisplayName = "independent-WSS-replacement"
	fresh.Addresses.Local = netip.MustParsePrefix("10.94.0.1/30")
	fresh.Addresses.Peer = netip.MustParsePrefix("10.94.0.2/30")
	fresh.WireGuard.ListenPort = 51822
	fresh.WireGuard.PeerPort = 51823
	fresh.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	fresh.WireGuard.PeerPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	fresh.WSS.TCPPort = 59444
	if err := fresh.Validate(); err != nil {
		t.Fatal(err)
	}
	return fresh
}

func TestWSSSupersessionPersistsAcrossFreshEngineAndNewKernelWithoutOldRestore(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	gre := newFakeBackend()
	before, store := testSupersessionEngine(t, root, host, gre, testWSSBootBefore)
	old := journalTestLink(t)
	replacement := testIndependentWSSLink(t, old)
	sibling := linkFor(t, "independent-gre", "10.80.43.0/31", "10.80.43.1/31")

	for _, link := range []domain.Link{old, sibling} {
		if _, err := before.Ensure(ctx, link); err != nil {
			t.Fatalf("original/sibling provisioning: %v", err)
		}
	}
	original, exists := mustLoadCrashSnapshot(t, store).Find(old.ID)
	if !exists || original.WSSKernelBootID != testWSSBootBefore {
		t.Fatal("original not committed with trusted birth identity")
	}
	delete(host.present, old.ID) // moved-DOWN WG may survive in another netns
	if _, err := before.Ensure(ctx, old); err == nil {
		t.Fatal("missing same-kernel original was silently recovered")
	}
	if _, err := before.Ensure(ctx, replacement); err != nil {
		t.Fatalf("new independent WSS provisioning failed: %v", err)
	}
	// The new Link being locally committed does not automatically mark the
	// old one. The operator must separately confirm tested peer traffic.
	if interim, _ := mustLoadCrashSnapshot(t, store).Find(old.ID); interim.WSSSupersededBy != "" {
		t.Fatal("new Ensure implicitly superseded an original")
	}
	changed, err := before.SupersedeWSSOriginal(ctx, old.ID, replacement.ID)
	if err != nil || !changed {
		t.Fatalf("explicit supersession failed: changed=%t err=%v", changed, err)
	}
	quarantined := mustLoadCrashSnapshot(t, store)
	retained, exists := quarantined.Find(old.ID)
	if !exists {
		t.Fatal("supersession deleted original")
	}
	original.WSSSupersededBy = replacement.ID
	if !reflect.DeepEqual(retained, original) || len(quarantined.WSSCrashOperations) != 0 ||
		len(quarantined.RemovalReceipts) != 0 {
		t.Fatal("supersession changed original owner, journal, claims, files or receipt")
	}
	changed, err = before.SupersedeWSSOriginal(ctx, old.ID, replacement.ID)
	if changed || err != nil {
		t.Fatalf("exact supersession retry not idempotent: changed=%t err=%v", changed, err)
	}
	for name, operation := range map[string]func() error{
		"ordinary_ensure": func() error { _, err := before.Ensure(ctx, old); return err },
		"imported_ensure": func() error { _, err := before.EnsureImported(ctx, old); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := operation()
			if err == nil || stlerr.Public(err).ReasonCode != "wss_original_superseded" {
				t.Fatalf("superseded original re-ensured or bad code: %v", err)
			}
		})
	}
	// Reboot simulator: original and successor interfaces disappear from
	// this disposable fake backend. The trusted kernel generation changes.
	host.present = make(map[domain.LinkID][]domain.ResourceClaim)
	gre.present = make(map[domain.LinkID][]domain.ResourceClaim)
	oldApplyCount := host.applyCount
	after, _ := testSupersessionEngine(t, root, host, gre, testWSSBootAfter)
	results, err := after.RestoreAll(ctx)
	if err != nil {
		t.Fatalf("new generation restoring healthy siblings should work: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected only GRE and new WSS restore, got %+v", results)
	}
	seen := map[domain.LinkID]bool{}
	for _, result := range results {
		seen[result.LinkID] = true
	}
	if !seen[replacement.ID] || !seen[sibling.ID] || seen[old.ID] ||
		host.applyCount != oldApplyCount+1 {
		t.Fatalf("superseded old original was re-created or a healthy sibling dropped: %+v", results)
	}
	if _, present := host.present[old.ID]; present {
		t.Fatal("old WSS interface resurrected after trusted new kernel")
	}
	if _, present := host.present[replacement.ID]; !present {
		t.Fatal("new WSS Link was not restored")
	}
	if _, present := gre.present[sibling.ID]; !present {
		t.Fatal("GRE sibling was not restored")
	}
	final := mustLoadCrashSnapshot(t, store)
	if persisted, _ := final.Find(old.ID); !reflect.DeepEqual(persisted, retained) {
		t.Fatal("trusted new kernel changed quarantined original or fingerprints")
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		marked, _ := s.Find(old.ID)
		marked.WSSSupersededBy = ""
		s.Upsert(marked)
		return nil
	}); err == nil {
		t.Fatal("arbitrary State update revoked immutable supersession")
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Delete(old.ID)
		return nil
	}); err == nil {
		t.Fatal("original deleted without kernel termination proof and retirement receipt")
	}
	if persisted, _ := mustLoadCrashSnapshot(t, store).Find(old.ID); !reflect.DeepEqual(persisted, retained) {
		t.Fatal("unauthorized State transition modified original")
	}
	// A legitimate, new-kernel positive-deletion witness still permits
	// owner-scoped Remove/retirement of the superseded original.
	if _, err := after.Remove(ctx, old.ID); err != nil {
		t.Fatalf("exact protected original cleanup was incorrectly forbidden: %v", err)
	}
	receipt, found := mustLoadCrashSnapshot(t, store).FindRemovalReceipt(old.ID)
	if !found || receipt.WSSOriginalTermination != state.WSSOriginalKernelGenerationExtinct {
		t.Fatal("original cleanup was not receipt-bound to kernel extinction")
	}
}

func TestWSSFailedReplacementNeverMarksOriginalSuperseded(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	gre := newFakeBackend()
	e, store := testSupersessionEngine(t, root, host, gre, testWSSBootBefore)
	original := journalTestLink(t)
	fresh := testIndependentWSSLink(t, original)
	if _, err := e.Ensure(ctx, original); err != nil {
		t.Fatal(err)
	}
	delete(host.present, original.ID)
	host.failVerifyOnce = true
	if _, err := e.Ensure(ctx, fresh); err == nil {
		t.Fatal("injected new replacement Verify failure did not occur")
	}
	if _, err := e.SupersedeWSSOriginal(ctx, original.ID, fresh.ID); err == nil {
		t.Fatal("failed replacement Apply incorrectly marked original as replaced")
	}
	snapshot := mustLoadCrashSnapshot(t, store)
	current, found := snapshot.Find(original.ID)
	if !found || current.WSSSupersededBy != "" {
		t.Fatal("failed new Apply marked original as superseded")
	}
	if _, committed := snapshot.Find(fresh.ID); committed {
		t.Fatal("failed replacement was committed as healthy")
	}
	// An unrelated committed Link is not sufficient supersession proof.
	sibling := linkFor(t, "unrelated-gre", "10.80.40.0/31", "10.80.40.1/31")
	if _, err := e.Ensure(ctx, sibling); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SupersedeWSSOriginal(ctx, original.ID, sibling.ID); err == nil {
		t.Fatal("GRE sibling was accepted as WSS replacement")
	}
}

// Independently committed replacements must not recycle either endpoint's
// WireGuard key or collide through a non-identical reserved network claim.
func TestWSSSupersessionRejectsSharedCrossKeysAndOverlappingClaims(t *testing.T) {
	original := journalTestLink(t)
	replacement := testIndependentWSSLink(t, original)
	issuer := testPerLinkIssuance{}
	originalFiles, err := issuer.CaptureIdentity(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	replacementFiles, err := issuer.CaptureIdentity(context.Background(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	old := state.LinkRecord{Desired: original,
		WSSOrigin: hex.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		WSSFiles:  originalFiles,
		OwnedResources: []domain.ResourceClaim{
			{Kind: domain.ResourceInterface, Key: "original-wss"},
			{Kind: domain.ResourceLinkSubnet, Key: "192.0.2.0/24"},
		},
	}
	next := state.LinkRecord{Desired: replacement,
		WSSOrigin: hex.EncodeToString(bytes.Repeat([]byte{2}, 16)),
		WSSFiles:  replacementFiles,
		OwnedResources: []domain.ResourceClaim{
			{Kind: domain.ResourceInterface, Key: "replacement-wss"},
			{Kind: domain.ResourceLinkSubnet, Key: "198.51.100.0/24"},
		},
	}
	if !independentWSSReplacement(old, next) {
		t.Fatal("disjoint baseline replacement rejected")
	}
	t.Run("reused_original_local_as_new_peer", func(t *testing.T) {
		reused := next
		reused.Desired.WireGuard.PeerPublicKey = old.Desired.WireGuard.LocalPublicKey
		if err := reused.Desired.Validate(); err != nil {
			t.Fatal(err)
		}
		if independentWSSReplacement(old, reused) {
			t.Fatal("replacement reused original local WireGuard key as peer")
		}
	})
	t.Run("reused_original_peer_as_new_local", func(t *testing.T) {
		reused := next
		reused.Desired.WireGuard.LocalPublicKey = old.Desired.WireGuard.PeerPublicKey
		if err := reused.Desired.Validate(); err != nil {
			t.Fatal(err)
		}
		if independentWSSReplacement(old, reused) {
			t.Fatal("replacement reused original peer WireGuard key as local")
		}
	})
	t.Run("overlapping_nonidentical_claims", func(t *testing.T) {
		reused := next
		reused.OwnedResources = append([]domain.ResourceClaim(nil), next.OwnedResources...)
		reused.OwnedResources = append(reused.OwnedResources,
			domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: "192.0.2.128/25"})
		if independentWSSReplacement(old, reused) {
			t.Fatal("overlapping nonidentical resource claims were accepted")
		}
	})
}
