package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// A harmless fake that only records exact committed auto-Connect intent. The
// real admission/VICI/SA side effects are tested in separately gated KVM E2E.
type restoreIPsecReconnectFake struct {
	*fakeBackend
	hasSA       bool
	connections int
	connectErr  error
}

func (f *restoreIPsecReconnectFake) Kind() domain.Backend { return domain.BackendIPsec }

func (f *restoreIPsecReconnectFake) DiagnosticState(_ context.Context, link domain.Link) (ipsec.DiagnosticState, error) {
	f.mu.Lock()
	_, present := f.present[link.ID]
	f.mu.Unlock()
	if !present {
		return ipsec.DiagnosticState{}, errors.New("committed identity not present")
	}
	return ipsec.DiagnosticState{IfIndex: 12, ConnectionConfigured: true, SecurityAssociationPresent: f.hasSA}, nil
}

func (f *restoreIPsecReconnectFake) Connect(_ context.Context, link domain.Link, claims []domain.ResourceClaim) error {
	if link.Backend != domain.BackendIPsec || len(claims) != 1 || claims[0].Key != link.DisplayName {
		return errors.New("untrusted or incomplete IPsec ownership")
	}
	f.connections++
	return f.connectErr
}

func TestRestoreAutoReconnectOnlyCommittedIPsecWithoutSA(t *testing.T) {
	for _, tc := range []struct {
		name            string
		hasSA, fail     bool
		wantConnections int
		wantFailure     bool
	}{
		{"missing SA reconnects", false, false, 1, false},
		{"already negotiated SA skips", true, false, 0, false},
		{"uncertain IKE is a truthful failure", false, true, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &restoreIPsecReconnectFake{fakeBackend: newFakeBackend(), hasSA: tc.hasSA}
			if tc.fail {
				fake.connectErr = errors.New("private_key=SENSITIVE-DO-NOT-LEAK")
			}
			registry, err := backend.NewRegistry(fake)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			store := state.NewFileStore(root)
			eng, err := New(registry, store, state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			link := linkFor(t, "owned-ipsec", "10.180.10.0/31", "10.180.10.1/31")
			link.Backend = domain.BackendIPsec
			link.Encapsulation = domain.EncapESP
			link.Underlay.Local = netip.MustParseAddr("192.0.2.1")
			link.Underlay.Peer = netip.MustParseAddr("192.0.2.2")
			claim := domain.ResourceClaim{Kind: domain.ResourceInterface, Key: link.DisplayName}
			fake.present[link.ID] = []domain.ResourceClaim{claim}
			if err := store.Update(context.Background(), func(s *state.Snapshot) error {
				s.Upsert(state.LinkRecord{Desired: link, OwnedResources: []domain.ResourceClaim{claim}})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			results, err := eng.RestoreAll(context.Background())
			if (err != nil) != tc.wantFailure {
				t.Fatalf("unexpected failure: results=%v error=%v", results, err)
			}
			if tc.wantFailure && (stlerr.CodeOf(err) != stlerr.CodeApply || strings.Contains(err.Error(), "SENSITIVE-DO-NOT-LEAK")) {
				t.Fatalf("indeterminate Connect error not fail-closed and secret-safe: %v", err)
			}
			if fake.connections != tc.wantConnections {
				t.Fatalf("Connect=%d want=%d", fake.connections, tc.wantConnections)
			}
			saved, loadErr := store.Load(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			exact, exists := saved.Find(link.ID)
			if !exists || exact.Desired != link || len(exact.OwnedResources) != 1 {
				t.Fatal("automatic IKE attempt modified durable committed Link or owner claims")
			}
			if !tc.wantFailure && (len(results) != 1 || results[0].LinkID != link.ID) {
				t.Fatal("successful Link restore result missing")
			}
		})
	}
}

// A failed, indeterminate post-commit IKE exchange is local to its Link:
// it must not stop later independent Links from restoring, nor cause
// retries, credential leaks, or changes to committed ownership receipts.
func TestRestoreContinuesSiblingAfterFailedIPsecAutoReconnect(t *testing.T) {
	ctx := context.Background()
	ipsecFake := &restoreIPsecReconnectFake{
		fakeBackend: newFakeBackend(),
		connectErr:  errors.New("private_key=SENSITIVE-DO-NOT-LEAK"),
	}
	greFake := newFakeBackend()
	registry, err := backend.NewRegistry(ipsecFake, greFake)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	engine, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}

	first := linkFor(t, "owned-ipsec-first", "10.180.40.0/31", "10.180.40.1/31")
	first.ID = domain.LinkID("lnk_" + strings.Repeat("1", 32))
	first.Backend = domain.BackendIPsec
	first.Encapsulation = domain.EncapESP
	first.Underlay.Local = netip.MustParseAddr("192.0.2.1")
	first.Underlay.Peer = netip.MustParseAddr("192.0.2.2")
	claim := domain.ResourceClaim{Kind: domain.ResourceInterface, Key: first.DisplayName}
	// The canonical local Ensure is idempotent for an already-owned device;
	// the independent IKE initiation then fails after that successful step.
	ipsecFake.present[first.ID] = []domain.ResourceClaim{claim}
	second := linkFor(t, "gre-sibling-second", "10.180.41.0/31", "10.180.41.1/31")
	second.ID = domain.LinkID("lnk_" + strings.Repeat("2", 32))
	if err := store.Update(ctx, func(snapshot *state.Snapshot) error {
		snapshot.Upsert(state.LinkRecord{Desired: first, OwnedResources: []domain.ResourceClaim{claim}})
		snapshot.Upsert(state.LinkRecord{Desired: second})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	results, err := engine.RestoreAll(ctx)
	if stlerr.CodeOf(err) != stlerr.CodeApply ||
		!strings.Contains(err.Error(), "1 independent Link(s) could not be restored") ||
		strings.Contains(err.Error(), "restore halted") ||
		strings.Contains(err.Error(), "SENSITIVE-DO-NOT-LEAK") {
		t.Fatalf("Link-scoped failure not aggregated and redacted: results=%+v err=%v", results, err)
	}
	if len(results) != 1 || results[0].LinkID != second.ID {
		t.Fatalf("later independent GRE Link was not restored: %+v", results)
	}
	if ipsecFake.applyCount != 0 || ipsecFake.connections != 1 || greFake.applyCount != 1 {
		t.Fatalf("unexpected canonical restores or blind IKE retries: ipsec applies=%d connects=%d gre applies=%d",
			ipsecFake.applyCount, ipsecFake.connections, greFake.applyCount)
	}
	if len(ipsecFake.lastOwned) != 1 || ipsecFake.lastOwned[0].Canonical() != claim.Canonical() {
		t.Fatalf("canonical IPsec Ensure did not verify committed ownership: %+v", ipsecFake.lastOwned)
	}
	greFake.mu.Lock()
	_, siblingPresent := greFake.present[second.ID]
	greFake.mu.Unlock()
	if !siblingPresent {
		t.Fatal("GRE sibling has no live restored backend state")
	}
	snapshot, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	saved, exists := snapshot.Find(first.ID)
	if !exists || saved.Desired != first || len(saved.OwnedResources) != 1 ||
		saved.OwnedResources[0].Canonical() != claim.Canonical() {
		t.Fatalf("failed IKE initiation damaged original committed IPsec intent/claims: %+v", saved)
	}
	gre, exists := snapshot.Find(second.ID)
	if !exists || gre.Desired != second {
		t.Fatal("restoring GRE sibling damaged persisted intent")
	}
}
