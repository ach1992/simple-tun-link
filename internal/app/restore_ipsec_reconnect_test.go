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
			if tc.wantFailure && (stlerr.CodeOf(err) != stlerr.CodeState || strings.Contains(err.Error(), "SENSITIVE-DO-NOT-LEAK")) {
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
