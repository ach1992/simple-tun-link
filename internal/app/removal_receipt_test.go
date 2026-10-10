package app

import (
	"context"
	"errors"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type fakeWireGuardReceiptBackend struct{ *fakeBackend }

func (*fakeWireGuardReceiptBackend) Kind() domain.Backend { return domain.BackendWireGuard }

type uncertainRemovalState struct {
	state.Store
	failAfterRemove bool
}

func (s *uncertainRemovalState) Update(ctx context.Context, mutate func(*state.Snapshot) error) error {
	removed := false
	err := s.Store.Update(ctx, func(snapshot *state.Snapshot) error {
		before := len(snapshot.Links)
		if err := mutate(snapshot); err != nil {
			return err
		}
		removed = len(snapshot.Links) < before
		return nil
	})
	if err == nil && removed && s.failAfterRemove {
		return &state.PublicationError{Cause: errors.New("injected postpublication state durability uncertainty")}
	}
	return err
}

func TestIndeterminateRemoveCannotIssueDurableCredentialReceipt(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	committed := state.NewFileStore(root)
	stateWithFault := &uncertainRemovalState{Store: committed}
	adapter := &fakeWireGuardReceiptBackend{newFakeBackend()}
	registry, err := backend.NewRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(registry, stateWithFault, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	keyA, publicA, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer keyA.Zeroize()
	keyB, publicB, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer keyB.Zeroize()
	link := linkFor(t, "receipt-uncertain", "10.80.72.0/31", "10.80.72.1/31")
	link.Backend = domain.BackendWireGuard
	link.Encapsulation = domain.EncapUDP
	link.WireGuard = domain.WireGuardOptions{LocalPublicKey: publicA, PeerPublicKey: publicB, ListenPort: 51871, PeerPort: 51872}
	if _, err := engine.Ensure(ctx, link); err != nil {
		t.Fatal("fixture Ensure failed", err)
	}
	stateWithFault.failAfterRemove = true
	_, err = engine.Remove(ctx, link.ID)
	if err == nil {
		t.Fatal("indeterminate state publication falsely reported confirmed Remove")
	}
	snapshot, err := committed.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, proof := snapshot.FindRemovalReceipt(link.ID); proof {
		t.Fatal("indeterminate Remove left a credential-retirement authorization")
	}
	// The actual underlying mutation deliberately succeeded (visible) before
	// its injected uncertainty. Such ambiguous visibility is NOT a receipt.
	if _, stillCommitted := snapshot.Find(link.ID); stillCommitted {
		t.Fatal("fixture did not exercise postpublication uncertainty")
	}
}
