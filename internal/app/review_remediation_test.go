package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// The second Update is receipt publication; the first must still commit
// the canonical Remove. No network operation is made by this fault store.
type rejectRemovalReceiptStore struct {
	state.Store
	updates int
}

func (s *rejectRemovalReceiptStore) Update(ctx context.Context, mutate func(*state.Snapshot) error) error {
	s.updates++
	if s.updates == 2 {
		return errors.New("private_key=DO_NOT_EXPOSE: receipt publication failed")
	}
	return s.Store.Update(ctx, mutate)
}

func wireGuardReviewLink(t *testing.T, name, local, peer string) domain.Link {
	t.Helper()
	own, publicOwn, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer own.Zeroize()
	remote, publicRemote, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Zeroize()
	link := linkFor(t, name, local, peer)
	link.Backend = domain.BackendWireGuard
	link.Encapsulation = domain.EncapUDP
	link.WireGuard = domain.WireGuardOptions{
		LocalPublicKey: publicOwn, PeerPublicKey: publicRemote,
		ListenPort: 51871, PeerPort: 51872,
	}
	return link
}

func TestFinalNoopRemoveUnitCleanupIsStillHostMutationAttempt(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{}
	engine, store := persistentTestEngine(t, b, p)
	link := linkFor(t, "last-noop", "10.92.100.0/31", "10.92.100.1/31")
	if _, err := engine.Ensure(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	// The host resource disappeared outside STL; the desired Link remains.
	b.mu.Lock()
	delete(b.present, link.ID)
	applies := b.applyCount
	undos := b.rollbackCount
	b.mu.Unlock()
	p.failRemove = true

	result, err := engine.Remove(context.Background(), link.ID)
	if stlerr.CodeOf(err) != stlerr.CodeState || !result.Removed || result.Changed {
		t.Fatalf("no-op Remove cleanup incorrectly succeeded: result=%+v err=%v", result, err)
	}
	requireOperationEvidence(t, err, "persistence_cleanup", "attempted", "committed", "not_required")
	if p.removes != 1 || !p.active {
		t.Fatalf("failed owned-unit cleanup was not attempted/preserved: removes=%d active=%t", p.removes, p.active)
	}
	snapshot, loadErr := store.Load(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, present := snapshot.Find(link.ID); present {
		t.Fatal("committed Remove was rolled back after cleanup failure")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.applyCount != applies || b.rollbackCount != undos {
		t.Fatal("no-op backend Remove unexpectedly invoked Apply/rollback")
	}
}

func TestWireGuardReceiptFailurePreservesExactPriorHostMutationEvidence(t *testing.T) {
	for _, hostPresent := range []bool{false, true} {
		name := "backend_already_absent"
		if hostPresent {
			name = "backend_apply_invoked"
		}
		t.Run(name, func(t *testing.T) {
			b := &fakeWireGuardReceiptBackend{newFakeBackend()}
			registry, err := backend.NewRegistry(b)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			store := state.NewFileStore(root)
			engine, err := New(registry, store, state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			target := wireGuardReviewLink(t, "target", "10.92.102.0/31", "10.92.102.1/31")
			sibling := wireGuardReviewLink(t, "sibling", "10.92.103.0/31", "10.92.103.1/31")
			for _, link := range []domain.Link{target, sibling} {
				if _, err := engine.Ensure(context.Background(), link); err != nil {
					t.Fatal(err)
				}
			}
			if !hostPresent {
				b.mu.Lock()
				delete(b.present, target.ID)
				b.mu.Unlock()
			}
			b.mu.Lock()
			beforeApplies, beforeUndos := b.applyCount, b.rollbackCount
			b.mu.Unlock()
			fault := &rejectRemovalReceiptStore{Store: store}
			engine.store = fault

			result, err := engine.Remove(context.Background(), target.ID)
			if stlerr.CodeOf(err) != stlerr.CodeState || !result.Removed || result.Changed != hostPresent {
				t.Fatalf("receipt failure changed Remove outcome: %+v %v", result, err)
			}
			mutation := "not_attempted"
			if hostPresent {
				mutation = "attempted"
			}
			requireOperationEvidence(t, err, "credential_retirement", mutation, "committed", "not_attempted")
			if fault.updates != 2 {
				t.Fatalf("expected committed delete then rejected receipt: %d updates", fault.updates)
			}
			snapshot, loadErr := store.Load(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if _, found := snapshot.Find(target.ID); found {
				t.Fatal("receipt failure rolled back committed desired-state deletion")
			}
			if _, found := snapshot.Find(sibling.ID); !found {
				t.Fatal("receipt failure removed independent Link")
			}
			if _, receipt := snapshot.FindRemovalReceipt(target.ID); receipt {
				t.Fatal("failed receipt publication granted retirement authority")
			}
			b.mu.Lock()
			_, siblingLive := b.present[sibling.ID]
			_, targetLive := b.present[target.ID]
			afterApplies, afterUndos := b.applyCount, b.rollbackCount
			b.mu.Unlock()
			if !siblingLive || targetLive || afterUndos != beforeUndos {
				t.Fatal("receipt failure affected sibling or compensated a committed Remove")
			}
			expectedApplies := beforeApplies
			if hostPresent {
				expectedApplies++
			}
			if afterApplies != expectedApplies {
				t.Fatalf("unexpected backend Apply: %d vs %d", afterApplies, expectedApplies)
			}
			if strings.Contains(stlerr.Public(err).Error(), "DO_NOT_EXPOSE") {
				t.Fatal("receipt-state failure leaked untrusted error detail")
			}
		})
	}
}

func TestCanceledLinkLockWaitIsReportedBeforeBackendApply(t *testing.T) {
	b := newFakeBackend()
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	locks := state.NewLockManager(root)
	engine, err := New(registry, state.NewFileStore(root), locks)
	if err != nil {
		t.Fatal(err)
	}
	link := linkFor(t, "blocked-lock", "10.92.104.0/31", "10.92.104.1/31")
	release, err := locks.Acquire(context.Background(), []domain.ResourceClaim{linkLock(link.ID)})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = engine.Ensure(ctx, link)
	if !errors.Is(err, context.DeadlineExceeded) || stlerr.CodeOf(err) != stlerr.CodeState {
		t.Fatalf("lock wait did not retain deadline cause: %v", err)
	}
	requireOperationEvidence(t, err, "preflight", "not_attempted", "no_commit_attempted", "not_required")
	if b.applyCount != 0 || len(b.present) != 0 {
		t.Fatal("deadline while waiting for Link lock invoked host Apply")
	}
}

func TestWireGuardFinalNoopReceiptFailureRetainsSuccessfulUnitCleanupAttempt(t *testing.T) {
	ctx := context.Background()
	b := &fakeWireGuardReceiptBackend{newFakeBackend()}
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeRestorePersistence{}
	root := t.TempDir()
	store := state.NewFileStore(root)
	engine, err := NewWithRestorePersistence(registry, store, state.NewLockManager(root), p, "/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	link := wireGuardReviewLink(t, "last-wg", "10.92.106.0/31", "10.92.106.1/31")
	if _, err := engine.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	delete(b.present, link.ID)
	applies := b.applyCount
	b.mu.Unlock()
	fault := &rejectRemovalReceiptStore{Store: store}
	engine.store = fault
	result, err := engine.Remove(ctx, link.ID)
	if stlerr.CodeOf(err) != stlerr.CodeState || !result.Removed || result.Changed {
		t.Fatalf("unexpected committed no-op Remove receipt failure: %+v %v", result, err)
	}
	requireOperationEvidence(t, err, "credential_retirement", "attempted", "committed", "not_attempted")
	if p.removes != 1 || p.active || fault.updates != 2 {
		t.Fatalf("final owned-unit cleanup or receipt injection not exercised: %+v, updates=%d", p, fault.updates)
	}
	snapshot, loadErr := store.Load(ctx)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(snapshot.Links) != 0 {
		t.Fatal("last Link desired state was not durably removed")
	}
	if _, receipt := snapshot.FindRemovalReceipt(link.ID); receipt {
		t.Fatal("unconfirmed receipt authorized key retirement")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.applyCount != applies || b.rollbackCount != 0 {
		t.Fatal("no-op Remove unexpectedly invoked backend Apply or compensation")
	}
}
