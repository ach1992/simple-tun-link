package app

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestRestoreAllReappliesPersistedLinksThroughEnsure(t *testing.T) {
	backend := newFakeBackend()
	engine, store := newEngine(t, backend)
	first := linkFor(t, "stl-restore-a", "10.80.70.0/31", "10.80.70.1/31")
	second := linkFor(t, "stl-restore-b", "10.80.71.0/31", "10.80.71.1/31")
	if err := store.Update(context.Background(), func(snapshot *state.Snapshot) error {
		snapshot.Upsert(state.LinkRecord{Desired: second})
		snapshot.Upsert(state.LinkRecord{Desired: first})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	results, err := engine.RestoreAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results)=%d, want 2", len(results))
	}
	if backend.applyCount != 2 {
		t.Fatalf("applyCount=%d, want 2", backend.applyCount)
	}
	wantFirst, wantSecond := first.ID, second.ID
	if wantSecond < wantFirst {
		wantFirst, wantSecond = wantSecond, wantFirst
	}
	if results[0].LinkID != wantFirst || results[1].LinkID != wantSecond {
		t.Fatalf("restore order=%v,%v; want stable Link-ID order=%v,%v", results[0].LinkID, results[1].LinkID, wantFirst, wantSecond)
	}
}

func TestRestoreAllEmptyStateIsNoOp(t *testing.T) {
	backend := newFakeBackend()
	engine, _ := newEngine(t, backend)
	results, err := engine.RestoreAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 || backend.applyCount != 0 {
		t.Fatalf("results=%v applyCount=%d, want empty/0", results, backend.applyCount)
	}
}

// The initial iteration snapshot intentionally races with a normal lifecycle
// action. The next Load under the Link lock must always win as current intent.
type restoreSnapshotHookStore struct {
	state.Store
	onInitialSnapshot func()
	fired             atomic.Bool
}

func (s *restoreSnapshotHookStore) Load(ctx context.Context) (state.Snapshot, error) {
	snapshot, err := s.Store.Load(ctx)
	if err == nil && s.onInitialSnapshot != nil && s.fired.CompareAndSwap(false, true) {
		s.onInitialSnapshot()
	}
	return snapshot, err
}

func TestRestoreDoesNotResurrectLinkRemovedAfterSnapshot(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	first := linkFor(t, "removed-before-restore", "10.80.140.0/31", "10.80.140.1/31")
	sibling := linkFor(t, "independent-sibling", "10.80.141.0/31", "10.80.141.1/31")
	for _, link := range []domain.Link{first, sibling} {
		if _, err := engine.Ensure(context.Background(), link); err != nil {
			t.Fatal(err)
		}
	}
	hook := &restoreSnapshotHookStore{Store: store}
	hook.onInitialSnapshot = func() {
		if _, err := engine.Remove(context.Background(), first.ID); err != nil {
			t.Errorf("remove during snapshot: %v", err)
		}
	}
	engine.store = hook
	results, err := engine.RestoreAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := snapshot.Find(first.ID); exists {
		t.Fatal("stale restore recreated a removed Link")
	}
	if _, exists := snapshot.Find(sibling.ID); !exists {
		t.Fatal("unrelated sibling was disturbed")
	}
	if len(results) != 1 || results[0].LinkID != sibling.ID {
		t.Fatalf("expected only independent sibling restored, got %+v", results)
	}
	b.mu.Lock()
	_, observed := b.present[first.ID]
	b.mu.Unlock()
	if observed {
		t.Fatal("removed backend was re-created")
	}
}

func TestRestoreNeverOverwritesNewerDesiredState(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	previous := linkFor(t, "old-name", "10.80.142.0/31", "10.80.142.1/31")
	if _, err := engine.Ensure(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	newer := previous
	newer.DisplayName = "new-name"
	hook := &restoreSnapshotHookStore{Store: store}
	hook.onInitialSnapshot = func() {
		if _, err := engine.Ensure(context.Background(), newer); err != nil {
			t.Errorf("concurrent update: %v", err)
		}
	}
	engine.store = hook
	results, err := engine.RestoreAll(context.Background())
	if err != nil || len(results) != 1 {
		t.Fatalf("restore failed: %+v %v", results, err)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, ok := snapshot.Find(previous.ID)
	if !ok || record.Desired.DisplayName != newer.DisplayName || len(record.OwnedResources) != 1 || record.OwnedResources[0].Key != "new-name" {
		t.Fatalf("restore overwrote newer desired state: %+v", record)
	}
}

func TestRestoreContinuesThroughUnsupportedBackendInEitherOrder(t *testing.T) {
	for _, unsupportedFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("unsupportedFirst=%t", unsupportedFirst), func(t *testing.T) {
			b := newFakeBackend()
			engine, store := newEngine(t, b)
			supported := linkFor(t, "supported", "10.80.143.0/31", "10.80.143.1/31")
			unsupported := linkFor(t, "unsupported", "10.80.144.0/31", "10.80.144.1/31")
			unsupported.Backend = domain.BackendIPIP
			if unsupportedFirst {
				unsupported.ID = domain.LinkID("lnk_" + strings.Repeat("1", 32))
				supported.ID = domain.LinkID("lnk_" + strings.Repeat("2", 32))
			} else {
				supported.ID = domain.LinkID("lnk_" + strings.Repeat("1", 32))
				unsupported.ID = domain.LinkID("lnk_" + strings.Repeat("2", 32))
			}
			if err := store.Update(context.Background(), func(s *state.Snapshot) error {
				s.Upsert(state.LinkRecord{Desired: supported})
				s.Upsert(state.LinkRecord{Desired: unsupported})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			results, err := engine.RestoreAll(context.Background())
			if stlerr.CodeOf(err) != stlerr.CodeUnsupported {
				t.Fatalf("overall missing-backend failure invisible: %v", err)
			}
			if len(results) != 1 || results[0].LinkID != supported.ID || b.applyCount != 1 {
				t.Fatalf("independent supported Link was skipped: %+v applies=%d", results, b.applyCount)
			}
		})
	}
}
