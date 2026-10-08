package app

import (
	"context"
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
