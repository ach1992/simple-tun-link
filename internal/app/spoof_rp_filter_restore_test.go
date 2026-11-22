package app

import (
	"context"
	"errors"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type failingRPFRestore struct{}

func (failingRPFRestore) Preview(context.Context, state.Snapshot, domain.LinkID, string, string) (SpoofRPFilterPlan, error) {
	return SpoofRPFilterPlan{}, nil
}
func (failingRPFRestore) Apply(context.Context, state.Store, domain.LinkID, string, string) (SpoofRPFilterPlan, error) {
	return SpoofRPFilterPlan{}, nil
}
func (failingRPFRestore) Release(context.Context, state.Store, domain.LinkID) error { return nil }
func (failingRPFRestore) Reconcile(context.Context, state.Store) error {
	return errors.New("fake before-values no longer match")
}

func TestRPFilterReconcileFailureKeepsUnrelatedSavedLinksRestorable(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	link := linkFor(t, "restorable-independent-gre", "10.80.220.0/31", "10.80.220.1/31")
	if err := store.Update(context.Background(), func(s *state.Snapshot) error { s.Upsert(state.LinkRecord{Desired: link}); return nil }); err != nil {
		t.Fatal(err)
	}
	engine.SetSpoofRPFilterManager(failingRPFRestore{})
	results, err := engine.RestoreAll(context.Background())
	if err == nil || len(results) != 1 || results[0].LinkID != link.ID || b.applyCount != 1 {
		t.Fatalf("unrelated native Link was unnecessarily blocked: restored=%+v applies=%d err=%v", results, b.applyCount, err)
	}
}

func TestRPFilterReconcileFailurePreventsDroppingLastRecoveryUnit(t *testing.T) {
	b := newFakeBackend()
	engine, _ := newEngine(t, b)
	engine.SetSpoofRPFilterManager(failingRPFRestore{})
	results, err := engine.RestoreAll(context.Background())
	if err == nil || len(results) != 0 {
		t.Fatalf("unresolved host rp_filter policy treated as clean empty State: %+v %v", results, err)
	}
}
