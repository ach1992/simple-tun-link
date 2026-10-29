package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/state"
)

type orphanRestoreFixture struct {
	present    bool
	inspectErr error
	removeErr  error
	keepAfter  bool
	calls      int
	onRemove   func()
}

func (f *orphanRestoreFixture) IsRestoreInstalled(context.Context) (bool, error) {
	return f.present, f.inspectErr
}

func (f *orphanRestoreFixture) RemoveRestore(context.Context) error {
	f.calls++
	if f.onRemove != nil {
		f.onRemove()
	}
	if f.removeErr != nil {
		return f.removeErr
	}
	if !f.keepAfter {
		f.present = false
	}
	return nil
}

func TestRetireOrphanRestoreUnitGuardedReconciliation(t *testing.T) {
	trust := func(string) error { return nil } // private isolated fixture only
	for _, tc := range []struct {
		name      string
		fixture   orphanRestoreFixture
		success   bool
		wantCalls int
	}{
		{"owned orphan", orphanRestoreFixture{present: true}, true, 1},
		{"already absent retry", orphanRestoreFixture{}, true, 0},
		{"foreign or enabled without unit", orphanRestoreFixture{inspectErr: errors.New("unknown unit ownership")}, false, 0},
		{"interrupted systemctl", orphanRestoreFixture{present: true, removeErr: errors.New("disable interrupted")}, false, 1},
		{"missing absence proof", orphanRestoreFixture{present: true, keepAfter: true}, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			err := retireOrphanRestoreUnit(context.Background(), root, &tc.fixture, trust)
			if (err == nil) != tc.success || tc.fixture.calls != tc.wantCalls {
				t.Fatalf("retirement: err=%v calls=%d want success=%v calls=%d",
					err, tc.fixture.calls, tc.success, tc.wantCalls)
			}
			// Refusal must leave the original uncertain systemd state alone.
			if tc.fixture.inspectErr != nil && tc.fixture.calls != 0 {
				t.Fatal("unknown unit was modified after failed inspection")
			}
		})
	}
}

func TestRetireOrphanRestoreRejectsSavedOrReappearingState(t *testing.T) {
	trust := func(string) error { return nil }
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "state")
	link, _ := makeLifecycleDesired(t, "a", "10.70.91.0/31")
	store := state.NewFileStore(root)
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	unit := &orphanRestoreFixture{present: true}
	if err := retireOrphanRestoreUnit(ctx, root, unit, trust); err == nil || unit.calls != 0 {
		t.Fatalf("pending saved Link allowed unit retirement: %v (%d calls)", err, unit.calls)
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		s.Delete(link.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	unit.onRemove = func() {
		if err := store.Update(ctx, func(s *state.Snapshot) error {
			s.Upsert(state.LinkRecord{Desired: link})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := retireOrphanRestoreUnit(ctx, root, unit, trust); err == nil ||
		!strings.Contains(err.Error(), "State changed") || unit.calls != 1 {
		t.Fatalf("state reappeared after systemd but result was accepted: %v, calls=%d", err, unit.calls)
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); err != nil {
		t.Fatalf("State was incorrectly removed: %v", err)
	}
}

func TestOrphanRestoreRequiresInstallerPrivateTransition(t *testing.T) {
	if !isMaintenanceTransition([]string{"retire-orphan-restore", "--json"}) {
		t.Fatal("canonical private maintenance dispatch missing")
	}
	for _, args := range [][]string{{"retire-unknown"}, {"pre-uninstall", "--json"}} {
		if isMaintenanceTransition(args) {
			t.Fatalf("unsafe maintenance dispatch accepted: %q", args)
		}
	}
}
