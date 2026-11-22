package app

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// The fake host adapters observe the canonical Engine transaction stages;
// real kernel sysctl and credential/quarantine effects are independently
// tested in package spoofhost and on disposable privileged VM guests.
type interruptedRPFilter struct {
	failRelease   bool
	failReconcile bool
	releases      int
	reconciles    int
	check         func() error
}

func (*interruptedRPFilter) Preview(context.Context, state.Snapshot, domain.LinkID, string, string) (SpoofRPFilterPlan, error) {
	return SpoofRPFilterPlan{}, nil
}
func (*interruptedRPFilter) Apply(context.Context, state.Store, domain.LinkID, string, string) (SpoofRPFilterPlan, error) {
	return SpoofRPFilterPlan{}, nil
}
func (m *interruptedRPFilter) Release(ctx context.Context, store state.Store, id domain.LinkID) error {
	m.releases++
	if m.check != nil {
		if err := m.check(); err != nil {
			return err
		}
	}
	if m.failRelease {
		return errors.New("simulated kernel sysctl restoration failed")
	}
	return m.recover(ctx, store)
}
func (m *interruptedRPFilter) Reconcile(ctx context.Context, store state.Store) error {
	m.reconciles++
	if m.failReconcile {
		return errors.New("simulated kernel sysctl readback unavailable")
	}
	return m.recover(ctx, store)
}
func (m *interruptedRPFilter) recover(ctx context.Context, store state.Store) error {
	return store.Update(ctx, func(s *state.Snapshot) error {
		remaining := make([]state.SpoofRPFilterClaim, 0, len(s.SpoofRPFilterClaims))
		for _, c := range s.SpoofRPFilterClaims {
			if _, active := s.Find(c.LinkID); active {
				remaining = append(remaining, c)
			}
		}
		s.SpoofRPFilterClaims = remaining
		if len(remaining) == 0 {
			s.SpoofRPFilterSettings = nil
		}
		return nil
	})
}

type interruptedSpoofRetirement struct {
	store state.Store
	fail  bool
	calls int
}

func (m *interruptedSpoofRetirement) RetireAfterRemove(ctx context.Context, link domain.Link) error {
	m.calls++
	if m.fail {
		return errors.New("simulated protected quarantine cleanup failed")
	}
	return m.store.Update(ctx, func(s *state.Snapshot) error {
		if _, active := s.Find(link.ID); active {
			return errors.New("Link not durably removed")
		}
		for i := range s.SpoofRemovalReceipts {
			if s.SpoofRemovalReceipts[i].Link == link {
				s.SpoofRemovalReceipts[i].Retired = true
				return nil
			}
		}
		return errors.New("missing exact original retirement identity")
	})
}

type spoofRecoveryFixture struct {
	engine  *Engine
	store   *state.FileStore
	persist *fakeRestorePersistence
	policy  *interruptedRPFilter
	retire  *interruptedSpoofRetirement
	link    domain.Link
}

func newSpoofRecoveryFixture(t *testing.T) spoofRecoveryFixture {
	t.Helper()
	b := &provisioningSpoofFake{fakeBackend: newFakeBackend()}
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	p := &fakeRestorePersistence{}
	e, err := NewWithRestorePersistence(registry, store, state.NewLockManager(root), p, "/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	policy := &interruptedRPFilter{}
	retire := &interruptedSpoofRetirement{store: store}
	e.SetSpoofRPFilterManager(policy)
	e.SetSpoofRetirementStore(retire)
	link := provisioningSpoofLink(t, "rpf-last-owner", "10.244.151.1/32", "10.244.151.2/32")
	if _, err := e.EnsureWithSpoofProvision(context.Background(), link, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.SpoofRPFilterClaims = []state.SpoofRPFilterClaim{{LinkID: link.ID, Interface: "in0", Mode: "off"}}
		s.SpoofRPFilterSettings = []state.SpoofRPFilterSetting{{Interface: "all", Original: 1, Previous: 1, Desired: 0}, {Interface: "in0", Original: 1, Previous: 1, Desired: 0}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return spoofRecoveryFixture{engine: e, store: store, persist: p, policy: policy, retire: retire, link: link}
}
func (f spoofRecoveryFixture) assertPersistence(t *testing.T, active bool, removes int) {
	t.Helper()
	f.persist.mu.Lock()
	defer f.persist.mu.Unlock()
	if f.persist.active != active || f.persist.removes != removes {
		t.Fatalf("restore unit active=%t removes=%d; want active=%t removes=%d", f.persist.active, f.persist.removes, active, removes)
	}
}

func TestSpoofLastLinkInterruptedPolicyCleanupRetainsRebootRecoveryUnit(t *testing.T) {
	f := newSpoofRecoveryFixture(t)
	ctx := context.Background()
	f.policy.check = func() error {
		snapshot, err := f.store.Load(ctx)
		if err != nil {
			return err
		}
		if _, active := snapshot.Find(f.link.ID); active {
			return errors.New("postcommit Release preceded durable Link removal")
		}
		if r, ok := snapshot.FindSpoofRemovalReceipt(f.link.ID); !ok || r.Retired {
			return errors.New("original committed removal receipt missing before policy cleanup")
		}
		if !f.persist.active || f.persist.removes != 0 {
			return errors.New("reboot service removed before rp_filter Release")
		}
		return nil
	}
	f.policy.failRelease = true
	result, err := f.engine.Remove(ctx, f.link.ID)
	if err == nil || !result.Removed {
		t.Fatalf("injected interrupted Release not reported: %+v %v", result, err)
	}
	f.assertPersistence(t, true, 0)
	snapshot, err := f.store.Load(ctx)
	if err != nil || outstandingSpoofRecovery(snapshot) < 2 || len(snapshot.Links) != 0 {
		t.Fatalf("original owner journal not durable: %+v %v", snapshot, err)
	}
	f.policy.failRelease = false
	results, err := f.engine.RestoreAll(ctx)
	if err != nil || len(results) != 0 {
		t.Fatalf("reboot failed to reconcile pending last-owner recovery: %+v %v", results, err)
	}
	f.assertPersistence(t, false, 1)
	after, err := f.store.Load(ctx)
	if err != nil || outstandingRestoreObligations(after) != 0 {
		t.Fatalf("completed last-owner journals not settled: %+v %v", after, err)
	}
	if r, ok := after.FindSpoofRemovalReceipt(f.link.ID); !ok || !r.Retired {
		t.Fatal("boot-time original credential retirement not proven")
	}
}

func TestSpoofFailedPostCommitCredentialRetirementPreservesUnitUntilExplicitRetry(t *testing.T) {
	f := newSpoofRecoveryFixture(t)
	ctx := context.Background()
	f.retire.fail = true
	result, err := f.engine.Remove(ctx, f.link.ID)
	if err == nil || !result.Removed {
		t.Fatalf("failed credential cleanup hidden: %+v %v", result, err)
	}
	f.assertPersistence(t, true, 0)
	snapshot, err := f.store.Load(ctx)
	if err != nil || len(snapshot.SpoofRPFilterSettings) != 0 || outstandingSpoofRecovery(snapshot) != 1 {
		t.Fatalf("postcommit credential receipt was not retained: %+v %v", snapshot, err)
	}
	f.retire.fail = false
	if err := f.engine.RetireSpoofCredential(ctx, f.link.ID); err != nil {
		t.Fatalf("exact receipt retry failed: %v", err)
	}
	f.assertPersistence(t, false, 1)
}

func TestSpoofLastOwnerNormalRemoveAndSiblingPreservation(t *testing.T) {
	f := newSpoofRecoveryFixture(t)
	ctx := context.Background()
	sibling := provisioningSpoofLink(t, "spoof-sibling", "10.244.152.1/32", "10.244.152.2/32")
	if _, err := f.engine.EnsureWithSpoofProvision(ctx, sibling, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	result, err := f.engine.Remove(ctx, f.link.ID)
	if err != nil || !result.Removed {
		t.Fatalf("sibling-safe Remove failed: %+v %v", result, err)
	}
	f.assertPersistence(t, true, 0)
	snapshot, err := f.store.Load(ctx)
	if err != nil || len(snapshot.Links) != 1 || snapshot.Links[0].Desired.ID != sibling.ID || outstandingSpoofRecovery(snapshot) != 0 {
		t.Fatalf("remaining Spoof Link or journal damaged: %+v %v", snapshot, err)
	}
	if _, err := f.engine.Remove(ctx, sibling.ID); err != nil {
		t.Fatal(err)
	}
	f.assertPersistence(t, false, 1)
}

func TestSpoofRestoreDoesNotDropUnitWhenPolicyReconcileFails(t *testing.T) {
	f := newSpoofRecoveryFixture(t)
	ctx := context.Background()
	f.policy.failRelease = true
	if _, err := f.engine.Remove(ctx, f.link.ID); err == nil {
		t.Fatal("injected Release failure missing")
	}
	f.policy.failRelease = false
	f.policy.failReconcile = true
	_, err := f.engine.RestoreAll(ctx)
	if err == nil {
		t.Fatal("unsettled host journal accepted as healthy")
	}
	f.assertPersistence(t, true, 0)
	if s, loadErr := f.store.Load(ctx); loadErr != nil || outstandingSpoofRecovery(s) == 0 {
		t.Fatal("policy journal erased despite kernel failure")
	}
	f.policy.failReconcile = false
	if _, err := f.engine.RestoreAll(ctx); err != nil {
		t.Fatal(fmt.Errorf("restored manager cannot reconcile pending policy: %w", err))
	}
	f.assertPersistence(t, false, 1)
}
