package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type fakeRestorePersistence struct {
	mu         sync.Mutex
	active     bool
	ensures    int
	removes    int
	undos      int
	failEnsure bool
	failRemove bool
}

func (p *fakeRestorePersistence) EnsureRestore(context.Context, string) (func(context.Context) error, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ensures++
	if p.failEnsure {
		return nil, false, errors.New("private_key=NOT-FOR-OUTPUT")
	}
	wasActive := p.active
	p.active = true
	return func(context.Context) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.undos++
		p.active = wasActive
		return nil
	}, !wasActive, nil
}

func (p *fakeRestorePersistence) IsRestoreInstalled(context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active, nil
}

func (p *fakeRestorePersistence) RemoveRestore(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removes++
	if p.failRemove {
		return errors.New("remove unit failed")
	}
	p.active = false
	return nil
}

func persistentTestEngine(t *testing.T, b *fakeBackend, p *fakeRestorePersistence) (*Engine, *state.FileStore) {
	t.Helper()
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store := state.NewFileStore(root)
	engine, err := NewWithRestorePersistence(registry, store, state.NewLockManager(root), p, "/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	return engine, store
}

func TestPersistenceActivationTracksMultiLinkLastOwner(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{}
	engine, _ := persistentTestEngine(t, b, p)
	a := linkFor(t, "persist-one", "10.80.91.0/31", "10.80.91.1/31")
	z := linkFor(t, "persist-two", "10.80.92.0/31", "10.80.92.1/31")

	if _, err := engine.Ensure(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Ensure(context.Background(), z); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Remove(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	stillActive, priorRemoves := p.active, p.removes
	p.mu.Unlock()
	if !stillActive || priorRemoves != 0 {
		t.Fatalf("persistence disabled with sibling Link: active=%t removes=%d", stillActive, priorRemoves)
	}

	if _, err := engine.Remove(context.Background(), z.ID); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active || p.removes != 1 || p.ensures != 2 {
		t.Fatalf("persistence tracking: active=%t removes=%d ensures=%d", p.active, p.removes, p.ensures)
	}
}

func TestPersistenceActivationFailureRollsBackBackendBeforeCommit(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{failEnsure: true}
	engine, store := persistentTestEngine(t, b, p)
	link := linkFor(t, "persist-fail", "10.80.93.0/31", "10.80.93.1/31")

	_, err := engine.Ensure(context.Background(), link)
	if stlerr.CodeOf(err) != stlerr.CodeState {
		t.Fatalf("expected state error, got %v", err)
	}
	if strings.Contains(err.Error(), "NOT-FOR-OUTPUT") {
		t.Fatalf("secret surfaced in public error: %v", err)
	}
	if b.rollbackCount != 1 {
		t.Fatalf("backend not rolled back after failed persistence activation: %d", b.rollbackCount)
	}
	snapshot, loadErr := store.Load(context.Background())
	if loadErr != nil || len(snapshot.Links) != 0 {
		t.Fatalf("failed Ensure left persisted Link: snapshot=%v err=%v", snapshot, loadErr)
	}
}

type rejectCommitStore struct{ state.Store }

func (*rejectCommitStore) Update(context.Context, func(*state.Snapshot) error) error {
	return errors.New("commit rejected")
}

func TestPersistenceRollsBackWhenStateCommitFails(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{}
	engine, _ := persistentTestEngine(t, b, p)
	engine.store = &rejectCommitStore{Store: engine.store}
	link := linkFor(t, "persist-commit-fail", "10.80.94.0/31", "10.80.94.1/31")

	_, err := engine.Ensure(context.Background(), link)
	if stlerr.CodeOf(err) != stlerr.CodeState {
		t.Fatalf("expected state commit error, got %v", err)
	}
	p.mu.Lock()
	active, undos := p.active, p.undos
	p.mu.Unlock()
	if active || undos != 1 || b.rollbackCount != 1 {
		t.Fatalf("incomplete rollback: active=%t undos=%d backend=%d", active, undos, b.rollbackCount)
	}
}

func TestRemoveReportsPartialFailureAfterCommitWhenUnitCleanupFails(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{}
	engine, store := persistentTestEngine(t, b, p)
	link := linkFor(t, "persist-removal", "10.80.95.0/31", "10.80.95.1/31")
	if _, err := engine.Ensure(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	p.failRemove = true
	result, err := engine.Remove(context.Background(), link.ID)
	if stlerr.CodeOf(err) != stlerr.CodeState || !result.Removed {
		t.Fatalf("expected reported partial removal, got %#v %v", result, err)
	}
	snapshot, loadErr := store.Load(context.Background())
	if loadErr != nil || len(snapshot.Links) != 0 {
		t.Fatalf("last Link removal was not committed: %v %v", snapshot, loadErr)
	}
	if b.rollbackCount != 0 {
		t.Fatal("completed removal was incorrectly rolled back")
	}
}

func TestRestoreAllReconcilesPersistenceThroughNormalEnsure(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{}
	engine, store := persistentTestEngine(t, b, p)
	link := linkFor(t, "persist-restore", "10.80.96.0/31", "10.80.96.1/31")
	if err := store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	results, err := engine.RestoreAll(context.Background())
	if err != nil || len(results) != 1 {
		t.Fatalf("restore did not re-Ensure persisted Link: %v %v", results, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.ensures != 1 || b.applyCount != 1 {
		t.Fatalf("restore failed to activate unit and backend: active=%t ensures=%d applies=%d", p.active, p.ensures, b.applyCount)
	}
}

func TestNoPersistenceManagerStillSupportsManualEnsure(t *testing.T) {
	b := newFakeBackend()
	engine, _ := newEngine(t, b)
	link := linkFor(t, "manual-link", "10.80.97.0/31", "10.80.97.1/31")
	if _, err := engine.Ensure(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Remove(context.Background(), link.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreEmptyReconcilesOrphanedOwnedPersistence(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{active: true}
	engine, store := persistentTestEngine(t, b, p)
	if err := store.Update(context.Background(), func(*state.Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	results, err := engine.RestoreAll(context.Background())
	if err != nil || len(results) != 0 {
		t.Fatalf("empty restore cannot reconcile persistence: %v %v", results, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active || p.removes != 1 || p.ensures != 0 {
		t.Fatalf("orphaned unit was not cleaned: active=%t removes=%d ensures=%d", p.active, p.removes, p.ensures)
	}
}

func TestRestoreEmptyReportsOwnedPersistenceCleanupFailure(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{active: true, failRemove: true}
	engine, store := persistentTestEngine(t, b, p)
	if err := store.Update(context.Background(), func(*state.Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, err := engine.RestoreAll(context.Background())
	if stlerr.CodeOf(err) != stlerr.CodeState {
		t.Fatalf("expected cleanup error, got %v", err)
	}
}

// When a state mount/file goes missing, never infer permission to delete an
// existing reboot unit. This is a fail-closed ownership and durability guard.
func TestRestoreAbsentStateNeverDeletesExistingUnit(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{active: true}
	engine, _ := persistentTestEngine(t, b, p)
	_, err := engine.RestoreAll(context.Background())
	if stlerr.CodeOf(err) != stlerr.CodeState || !strings.Contains(err.Error(), "persisted desired state is missing") {
		t.Fatalf("missing state was silently treated as empty: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.removes != 0 {
		t.Fatalf("absent state incorrectly triggered persistence removal: active=%t removes=%d", p.active, p.removes)
	}
}

// Independent links may prepare/apply concurrently, but their final persistence
// transitions must serialize so neither removal nor creation can lose the unit.
func TestConcurrentMultiLinkPersistenceTransitions(t *testing.T) {
	b, p := newFakeBackend(), &fakeRestorePersistence{}
	b.applyDelay = 20 * time.Millisecond
	engine, store := persistentTestEngine(t, b, p)
	first := linkFor(t, "concurrent-persist-a", "10.80.110.0/31", "10.80.110.1/31")
	second := linkFor(t, "concurrent-persist-b", "10.80.111.0/31", "10.80.111.1/31")

	var wg sync.WaitGroup
	var errs [2]error
	wg.Add(2)
	go func() { defer wg.Done(); _, errs[0] = engine.Ensure(context.Background(), first) }()
	go func() { defer wg.Done(); _, errs[1] = engine.Ensure(context.Background(), second) }()
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("concurrent Ensures failed: %v %v", errs[0], errs[1])
	}
	snapshot, err := store.Load(context.Background())
	if err != nil || len(snapshot.Links) != 2 {
		t.Fatalf("missing concurrently committed Links: %+v %v", snapshot, err)
	}

	wg.Add(2)
	go func() { defer wg.Done(); _, errs[0] = engine.Remove(context.Background(), first.ID) }()
	go func() { defer wg.Done(); _, errs[1] = engine.Remove(context.Background(), second.ID) }()
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("concurrent Removes failed: %v %v", errs[0], errs[1])
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active || p.removes != 1 {
		t.Fatalf("concurrent last-owner cleanup violated: active=%t removes=%d", p.active, p.removes)
	}
}

type cancelPersistence struct{ cancel context.CancelFunc }

func (p cancelPersistence) EnsureRestore(context.Context, string) (func(context.Context) error, bool, error) {
	p.cancel()
	return nil, false, context.Canceled
}
func (cancelPersistence) RemoveRestore(context.Context) error              { return nil }
func (cancelPersistence) IsRestoreInstalled(context.Context) (bool, error) { return false, nil }

type contextAwareBackend struct {
	*fakeBackend
	rollbackCtxErr error
}

func (b *contextAwareBackend) Apply(ctx context.Context, req backend.Request, observed backend.Observation, plan backend.Plan) (backend.Rollback, error) {
	undo, err := b.fakeBackend.Apply(ctx, req, observed, plan)
	if err != nil {
		return nil, err
	}
	return func(rollbackCtx context.Context) error {
		if rollbackCtx.Err() != nil {
			b.rollbackCtxErr = rollbackCtx.Err()
			return rollbackCtx.Err()
		}
		return undo(rollbackCtx)
	}, nil
}

func TestPersistenceFailureAfterContextCancellationStillRollsBackBackend(t *testing.T) {
	b := &contextAwareBackend{fakeBackend: newFakeBackend()}
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine, err := NewWithRestorePersistence(registry, state.NewFileStore(root), state.NewLockManager(root),
		cancelPersistence{cancel: cancel}, "/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	link := linkFor(t, "cancel-persist", "10.80.112.0/31", "10.80.112.1/31")
	_, err = engine.Ensure(ctx, link)
	if err == nil {
		t.Fatal("expected cancellation-related persistence failure")
	}
	if b.rollbackCtxErr != nil || b.rollbackCount != 1 {
		t.Fatalf("canceled context prevented owned backend rollback: ctxErr=%v count=%d", b.rollbackCtxErr, b.rollbackCount)
	}
}

type canceledCommitStore struct {
	state.Store
	cancel context.CancelFunc
}

func (s canceledCommitStore) Update(context.Context, func(*state.Snapshot) error) error {
	s.cancel()
	return context.Canceled
}

type contextAwarePersistence struct {
	*fakeRestorePersistence
	rollbackCtxErr error
}

func (p *contextAwarePersistence) EnsureRestore(ctx context.Context, executable string) (func(context.Context) error, bool, error) {
	undo, changed, err := p.fakeRestorePersistence.EnsureRestore(ctx, executable)
	if err != nil {
		return nil, false, err
	}
	return func(undoCtx context.Context) error {
		if undoCtx.Err() != nil {
			p.rollbackCtxErr = undoCtx.Err()
			return undoCtx.Err()
		}
		return undo(undoCtx)
	}, changed, nil
}

func TestCommitCancellationStillRollsBackPersistenceAndBackend(t *testing.T) {
	b := &contextAwareBackend{fakeBackend: newFakeBackend()}
	p := &contextAwarePersistence{fakeRestorePersistence: &fakeRestorePersistence{}}
	registry, err := backend.NewRegistry(b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := canceledCommitStore{Store: state.NewFileStore(root), cancel: cancel}
	engine, err := NewWithRestorePersistence(registry, store, state.NewLockManager(root), p, "/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	link := linkFor(t, "cancel-commit", "10.80.113.0/31", "10.80.113.1/31")
	_, err = engine.Ensure(ctx, link)
	if err == nil {
		t.Fatal("expected state commit cancellation")
	}
	if b.rollbackCtxErr != nil || b.rollbackCount != 1 || p.rollbackCtxErr != nil || p.undos != 1 || p.active {
		t.Fatalf("cancellation lost rollback: backendContext=%v backendCount=%d unitContext=%v unitUndos=%d unitActive=%t",
			b.rollbackCtxErr, b.rollbackCount, p.rollbackCtxErr, p.undos, p.active)
	}
}
