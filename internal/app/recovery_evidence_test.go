package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func requireOperationEvidence(t *testing.T, err error, stage, host, desired, rollback string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected failure with Engine evidence")
	}
	proof := stlerr.EvidenceOf(err)
	if proof == nil || proof.Stage != stage || proof.HostMutation != host ||
		proof.DesiredState != desired || proof.Rollback != rollback {
		t.Fatalf("incorrect Engine evidence: %+v, err=%v", proof, err)
	}
}

type failingApplyBackend struct {
	*fakeBackend
	undoFails bool
}

func (b *failingApplyBackend) Apply(ctx context.Context, req backend.Request, obs backend.Observation, p backend.Plan) (backend.Rollback, error) {
	undo, err := b.fakeBackend.Apply(ctx, req, obs, p)
	if err != nil {
		return undo, err
	}
	if b.undoFails {
		return func(context.Context) error {
			return errors.New("PSK=HIDDEN: rollback failed")
		}, errors.New("private_key=HIDDEN: backend apply failed")
	}
	return undo, errors.New("private_key=HIDDEN: backend apply failed")
}

func TestEngineReportsPreApplyFailureWithoutInventingHostMutation(t *testing.T) {
	engine, _ := newEngine(t, newFakeBackend())
	invalid := linkFor(t, "invalid", "10.92.11.0/31", "10.92.11.1/31")
	invalid.ID = ""
	_, err := engine.Ensure(context.Background(), invalid)
	if stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("wrong preflight error code %v", err)
	}
	requireOperationEvidence(t, err, "preflight", "not_attempted", "no_commit_attempted", "not_required")
}

func TestEngineDistinguishesVerifiedSuccessfulRollbackFromUnknownHostState(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(map[bool]string{false: "undo_returned_success", true: "undo_incomplete"}[fails], func(t *testing.T) {
			b := &failingApplyBackend{fakeBackend: newFakeBackend(), undoFails: fails}
			registry, err := backend.NewRegistry(b)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			engine, err := New(registry, state.NewFileStore(root), state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			link := linkFor(t, "partial", "10.92.12.0/31", "10.92.12.1/31")
			_, err = engine.Ensure(context.Background(), link)
			wantCode, wantRollback := stlerr.CodeApply, "completed_unverified"
			if fails {
				wantCode, wantRollback = stlerr.CodeRollback, "incomplete"
			}
			if stlerr.CodeOf(err) != wantCode {
				t.Fatalf("wrong apply error code: %v", err)
			}
			requireOperationEvidence(t, err, "apply", "attempted", "no_commit_attempted", wantRollback)
			if strings.Contains(stlerr.Public(err).Error(), "HIDDEN") {
				t.Fatal("secret-bearing cause leaked into public error")
			}
			snap, err := state.NewFileStore(root).Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := snap.Find(link.ID); exists {
				t.Fatal("failed apply committed desired Link")
			}
			_, hostPresent := b.present[link.ID]
			if hostPresent != fails {
				t.Fatalf("fake owned backend rollback disagrees with failure mode: present=%t", hostPresent)
			}
		})
	}
}

func TestEngineVerifyRollbackAndSiblingIsolationEvidence(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	a := linkFor(t, "peer-a", "10.92.13.0/31", "10.92.13.1/31")
	other := linkFor(t, "peer-b", "10.92.14.0/31", "10.92.14.1/31")
	if _, err := engine.Ensure(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Ensure(context.Background(), a)
	if err != nil || result.Changed {
		t.Fatalf("idempotent operation was not a verified no-op: result=%+v err=%v", result, err)
	}
	b.failVerifyOnce = true
	_, err = engine.Ensure(context.Background(), other)
	if stlerr.CodeOf(err) != stlerr.CodeVerify {
		t.Fatalf("unexpected verify error: %v", err)
	}
	requireOperationEvidence(t, err, "verify", "attempted", "no_commit_attempted", "completed_unverified")
	snap, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := snap.Find(a.ID); !exists {
		t.Fatal("independent Link was removed")
	}
	if _, exists := snap.Find(other.ID); exists {
		t.Fatal("failed sibling Link persisted")
	}
	if _, exists := b.present[a.ID]; !exists {
		t.Fatal("independent backend state was modified")
	}
}

func TestEnginePublishedIntentRemainsUncertainAndCannotBeUndone(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	engine.store = publishThenErrorStore{Store: store}
	link := linkFor(t, "published", "10.92.15.0/31", "10.92.15.1/31")
	result, err := engine.Ensure(context.Background(), link)
	if stlerr.CodeOf(err) != stlerr.CodeState || !result.Changed {
		t.Fatalf("unexpected publication failure: result=%+v err=%v", result, err)
	}
	requireOperationEvidence(t, err, "state_commit", "retained", "visible_unconfirmed", "not_attempted")
	snap, loadErr := store.Load(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, exists := snap.Find(link.ID); !exists || b.rollbackCount != 0 {
		t.Fatal("an indeterminate publication was compensated or lost")
	}
}

func TestEngineVerifyFailureOnNoopDoesNotInventHostMutation(t *testing.T) {
	b := newFakeBackend()
	engine, store := newEngine(t, b)
	link := linkFor(t, "noop-verify", "10.92.19.0/31", "10.92.19.1/31")
	if _, err := engine.Ensure(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	b.failVerifyOnce = true
	_, err := engine.Ensure(context.Background(), link)
	if stlerr.CodeOf(err) != stlerr.CodeVerify {
		t.Fatalf("incorrect failed no-op category: %v", err)
	}
	requireOperationEvidence(t, err, "verify", "not_attempted", "no_commit_attempted", "not_required")
	if b.applyCount != 1 || b.rollbackCount != 0 {
		t.Fatal("failed no-op verification incorrectly called mutation or rollback")
	}
	snapshot, loadErr := store.Load(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if _, found := snapshot.Find(link.ID); !found {
		t.Fatal("failed no-op verification removed committed Link")
	}
}

func TestEngineRejectsCrossLinkResourceConflictBeforeHostApply(t *testing.T) {
	b := newFakeBackend()
	engine, _ := newEngine(t, b)
	one := linkFor(t, "shared-ifname", "10.92.20.0/31", "10.92.20.1/31")
	two := linkFor(t, "shared-ifname", "10.92.21.0/31", "10.92.21.1/31")
	if _, err := engine.Ensure(context.Background(), one); err != nil {
		t.Fatal(err)
	}
	_, err := engine.Ensure(context.Background(), two)
	if stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("missing resource conflict: %v", err)
	}
	requireOperationEvidence(t, err, "plan", "not_attempted", "no_commit_attempted", "not_required")
	if b.applyCount != 1 {
		t.Fatal("conflicting Link mutated backend")
	}
}

type prePublicationFailureStore struct{ state.Store }

func (s prePublicationFailureStore) Update(context.Context, func(*state.Snapshot) error) error {
	return errors.New("store rejected publication before any write")
}

type rollbackAfterCommitFailureBackend struct {
	*fakeBackend
	failUndo bool
}

func (b *rollbackAfterCommitFailureBackend) Apply(ctx context.Context, req backend.Request, observed backend.Observation, p backend.Plan) (backend.Rollback, error) {
	undo, err := b.fakeBackend.Apply(ctx, req, observed, p)
	if err != nil {
		return undo, err
	}
	if b.failUndo {
		return func(context.Context) error { return errors.New("secret=hidden: incomplete backend compensation") }, nil
	}
	return undo, nil
}

func TestEngineCommitFailureEvidenceMatchesActualCompensation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback_callback_succeeded", true: "rollback_failed"}[fail], func(t *testing.T) {
			b := &rollbackAfterCommitFailureBackend{fakeBackend: newFakeBackend(), failUndo: fail}
			registry, err := backend.NewRegistry(b)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			committed := state.NewFileStore(root)
			engine, err := New(registry, prePublicationFailureStore{Store: committed}, state.NewLockManager(root))
			if err != nil {
				t.Fatal(err)
			}
			link := linkFor(t, "failed-commit", "10.92.25.0/31", "10.92.25.1/31")
			_, err = engine.Ensure(context.Background(), link)
			wantCode, wantRollback := stlerr.CodeState, "completed_unverified"
			if fail {
				wantCode, wantRollback = stlerr.CodeRollback, "incomplete"
			}
			if stlerr.CodeOf(err) != wantCode {
				t.Fatalf("unexpected commit compensation error: %v", err)
			}
			requireOperationEvidence(t, err, "state_commit", "attempted", "prior_verified", wantRollback)
			snap, loadErr := committed.Load(context.Background())
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if _, exists := snap.Find(link.ID); exists {
				t.Fatal("rejected commit persisted Link")
			}
			_, hostPresent := b.present[link.ID]
			if hostPresent != fail {
				t.Fatalf("backend compensation mismatch: present=%t fail=%t", hostPresent, fail)
			}
		})
	}
}
