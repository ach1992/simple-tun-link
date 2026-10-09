package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// cancellationBackend applies the real fake delta before injecting caller
// cancellation. Its owned undo deliberately refuses canceled/expired contexts.
type cancellationBackend struct {
	*fakeBackend
	cancel           context.CancelFunc
	cancelAt         string
	failRollback     bool
	rollbackCalls    int
	rollbackCtxErr   error
	rollbackDeadline bool
}

func (b *cancellationBackend) Apply(ctx context.Context, req backend.Request, observed backend.Observation, plan backend.Plan) (backend.Rollback, error) {
	undo, err := b.fakeBackend.Apply(ctx, req, observed, plan)
	if err != nil {
		return nil, err
	}
	boundedUndo := func(cleanupCtx context.Context) error {
		b.rollbackCalls++
		b.rollbackCtxErr = cleanupCtx.Err()
		_, b.rollbackDeadline = cleanupCtx.Deadline()
		if b.rollbackCtxErr != nil {
			return b.rollbackCtxErr
		}
		if b.failRollback {
			return errors.New("deliberate owned rollback failure")
		}
		return undo(cleanupCtx)
	}
	if b.cancelAt == "apply" {
		b.cancel()
		return boundedUndo, context.Canceled
	}
	return boundedUndo, nil
}

func (b *cancellationBackend) Verify(ctx context.Context, req backend.Request) (backend.Observation, error) {
	if b.cancelAt == "verify" {
		b.cancel()
		return nil, context.Canceled
	}
	return b.fakeBackend.Verify(ctx, req)
}

func TestCanceledBackendMutationUsesDetachedBoundedRollback(t *testing.T) {
	for _, phase := range []string{"apply", "verify", "commit"} {
		for _, failRollback := range []bool{false, true} {
			t.Run(phase+"/"+map[bool]string{false: "success", true: "incomplete"}[failRollback], func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				b := &cancellationBackend{
					fakeBackend:  newFakeBackend(),
					cancel:       cancel,
					cancelAt:     phase,
					failRollback: failRollback,
				}
				registry, err := backend.NewRegistry(b)
				if err != nil {
					t.Fatal(err)
				}
				root := t.TempDir()
				var store state.Store = state.NewFileStore(root)
				if phase == "commit" {
					store = canceledCommitStore{Store: store, cancel: cancel}
				}
				engine, err := New(registry, store, state.NewLockManager(root))
				if err != nil {
					t.Fatal(err)
				}
				link := linkFor(t, "safe-"+phase, "10.90.210.0/31", "10.90.210.1/31")
				_, operationErr := engine.Ensure(ctx, link)
				expectedCode := stlerr.CodeRollback
				if !failRollback {
					switch phase {
					case "apply":
						expectedCode = stlerr.CodeApply
					case "verify":
						expectedCode = stlerr.CodeVerify
					case "commit":
						expectedCode = stlerr.CodeState
					}
				}
				if got := stlerr.CodeOf(operationErr); got != expectedCode {
					t.Fatalf("code=%q want %q: %v", got, expectedCode, operationErr)
				}
				if !errors.Is(operationErr, context.Canceled) {
					t.Fatalf("original cancellation was not retained: %v", operationErr)
				}
				if b.rollbackCalls != 1 || b.rollbackCtxErr != nil || !b.rollbackDeadline {
					t.Fatalf("owned undo not executed with fresh bounded context: calls=%d ctxErr=%v deadline=%t",
						b.rollbackCalls, b.rollbackCtxErr, b.rollbackDeadline)
				}
				b.mu.Lock()
				_, left := b.present[link.ID]
				b.mu.Unlock()
				if left != failRollback {
					t.Fatalf("wrong backend residual state: present=%t rollbackFails=%t", left, failRollback)
				}
				snapshot, err := store.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if _, persisted := snapshot.Find(link.ID); persisted {
					t.Fatal("an unsuccessful operation committed desired state")
				}
			})
		}
	}
}

// Validate that the rollback context is bounded by a deadline rather than
// merely detached from the caller, without sleeping for production timeouts.
func TestRollbackCleanupContextCarriesDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine := &Engine{}
	link := linkFor(t, "deadline-test", "10.90.211.0/31", "10.90.211.1/31")
	request := backend.Request{Operation: backend.OperationEnsure, Link: link}
	var deadline time.Time
	sentinel := errors.New("apply failed")
	err := engine.rollbackFailure(ctx, request, link, func(cleanupCtx context.Context) error {
		if cleanupCtx.Err() != nil {
			t.Fatalf("cleanup received canceled context: %v", cleanupCtx.Err())
		}
		var hasDeadline bool
		deadline, hasDeadline = cleanupCtx.Deadline()
		if !hasDeadline {
			t.Fatal("cleanup is unbounded")
		}
		return nil
	}, sentinel)
	if !errors.Is(err, sentinel) {
		t.Fatalf("original error was masked: %v", err)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 30*time.Second {
		t.Fatalf("unexpected rollback deadline: %v", remaining)
	}
}

var _ backend.Backend = (*cancellationBackend)(nil)
