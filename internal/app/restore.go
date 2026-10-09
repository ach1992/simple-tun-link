package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// RestoreAll reapplies persisted desired Links through the same idempotent
// Ensure lifecycle as ordinary operations. Completed results precede a
// failure, so the CLI can report actual partial progress without concealing
// a failed reapply.
func (e *Engine) RestoreAll(ctx context.Context) ([]Result, error) {
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot load persisted Links", err)
	}

	if len(snapshot.Links) == 0 && e.restorePersistence != nil {
		// Recheck under the same narrowly scoped lock used by every desired
		// state/persistence transition. A missing file or mount is not proof
		// that an existing reboot unit should be removed.
		release, lockErr := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
		if lockErr != nil {
			return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot lock restore persistence", lockErr)
		}
		fresh, reconcileErr := e.store.Load(ctx)
		if reconcileErr == nil && len(fresh.Links) == 0 {
			committed := false
			if witness, ok := e.store.(interface {
				HasCommittedState(context.Context) (bool, error)
			}); ok {
				committed, reconcileErr = witness.HasCommittedState(ctx)
			}
			if reconcileErr == nil {
				if committed {
					// A durable empty snapshot permits removing only STL's
					// owned unit (also retries failed last-owner cleanup).
					reconcileErr = e.restorePersistence.RemoveRestore(ctx)
				} else {
					var installed bool
					installed, reconcileErr = e.restorePersistence.IsRestoreInstalled(ctx)
					if reconcileErr == nil && installed {
						reconcileErr = stlerr.New(stlerr.CodeState, "restore_all", "", "", "restore unit exists but persisted desired state is missing")
					}
				}
			}
		}
		releaseErr := release()
		if reconcileErr != nil {
			if typed, ok := reconcileErr.(*stlerr.Error); ok {
				return nil, typed
			}
			return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot reconcile restore persistence", reconcileErr)
		}
		if releaseErr != nil {
			return nil, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "cannot release restore persistence lock", releaseErr)
		}
		snapshot = fresh
	}

	results := make([]Result, 0, len(snapshot.Links))
	var perLinkFailures []error
	for _, record := range snapshot.Links {
		if err := ctx.Err(); err != nil {
			return results, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "restore canceled or timed out", errors.Join(err, errors.Join(perLinkFailures...)))
		}
		result, present, err := e.restorePersisted(ctx, record.Desired.ID)
		if err != nil {
			failure := contextualize(err, stlerr.CodeApply, "restore", record.Desired, "cannot restore persisted Link")
			// A failed backend is independent when rollback completed and the
			// shared state/lock system remains trustworthy. A shared-state,
			// unknown, or incomplete-rollback failure stops the batch.
			if ctx.Err() != nil || !canContinueRestore(failure) {
				return results, stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "restore halted after a shared or unrecoverable failure", errors.Join(errors.Join(perLinkFailures...), failure))
			}
			perLinkFailures = append(perLinkFailures, failure)
			continue
		}
		if present {
			results = append(results, result)
		}
	}
	if len(perLinkFailures) != 0 {
		code := stlerr.CodeUnsupported
		for _, failure := range perLinkFailures {
			if stlerr.CodeOf(failure) != stlerr.CodeUnsupported {
				code = stlerr.CodeApply
				break
			}
		}
		return results, stlerr.Wrap(code, "restore_all", "", "",
			fmt.Sprintf("%d independent Link(s) could not be restored", len(perLinkFailures)), errors.Join(perLinkFailures...))
	}
	return results, nil
}

// restorePersisted holds the per-Link lock while refreshing committed intent.
// Unlike Ensure(userInput), it never replays stale intent captured before a
// concurrent Remove or update. It calls the same normal executeLocked engine.
func (e *Engine) restorePersisted(ctx context.Context, id domain.LinkID) (Result, bool, error) {
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return Result{}, false, stlerr.Wrap(stlerr.CodeState, "restore", string(id), "", "cannot lock persisted Link", err)
	}
	defer release()

	fresh, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, false, stlerr.Wrap(stlerr.CodeState, "restore", string(id), "", "cannot reload persisted Link intent", err)
	}
	record, exists := fresh.Find(id)
	if !exists {
		// Remove won before restore: skip rather than resurrecting the Link.
		return Result{}, false, nil
	}
	if err := record.Desired.Validate(); err != nil {
		return Result{}, true, contextualize(err, stlerr.CodeInvalid, "restore", record.Desired, "invalid persisted Link")
	}
	prior := record.Desired
	result, err := e.executeLocked(ctx, backend.Request{Operation: backend.OperationEnsure, Prior: &prior, Link: record.Desired}, record)
	return result, true, err
}

func canContinueRestore(err error) bool {
	switch stlerr.CodeOf(err) {
	case stlerr.CodeUnsupported, stlerr.CodeInvalid, stlerr.CodeConflict,
		stlerr.CodeInspect, stlerr.CodePlan, stlerr.CodeValidate,
		stlerr.CodeVerify:
		return true
	default:
		return false
	}
}
