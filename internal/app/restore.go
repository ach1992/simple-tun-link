package app

import (
	"context"

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
	for _, record := range snapshot.Links {
		result, err := e.Ensure(ctx, record.Desired)
		if err != nil {
			return results, contextualize(err, stlerr.CodeApply, "restore", record.Desired, "cannot restore persisted Link")
		}
		results = append(results, result)
	}
	return results, nil
}
