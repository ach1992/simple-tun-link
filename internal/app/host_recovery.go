package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// outstandingRestoreObligations keeps the one existing host-wide restore
// mechanism installed while *any* exact Link or post-commit recovery journal
// still requires it. A Spoof Remove receipt remains pending until protected
// material is durably retired, independently of whether its Link still exists.
func outstandingSpoofRecovery(s state.Snapshot) int {
	n := len(s.SpoofRPFilterClaims) + len(s.SpoofRPFilterSettings)
	for _, receipt := range s.SpoofRemovalReceipts {
		if !receipt.Retired {
			n++
		}
	}
	return n
}

func outstandingRestoreObligations(s state.Snapshot) int {
	return len(s.Links) + len(s.QUICCrashOperations) + len(s.WSSCrashOperations) +
		len(s.MASQUEOperations) + outstandingSpoofRecovery(s)
}

// cleanupRestoreIfSettled is called AFTER committed post-Remove cleanup or
// an explicit receipt-bound retry. It rechecks all remaining obligations
// under the canonical host restore lock, which also serializes concurrent
// Link Ensure/Remove. It never deletes a unit solely from an absent State file.
func (e *Engine) cleanupRestoreIfSettled(ctx context.Context) error {
	if e.restorePersistence == nil {
		return nil
	}
	unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
	if err != nil {
		return fmt.Errorf("lock host restore persistence: %w", err)
	}
	defer unlock()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return err
	}
	if outstandingRestoreObligations(fresh) > 0 {
		return nil
	}
	witness, ok := e.store.(interface {
		HasCommittedState(context.Context) (bool, error)
	})
	if !ok {
		return errors.New("cannot prove durable empty desired State before restore cleanup")
	}
	committed, err := witness.HasCommittedState(ctx)
	if err != nil {
		return err
	}
	if !committed {
		return errors.New("cannot remove restore service without committed State")
	}
	return e.restorePersistence.RemoveRestore(ctx)
}

// restorePendingSpoofRetirements resumes previously committed owner-approved
// Remove receipts (not fresh or uncommitted credentials) on host reboot.
// Every retry uses the same Link lock/Host identity as the explicit command.
// Errors are returned per original Link; unrelated persisted Links still
// restore independently and the common Restore unit stays installed.
func (e *Engine) restorePendingSpoofRetirements(ctx context.Context, snapshot state.Snapshot) []error {
	var failures []error
	for _, receipt := range snapshot.SpoofRemovalReceipts {
		if receipt.Retired {
			continue
		}
		id := receipt.Link.ID
		unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
		if err == nil {
			err = e.retireSpoofCredentialLocked(ctx, id)
			unlockErr := unlock()
			if err == nil {
				err = unlockErr
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("resume original Spoof credential retirement %s: %w", id, err))
		}
	}
	return failures
}
