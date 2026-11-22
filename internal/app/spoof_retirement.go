package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// retireSpoofCredentialLocked reconciles the durable exact Link removal
// receipt after the original backend and its TUN were committed absent.
// Called only with the Engine maintenance + exact Link locks held.
func (e *Engine) retireSpoofCredentialLocked(ctx context.Context, id domain.LinkID) error {
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeState, "spoof_retire", string(id), "spoof", "cannot load original Spoof removal receipt", err)
	}
	receipt, found := snapshot.FindSpoofRemovalReceipt(id)
	if !found || receipt.Link.ID != id || receipt.Link.Backend != domain.BackendSpoof || receipt.Link.Validate() != nil {
		return stlerr.New(stlerr.CodeConflict, "spoof_retire", string(id), "spoof", "no valid exact committed Spoof removal receipt exists")
	}
	if _, present := snapshot.Find(id); present {
		return stlerr.New(stlerr.CodeConflict, "spoof_retire", string(id), "spoof", "original Spoof Link is still committed; refuse retirement")
	}
	if receipt.Retired {
		return nil
	}
	if e.spoofRetirement == nil {
		return stlerr.New(stlerr.CodeUnsupported, "spoof_retire", string(id), "spoof", "Spoof exact-owned material retirement host is unavailable")
	}
	if err := e.spoofRetirement.RetireAfterRemove(ctx, receipt.Link); err != nil {
		return stlerr.Wrap(stlerr.CodeState, "spoof_retire", string(id), "spoof",
			fmt.Sprintf("protected original retirement is incomplete (%v); verify owned service/TUN and retry stl link retire-spoof", err), err)
	}
	after, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeState, "spoof_retire", string(id), "spoof", "retirement completed but receipt readback failed", err)
	}
	verified, exists := after.FindSpoofRemovalReceipt(id)
	if !exists || !verified.Retired || verified.Link != receipt.Link {
		return stlerr.New(stlerr.CodeState, "spoof_retire", string(id), "spoof", "exact original retirement receipt has not been durably marked retired")
	}
	return nil
}

// RetireSpoofCredential safely resumes a committed Remove which was
// interrupted during protected-file quarantine/unlink or receipt publication.
// The exact State receipt is the only authority, not a user-supplied path.
func (e *Engine) RetireSpoofCredential(ctx context.Context, id domain.LinkID) error {
	if err := id.Validate(); err != nil {
		return err
	}
	maintenanceRelease, err := e.acquireMaintenance(ctx)
	if err != nil {
		return fmt.Errorf("Spoof retirement maintenance admission unavailable: %w", err)
	}
	defer maintenanceRelease()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return fmt.Errorf("Spoof retirement Link lock unavailable: %w", err)
	}
	defer linkRelease()
	return e.retireSpoofCredentialLocked(ctx, id)
}
