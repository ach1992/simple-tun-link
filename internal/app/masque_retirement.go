package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type MASQUERetirementStore interface {
	RetireMatching(context.Context, domain.Link) error
}

func (e *Engine) SetMASQUERetirementStore(store MASQUERetirementStore) {
	e.masqueRetirement = store
}

// retireMASQUECredentialLocked must be called while the canonical Engine's
// maintenance and exact Link locks are already held. Its durable receipt is
// committed in the SAME State transaction as Remove. Missing or ambiguous
// original host objects keep the receipt pending; no destructive guess.
func (e *Engine) retireMASQUECredentialLocked(ctx context.Context, id domain.LinkID) error {
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeState, "masque_retire", string(id), "masque",
			"cannot load durable MASQUE retirement receipt", err)
	}
	receipt, found := snapshot.FindMASQUERemovalReceipt(id)
	if !found {
		return stlerr.New(stlerr.CodeConflict, "masque_retire", string(id), "masque",
			"no exact original MASQUE removal receipt exists")
	}
	if receipt.Retired {
		return nil
	}
	if receipt.Link.ID != id || receipt.Link.Backend != domain.BackendMASQUE ||
		receipt.Link.MASQUE.MaterialSHA256 != receipt.MaterialSHA256 {
		return stlerr.New(stlerr.CodeConflict, "masque_retire", string(id), "masque",
			"MASQUE original material receipt identity invalid")
	}
	if _, present := snapshot.Find(id); present {
		return stlerr.New(stlerr.CodeConflict, "masque_retire", string(id), "masque",
			"original committed Link still exists")
	}
	if _, pending := snapshot.FindMASQUEOperation(id); pending {
		return stlerr.New(stlerr.CodeConflict, "masque_retire", string(id), "masque",
			"interrupted MASQUE operation blocks credential retirement")
	}
	if e.masqueRetirement == nil {
		return stlerr.New(stlerr.CodeUnsupported, "masque_retire", string(id), "masque",
			"MASQUE exact-owned credential retirement store unavailable")
	}
	if err := e.masqueRetirement.RetireMatching(ctx, receipt.Link); err != nil {
		return stlerr.Wrap(stlerr.CodeState, "masque_retire", string(id), "masque",
			"MASQUE original material retirement outcome requires reconciliation", err)
	}
	if err := e.store.Update(ctx, func(current *state.Snapshot) error {
		same, ok := current.FindMASQUERemovalReceipt(id)
		if !ok || same != receipt {
			return errors.New("MASQUE material receipt changed during retirement")
		}
		if _, present := current.Find(id); present {
			return errors.New("MASQUE original Link reappeared before retirement")
		}
		if _, pending := current.FindMASQUEOperation(id); pending {
			return errors.New("MASQUE pre-effect journal emerged before retirement")
		}
		for i := range current.MASQUERemovalReceipts {
			if current.MASQUERemovalReceipts[i].Link.ID == id {
				current.MASQUERemovalReceipts[i].Retired = true
				return nil
			}
		}
		return errors.New("MASQUE exact original receipt disappeared")
	}); err != nil {
		return stlerr.Wrap(stlerr.CodeState, "masque_retire", string(id), "masque",
			"MASQUE original files were removed but retirement receipt update is unconfirmed", err)
	}
	return nil
}

// RetireMASQUECredential explicitly resumes only a committed, retired Link's
// original protected material cleanup, even if no live backend is available.
func (e *Engine) RetireMASQUECredential(ctx context.Context, id domain.LinkID) error {
	if err := id.Validate(); err != nil {
		return err
	}
	maintenanceRelease, err := e.acquireMaintenance(ctx)
	if err != nil {
		return fmt.Errorf("MASQUE maintenance admission unavailable: %w", err)
	}
	defer maintenanceRelease()
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return fmt.Errorf("MASQUE retirement Link lock unavailable: %w", err)
	}
	defer release()
	return e.retireMASQUECredentialLocked(ctx, id)
}
