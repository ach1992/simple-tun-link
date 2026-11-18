package app

import (
	"context"
	"errors"
	"reflect"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type MASQUEReconcileResult struct {
	LinkID           domain.LinkID
	Operation        string
	Recovery         string
	CommittedRemoved bool
	OriginalRetired  bool
}

// ReconcileMASQUE is a deliberate, explicitly confirmed recovery of an
// orphaned pre-effect journal. It never adopts/stops an unknown service or
// manipulates host networking. Only positive, repeated absence of the exact
// original service/TUN permits a State transition. Live or ambiguous host
// effects remain quarantined for independent intervention.
func (e *Engine) ReconcileMASQUE(ctx context.Context, id domain.LinkID) (result MASQUEReconcileResult, err error) {
	if err := id.Validate(); err != nil {
		return result, err
	}
	releaseMaintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return result, err
	}
	defer releaseMaintenance()
	releaseLink, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return result, err
	}
	defer releaseLink()
	initial, err := e.store.Load(ctx)
	if err != nil {
		return result, err
	}
	pending, found := initial.FindMASQUEOperation(id)
	if !found {
		return result, stlerr.New(stlerr.CodeConflict, "masque_reconcile", string(id), "masque", "no exact pending MASQUE host effect exists")
	}
	impl, available := e.backends.Get(domain.BackendMASQUE)
	if !available {
		return result, stlerr.New(stlerr.CodeUnsupported, "masque_reconcile", string(id), "masque", "MASQUE original host backend unavailable")
	}
	recoveryHost, ok := impl.(interface {
		MASQUEHostAbsent(context.Context, domain.Link) (bool, error)
	})
	if !ok {
		return result, errors.New("MASQUE host absent proof reader unavailable")
	}
	releaseResources, err := e.locks.Acquire(ctx, pending.Resources)
	if err != nil {
		return result, err
	}
	defer releaseResources()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return result, err
	}
	if current, exists := fresh.FindMASQUEOperation(id); !exists || !reflect.DeepEqual(current, pending) {
		return result, errors.New("MASQUE original pending intent changed under resource lock")
	}
	absent, err := recoveryHost.MASQUEHostAbsent(ctx, pending.Intent)
	if err != nil {
		return result, stlerr.Wrap(stlerr.CodeInspect, "masque_reconcile", string(id), "masque", "original host absence cannot be proven", err)
	}
	if !absent {
		return result, stlerr.New(stlerr.CodeConflict, "masque_reconcile", string(id), "masque", "original service/TUN may remain: no deletion or journal clear authorized")
	}
	// Repeat host inspection at the durable update boundary; an absent
	// interface name observed once is not ownership or lifetime proof.
	if absent, err = recoveryHost.MASQUEHostAbsent(ctx, pending.Intent); err != nil || !absent {
		return result, errors.New("MASQUE original host absence changed before recovery commit")
	}
	previousRecord, hadCommitted := fresh.Find(id)
	if pending.HadCommittedLink != hadCommitted ||
		hadCommitted && previousRecord.Desired != pending.Intent {
		return result, errors.New("MASQUE committed owner changed before recovery")
	}
	result = MASQUEReconcileResult{LinkID: id, Operation: pending.Operation}
	var purpose string
	commitErr := e.store.Update(ctx, func(snapshot *state.Snapshot) error {
		current, exists := snapshot.FindMASQUEOperation(id)
		if !exists || !reflect.DeepEqual(current, pending) {
			return errors.New("MASQUE recovery journal changed before State publication")
		}
		stored, committed := snapshot.Find(id)
		if committed != pending.HadCommittedLink ||
			committed && (stored.Desired != previousRecord.Desired ||
				!slices.Equal(stored.OwnedResources, previousRecord.OwnedResources)) {
			return errors.New("MASQUE original committed State differs from recovery intent")
		}
		if receipt, exists := snapshot.FindMASQUERemovalReceipt(id); exists {
			_ = receipt
			return errors.New("original MASQUE material receipt already reserved")
		}
		switch {
		case pending.Operation == "ensure" && !pending.HadCommittedLink:
			result.Recovery = "abandoned_uncommitted"
			purpose = "abandoned"
			snapshot.MASQUERemovalReceipts = append(snapshot.MASQUERemovalReceipts, state.MASQUERemovalReceipt{
				Link: pending.Intent, MaterialSHA256: pending.Intent.MASQUE.MaterialSHA256, Purpose: purpose})
		case pending.Operation == "ensure" && pending.HadCommittedLink:
			if _, existing := snapshot.FindMASQUERecoveryReceipt(id); existing {
				return errors.New("MASQUE committed original already has a recovery attestation")
			}
			result.Recovery = "committed_original_retained"
			snapshot.MASQUERecoveryReceipts = append(snapshot.MASQUERecoveryReceipts, state.MASQUERecoveryReceipt{
				LinkID: id, OriginalNonce: pending.Nonce, Outcome: "ensure_host_absent",
				MaterialSHA256: pending.Intent.MASQUE.MaterialSHA256})
		case pending.Operation == "remove" && pending.HadCommittedLink:
			if !snapshot.Delete(id) {
				return errors.New("MASQUE committed Link vanished during recovery")
			}
			result.Recovery = "completed_remove_after_verified_absence"
			result.CommittedRemoved = true
			purpose = "removed"
			snapshot.MASQUERemovalReceipts = append(snapshot.MASQUERemovalReceipts, state.MASQUERemovalReceipt{
				Link: pending.Intent, MaterialSHA256: pending.Intent.MASQUE.MaterialSHA256, Purpose: purpose})
		default:
			return errors.New("MASQUE recovery journal has unsupported original operation")
		}
		if !snapshot.DeleteMASQUEOperation(id) {
			return errors.New("MASQUE original pre-effect journal not consumable")
		}
		return nil
	})
	if commitErr != nil {
		return MASQUEReconcileResult{}, stlerr.Wrap(stlerr.CodeState, "masque_reconcile", string(id), "masque",
			"original MASQUE recovery State publication unconfirmed; preserve host and material", commitErr)
	}
	if purpose != "" {
		if err := e.retireMASQUECredentialLocked(ctx, id); err != nil {
			return result, stlerr.Wrap(stlerr.CodeState, "masque_reconcile", string(id), "masque",
				"original MASQUE host reconciled; exact material retirement still pending", err)
		}
		result.OriginalRetired = true
	}
	// Persistence cleanup of the last Link cannot be inferred from State
	// disappearance alone: preserve the restore unit for its owned
	// maintenance pass. An ordinary successful Remove has its own separate
	// restore-unit retirement path.
	return result, nil
}
