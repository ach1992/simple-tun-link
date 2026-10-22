package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// prepareWSSCrash journals the complete public WSS transaction BEFORE the
// first host effect. Called only under canonical Link AND resource locks,
// after final Inspect/Validate, and never for unrelated backends.
// A prepared record is a fail-closed reservation, NOT host ownership proof.
func (e *Engine) prepareWSSCrash(ctx context.Context, request backend.Request,
	prior state.LinkRecord, claims []domain.ResourceClaim) (state.WSSCrashOperation, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return state.WSSCrashOperation{}, stlerr.New(stlerr.CodeState, "wss_prepare", string(request.Link.ID),
			string(request.Link.Backend), "cannot allocate WSS crash transaction nonce")
	}
	op := state.WSSCrashOperation{
		Intent: request.Link, Operation: string(request.Operation),
		Nonce: hex.EncodeToString(nonce[:]), Resources: append([]domain.ResourceClaim(nil), claims...),
		HadCommittedLink: prior.Desired.ID == request.Link.ID,
	}
	if op.HadCommittedLink {
		op.OriginalHostNonce = prior.WSSOrigin
	}
	err := e.store.Update(ctx, func(s *state.Snapshot) error {
		if _, exists := s.FindWSSCrashOperation(request.Link.ID); exists {
			return fmt.Errorf("existing WSS crash journal requires reconciliation")
		}
		previous, exists := s.Find(request.Link.ID)
		if exists != op.HadCommittedLink || (exists && (previous.Desired != prior.Desired ||
			previous.WSSFiles != prior.WSSFiles ||
			previous.WSSOrigin != prior.WSSOrigin ||
			!slices.Equal(previous.OwnedResources, prior.OwnedResources))) {
			return fmt.Errorf("committed WSS Link changed before pre-effect journal")
		}
		if request.Operation == backend.OperationRemove && (!exists || previous.Desired != request.Link) {
			return fmt.Errorf("WSS Remove missing exact committed Link owner")
		}
		if request.Operation == backend.OperationEnsure {
			if err := rejectResourceConflicts(*s, request.Link.ID, claims); err != nil {
				return err
			}
		}
		s.WSSCrashOperations = append(s.WSSCrashOperations, op)
		return nil
	})
	if err != nil {
		// Publication may have happened before the fsync error. No host
		// effects are allowed; do not automatically clear an uncertain record.
		return state.WSSCrashOperation{}, stlerr.Wrap(stlerr.CodeState, "wss_prepare",
			string(request.Link.ID), string(request.Link.Backend),
			"cannot prove durable WSS pre-effect intent; no backend Apply attempted", err)
	}
	return op, nil
}

// ReconcileWSSCrashVacant is a narrowly safe recovery for a new WSS Ensure
// whose host resources are independently proven ABSENT. It never adopts or
// deletes a guard, helper, interface, private key or foreign resource.
// A journal with ANY observed host effect remains quarantined until a
// separately reviewed, identity-attested compensation is available.
func (e *Engine) ReconcileWSSCrashVacant(ctx context.Context, id domain.LinkID) error {
	return e.reconcileWSSCrash(ctx, id, false)
}

// ReconcileWSSCrashRemoved finalizes a previously committed WSS Remove
// ONLY when the exact original Link and all THREE host resources (WG
// interface, nft table and loaded systemd helper) are independently absent.
// It commits deletion + immutable retirement receipt in one State update.
// No command to mutate host networking, systemd or protected files is issued.
func (e *Engine) ReconcileWSSCrashRemoved(ctx context.Context, id domain.LinkID) error {
	return e.reconcileWSSCrash(ctx, id, true)
}

// ReconcileWSSCrashRepairVacant preserves an exact previously committed
// Link/credentials/claims while clearing ONLY an interrupted Ensure journal
// after independent proof that ALL original host resources are absent.
func (e *Engine) ReconcileWSSCrashRepairVacant(ctx context.Context, id domain.LinkID) error {
	return e.reconcileWSSCrashMode(ctx, id, "repair-vacant")
}

// ReconcileWSSCrashOriginal performs explicitly confirmed, bounded
// original-object compensation on an unresolved journal. It never silently
// uses resource names as authority, nor replays the original Ensure/Remove.
// Unsafe/foreign/unknown objects keep the exact journal quarantined.
func (e *Engine) ReconcileWSSCrashOriginal(ctx context.Context, id domain.LinkID) error {
	return e.reconcileWSSCrashMode(ctx, id, "original")
}
func (e *Engine) reconcileWSSCrash(ctx context.Context, id domain.LinkID, removed bool) error {
	mode := "initial-vacant"
	if removed {
		mode = "removed"
	}
	return e.reconcileWSSCrashMode(ctx, id, mode)
}
func (e *Engine) reconcileWSSCrashMode(ctx context.Context, id domain.LinkID, mode string) error {
	removed := mode == "removed"
	repair := mode == "repair-vacant"
	originalRecovery := mode == "original"
	if mode != "removed" && mode != "repair-vacant" && mode != "initial-vacant" && !originalRecovery {
		return stlerr.New(stlerr.CodeInvalid, "wss_reconcile", string(id), "wireguard-wss", "unsupported WSS recovery operation")
	}
	if err := id.Validate(); err != nil {
		return stlerr.New(stlerr.CodeInvalid, "wss_reconcile", string(id), "wireguard-wss", "invalid Link ID")
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return err
	}
	defer maintenance()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return err
	}
	defer linkRelease()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return err
	}
	op, found := snapshot.FindWSSCrashOperation(id)
	if !found {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"no durable WSS crash journal exists")
	}
	if originalRecovery {
		removed = op.Operation == "remove"
		repair = op.Operation == "ensure" && op.HadCommittedLink
	}
	wantOperation := "ensure"
	if removed {
		wantOperation = "remove"
	}
	if op.Operation != wantOperation || op.HadCommittedLink != (removed || repair) {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"WSS recovery mode does not match exact original transaction")
	}
	record, committed := snapshot.Find(id)
	if committed != (removed || repair) || (committed && record.Desired != op.Intent) {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"committed Link does not match original WSS pre-effect identity")
	}
	if removed || repair {
		if _, err := backend.WithWSSOrigin(ctx, record.WSSOrigin); err != nil ||
			op.OriginalHostNonce != record.WSSOrigin {
			return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id),
				"wireguard-wss", "original committed WSS host-object provenance does not match its journal")
		}
		if err := record.WSSFiles.VerifyLink(op.Intent); err != nil {
			return err
		}
		if repair && !slices.Equal(record.OwnedResources, op.Resources) {
			return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id),
				"wireguard-wss", "committed WSS Ensure original resource reservations changed")
		}
		// A pending operation must originate from committed owner claims.
		// A planned ResourceClaim is only a reservation until a matching
		// committed source verifies its original ownership.
		for _, claim := range op.Resources {
			if !slices.Contains(record.OwnedResources, claim) {
				return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id),
					"wireguard-wss", "WSS Remove journal includes unowned resource reservations")
			}
		}
	}
	claims, err := resourceLockClaims(op.Resources)
	if err != nil {
		return err
	}
	release, err := e.locks.Acquire(ctx, claims)
	if err != nil {
		return err
	}
	defer release()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return err
	}
	current, ok := fresh.FindWSSCrashOperation(id)
	if !ok || !sameWSSCrashOperation(current, op) {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"journal changed while acquiring resource locks")
	}
	freshRecord, exists := fresh.Find(id)
	if exists != (removed || repair) || (exists && (freshRecord.Desired != op.Intent ||
		freshRecord.WSSFiles != record.WSSFiles || freshRecord.WSSOrigin != record.WSSOrigin ||
		!slices.Equal(freshRecord.OwnedResources, record.OwnedResources))) {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"committed WSS Link changed during recovery")
	}
	impl, ok := e.backends.Get(domain.BackendWireGuardWSS)
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "wss_reconcile", string(id), "wireguard-wss",
			"WSS backend not registered; host absence cannot be proved")
	}
	verifier, ok := impl.(interface {
		CrashHostVacant(context.Context, backend.Observation) (bool, error)
	})
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "wss_reconcile", string(id), "wireguard-wss",
			"WSS backend lacks strict host vacancy readback")
	}
	original := op.Nonce
	if removed || repair {
		original = record.WSSOrigin
	}
	inspectionCtx, err := backend.WithWSSOrigin(ctx, original)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "wss_reconcile", string(id),
			"wireguard-wss", "invalid original WSS journal host-object identity")
	}
	observed, err := impl.Inspect(inspectionCtx, op.Intent)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeInspect, "wss_reconcile", string(id),
			"wireguard-wss", "cannot establish safe WSS original host resource identity", err)
	}
	// Even a read-only empty-host clearance for an EXISTING committed Link
	// must bind the original issued private-file contents. State fingerprint
	// metadata alone is not proof the files still match that issuance.
	if removed || repair {
		if e.wssRetirement == nil {
			return stlerr.New(stlerr.CodeState, "wss_reconcile", string(id),
				"wireguard-wss", "original committed WSS credential attestation unavailable")
		}
		issued, verifyErr := e.wssRetirement.CaptureIdentity(inspectionCtx, op.Intent)
		if verifyErr != nil || issued != record.WSSFiles {
			return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id),
				"wireguard-wss", "original committed WSS private issuance identity changed")
		}
	}
	if originalRecovery {
		compensator, ok := impl.(interface {
			CrashCompensateOriginal(context.Context, domain.Link, backend.Observation) error
		})
		if !ok {
			return stlerr.New(stlerr.CodeUnsupported, "wss_reconcile", string(id),
				"wireguard-wss", "backend lacks original-object attested compensation")
		}
		// All readbacks and destructive effects occur strictly under
		// canonical locks and after the immutable journal/State checks.
		if err := compensator.CrashCompensateOriginal(inspectionCtx, op.Intent, observed); err != nil {
			return stlerr.Wrap(stlerr.CodeConflict, "wss_reconcile", string(id),
				"wireguard-wss", "original WSS host cleanup unverified; retaining journal", err)
		}
		observed, err = impl.Inspect(inspectionCtx, op.Intent)
		if err != nil {
			return stlerr.Wrap(stlerr.CodeInspect, "wss_reconcile", string(id),
				"wireguard-wss", "post-compensation host inventory incomplete", err)
		}
	}
	vacant, err := verifier.CrashHostVacant(inspectionCtx, observed)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeInspect, "wss_reconcile", string(id),
			"wireguard-wss", "cannot verify complete WSS vacancy", err)
	}
	if !vacant {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"WSS resources remain or identity uncertain; preserve journal and host material")
	}
	return e.store.Update(ctx, func(s *state.Snapshot) error {
		entry, ok := s.FindWSSCrashOperation(id)
		if !ok || !sameWSSCrashOperation(entry, op) {
			return fmt.Errorf("WSS journal changed before recovery commit")
		}
		if removed {
			saved, ok := s.Find(id)
			if !ok || saved.Desired != op.Intent || saved.WSSFiles != record.WSSFiles ||
				saved.WSSOrigin != record.WSSOrigin ||
				!slices.Equal(saved.OwnedResources, record.OwnedResources) {
				return fmt.Errorf("original committed WSS Remove authority changed")
			}
			if _, exists := s.FindRemovalReceipt(id); exists {
				return fmt.Errorf("pre-existing WSS retirement authorization")
			}
			if !s.Delete(id) {
				return fmt.Errorf("failed to delete original committed WSS Link")
			}
			s.RemovalReceipts = append(s.RemovalReceipts, state.RemovalReceipt{
				LinkID: id, Backend: domain.BackendWireGuardWSS,
				LocalPublicKey: op.Intent.WireGuard.LocalPublicKey,
				WSSLink:        op.Intent, WSSFiles: saved.WSSFiles,
			})
		} else if repair {
			saved, ok := s.Find(id)
			if !ok || saved.Desired != record.Desired || saved.WSSFiles != record.WSSFiles ||
				saved.WSSOrigin != record.WSSOrigin ||
				!slices.Equal(saved.OwnedResources, record.OwnedResources) ||
				!slices.Equal(saved.OwnedResources, op.Resources) {
				return fmt.Errorf("original committed WSS Ensure authority changed")
			}
			if _, exists := s.FindRemovalReceipt(id); exists {
				return fmt.Errorf("committed Ensure overlaps retired Link identity")
			}
		} else if _, exists := s.Find(id); exists {
			return fmt.Errorf("new WSS Link was committed during vacancy reconciliation")
		}
		if !s.DeleteWSSCrashOperation(id) {
			return fmt.Errorf("WSS crash journal was not atomically consumed")
		}
		return nil
	})
}
func sameWSSCrashOperation(a, b state.WSSCrashOperation) bool {
	return a.Intent == b.Intent && a.Operation == b.Operation && a.Nonce == b.Nonce &&
		a.HadCommittedLink == b.HadCommittedLink &&
		a.OriginalHostNonce == b.OriginalHostNonce && slices.Equal(a.Resources, b.Resources)
}
