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
	err := e.store.Update(ctx, func(s *state.Snapshot) error {
		if _, exists := s.FindWSSCrashOperation(request.Link.ID); exists {
			return fmt.Errorf("existing WSS crash journal requires reconciliation")
		}
		previous, exists := s.Find(request.Link.ID)
		if exists != op.HadCommittedLink || (exists && previous.Desired != prior.Desired) {
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
	if err := id.Validate(); err != nil {
		return stlerr.New(stlerr.CodeInvalid, "wss_reconcile", string(id), "wireguard-wss", "invalid Link ID")
	}
	maintenanceRelease, err := e.acquireMaintenance(ctx)
	if err != nil {
		return err
	}
	defer maintenanceRelease()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return err
	}
	defer linkRelease()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return err
	}
	op, ok := snapshot.FindWSSCrashOperation(id)
	if !ok {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"no outstanding WSS crash journal exists")
	}
	if op.Operation != "ensure" || op.HadCommittedLink {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"committed-Link or Remove crash requires separate identity-attested recovery")
	}
	if _, committed := snapshot.Find(id); committed {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"WSS Link has committed State; cannot treat as vacant precommit attempt")
	}
	locks, err := resourceLockClaims(op.Resources)
	if err != nil {
		return err
	}
	release, err := e.locks.Acquire(ctx, locks)
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
			"WSS crash journal changed while acquiring resource locks")
	}
	if _, committed := fresh.Find(id); committed {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"Link became committed while inspecting pre-effect recovery")
	}
	impl, ok := e.backends.Get(domain.BackendWireGuardWSS)
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "wss_reconcile", string(id), "wireguard-wss",
			"WSS backend is unavailable; cannot prove host vacancy")
	}
	verifier, ok := impl.(interface {
		CrashHostVacant(context.Context, backend.Observation) (bool, error)
	})
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "wss_reconcile", string(id), "wireguard-wss",
			"WSS backend lacks independent host-vacancy attestation")
	}
	observed, err := impl.Inspect(ctx, op.Intent)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeInspect, "wss_reconcile", string(id),
			"wireguard-wss", "cannot prove WSS host inventory", err)
	}
	vacant, err := verifier.CrashHostVacant(ctx, observed)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeInspect, "wss_reconcile", string(id),
			"wireguard-wss", "WSS host vacancy proof incomplete", err)
	}
	if !vacant {
		return stlerr.New(stlerr.CodeConflict, "wss_reconcile", string(id), "wireguard-wss",
			"WSS host resources may remain; keeping durable crash journal; no deletion or adoption")
	}
	return e.store.Update(ctx, func(s *state.Snapshot) error {
		entry, exists := s.FindWSSCrashOperation(id)
		if !exists || !sameWSSCrashOperation(entry, op) {
			return fmt.Errorf("WSS transaction changed before vacancy clearance")
		}
		if _, committed := s.Find(id); committed {
			return fmt.Errorf("WSS Link committed while reconciling vacancy")
		}
		if !s.DeleteWSSCrashOperation(id) {
			return fmt.Errorf("WSS crash journal disappearance not committed")
		}
		return nil
	})
}
func sameWSSCrashOperation(a, b state.WSSCrashOperation) bool {
	return a.Intent == b.Intent && a.Operation == b.Operation && a.Nonce == b.Nonce &&
		a.HadCommittedLink == b.HadCommittedLink && slices.Equal(a.Resources, b.Resources)
}
