package app

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// ReconcileQUICAfterKernelExtinction is an explicitly confirmed recovery for
// NEW managed journals only. It never touches host resources. A later trusted
// whole-kernel generation, strict current vacancy and complete original
// material evidence jointly permit one atomic terminal State transition.
// Same-kernel absence and a successful unverified rollback cannot authorize it.
func (e *Engine) ReconcileQUICAfterKernelExtinction(ctx context.Context, id domain.LinkID) (Result, error) {
	result := Result{LinkID: id}
	if ctx == nil || id.Validate() != nil || e.kernelBootID == nil {
		return result, fmt.Errorf("invalid managed QUIC recovery request")
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return result, err
	}
	defer maintenance()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return result, err
	}
	defer linkRelease()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return result, err
	}
	op, ok := snapshot.FindQUICCrashOperation(id)
	if !ok || op.Managed == nil || op.Validate() != nil {
		return result, quicRecoveryError(id, "managed_attempt_required", "only an exact new managed QUIC journal can be reconciled")
	}
	prior, present := snapshot.Find(id)
	if err := quicRecoveryOwner(op, prior, present); err != nil {
		return result, err
	}
	claims, err := resourceLockClaims(op.Resources)
	if err != nil {
		return result, err
	}
	resources, err := e.locks.Acquire(ctx, claims)
	if err != nil {
		return result, err
	}
	defer resources()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return result, err
	}
	current, ok := fresh.FindQUICCrashOperation(id)
	currentOwner, currentPresent := fresh.Find(id)
	if !ok || !sameQUICOperation(current, op) || currentPresent != present || !sameQUICRecord(currentOwner, prior) {
		return result, fmt.Errorf("QUIC recovery journal or original owner changed while acquiring locks")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	boot, err := e.kernelBootID()
	if err != nil || !hostidentity.ValidBootID(boot) || boot == op.Managed.KernelBootID {
		return result, quicRecoveryError(id, "attempt_kernel_not_extinct", "a verified host kernel generation after the recorded QUIC attempt is required; journal retained")
	}
	ns, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		return result, fmt.Errorf("current QUIC recovery network namespace unavailable")
	}
	origin, materialNonce := op.Nonce, op.Nonce
	if present {
		origin, materialNonce = prior.QUICGeneration.OriginNonce, prior.QUICGeneration.MaterialNonce
		ctx = backend.WithQUICGeneration(ctx, prior.QUICGeneration)
	}
	ctx, err = backend.WithQUICOrigin(ctx, origin)
	if err != nil {
		return result, err
	}
	ctx, err = backend.WithQUICManagedOperation(ctx, op)
	if err != nil {
		return result, err
	}
	ctx, err = backend.WithQUICColdBootExtinct(ctx, id)
	if err != nil {
		return result, err
	}
	root, err := e.managedQUICRoot()
	if err != nil {
		return result, err
	}
	plan, err := quicPlanForManagedLink(op.Managed.Intent)
	if err != nil {
		return result, err
	}
	expected := quicExpectedMaterialIdentity(op)
	files, err := e.quicRecordedMaterial(ctx, root, plan, op.WireGuard.ListenPort, materialNonce, expected)
	if err != nil || files.Validate() != nil || present && files != prior.QUICGeneration.Files {
		return result, quicRecoveryError(id, "original_material_unverified", "complete original QUIC material receipt and identity are required; partial or drifted staging remains quarantined")
	}
	impl, ok := e.backends.Get(domain.BackendWireGuardQUIC)
	if !ok {
		return result, fmt.Errorf("managed QUIC backend unavailable")
	}
	reader, ok := impl.(interface {
		QUICRecoveryHostVacant(context.Context, state.QUICCrashOperation) (bool, error)
	})
	if !ok {
		return result, fmt.Errorf("managed QUIC strict recovery vacancy reader unavailable")
	}
	vacant, err := reader.QUICRecoveryHostVacant(ctx, op)
	if err != nil || !vacant {
		return result, quicRecoveryError(id, "current_resources_not_vacant", "current QUIC resources remain or vacancy is unverified; journal retained")
	}
	again, err := e.quicRecordedMaterial(ctx, root, plan, op.WireGuard.ListenPort, materialNonce, expected)
	if err != nil || again != files {
		return result, quicRecoveryError(id, "original_material_changed", "original QUIC material changed during recovery; journal retained")
	}
	publication, err := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
	if err != nil {
		return result, err
	}
	defer publication()
	currentBoot, bootErr := e.kernelBootID()
	currentNS, nsErr := os.Readlink("/proc/thread-self/ns/net")
	if bootErr != nil || currentBoot != boot || nsErr != nil || currentNS != ns {
		return result, fmt.Errorf("QUIC host generation changed before recovery publication")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	err = e.store.Update(ctx, func(s *state.Snapshot) error {
		entry, ok := s.FindQUICCrashOperation(id)
		owner, exists := s.Find(id)
		if !ok || !sameQUICOperation(entry, op) || exists != present || !sameQUICRecord(owner, prior) {
			return fmt.Errorf("QUIC recovery journal or committed owner changed before publication")
		}
		if err := quicRecoveryOwner(op, owner, exists); err != nil {
			return err
		}
		if _, ok := s.FindRemovalReceipt(id); ok {
			return fmt.Errorf("QUIC removal receipt already exists")
		}
		if _, ok := s.FindQUICAbandonmentReceipt(id); ok {
			return fmt.Errorf("QUIC abandonment receipt already exists")
		}
		if !present {
			r := state.QUICAbandonmentReceipt{Operation: op, Files: files, ReconciledKernelBootID: boot, ReconciledKernelBootSource: hostidentity.VerifiedHostBootSourceV1}
			if err := r.Validate(); err != nil {
				return err
			}
			s.QUICAbandonmentReceipts = append(s.QUICAbandonmentReceipts, r)
		} else if op.Managed.Operation == "remove" {
			if !s.Delete(id) {
				return fmt.Errorf("QUIC original owner disappeared")
			}
			s.RemovalReceipts = append(s.RemovalReceipts, state.RemovalReceipt{LinkID: id, Backend: domain.BackendWireGuardQUIC, LocalPublicKey: op.WireGuard.LocalPublicKey,
				QUICLink: op.Managed.Intent, QUICGeneration: prior.QUICGeneration, QUICOriginalTermination: state.QUICOriginalKernelGenerationExtinct})
		}
		// A committed Ensure keeps the exact original owner and credentials;
		// ordinary Restore is the sole route to a new managed host generation.
		return consumeManagedQUIC(s, op)
	})
	if err != nil {
		return result, stlerr.WithEvidence(stlerr.Wrap(stlerr.CodeState, "quic_reconcile", string(id), "wireguard-quic", "QUIC recovery publication unconfirmed; reload protected State before any further action", err), stlerr.OperationEvidence{Stage: "recovery_commit", HostMutation: "not_attempted", DesiredState: "commit_attempted", Rollback: "not_attempted"})
	}
	result.Changed, result.Removed = true, present && op.Managed.Operation == "remove"
	return result, nil
}

func quicRecoveryOwner(op state.QUICCrashOperation, r state.LinkRecord, present bool) error {
	if op.Managed == nil || present != op.Managed.HadCommittedLink {
		return fmt.Errorf("QUIC recovery committed presence differs from its journal")
	}
	if present && (r.Desired != op.Managed.Intent || r.QUICGeneration != op.Managed.OriginalGeneration || !slices.Equal(r.OwnedResources, op.Resources)) {
		return fmt.Errorf("QUIC recovery exact committed owner differs")
	}
	return nil
}

func quicRecoveryError(id domain.LinkID, reason, message string) error {
	err := stlerr.New(stlerr.CodeConflict, "quic_reconcile", string(id), "wireguard-quic", message)
	err.ReasonCode = reason
	return err
}
