package quichelper

import (
	"context"
	"fmt"
	"reflect"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// VerifyRecoveryHostAbsent accepts only an exact current managed journal or
// its canonical abandonment receipt. A different trusted whole-host kernel
// lifetime and complete current vacancy are required. It performs no host or
// material mutation and grants no adoption or restart authority.
func (h *Host) VerifyRecoveryHostAbsent(ctx context.Context, op state.QUICCrashOperation) error {
	if h == nil || ctx == nil || op.Managed == nil || op.Validate() != nil || op.ValidateManaged() != nil ||
		!hostidentity.ValidBootID(op.Managed.KernelBootID) || op.Managed.KernelBootSource != hostidentity.VerifiedHostBootSourceV1 {
		return fmt.Errorf("managed QUIC recovery requires an original trusted operation")
	}
	snapshot, err := h.store.Load(ctx)
	if err != nil {
		return err
	}
	current, pending := snapshot.FindQUICCrashOperation(op.Managed.Intent.ID)
	admitted := pending && reflect.DeepEqual(current, op)
	if !admitted {
		receipt, ok := snapshot.FindQUICAbandonmentReceipt(op.Managed.Intent.ID)
		admitted = ok && reflect.DeepEqual(receipt.Operation, op) && receipt.Validate() == nil
	}
	if !admitted {
		return fmt.Errorf("managed QUIC recovery operation is not the canonical pending or abandoned record")
	}
	origin := op.Nonce
	if op.Managed.HadCommittedLink {
		origin = op.Managed.OriginalGeneration.OriginNonce
		ctx = core.WithQUICGeneration(ctx, op.Managed.OriginalGeneration)
	}
	return h.verifyVacantHost(ctx, op.Managed.Intent, origin, op.Managed.KernelBootID)
}
