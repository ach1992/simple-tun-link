package app

import (
	"context"
	"errors"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// WithQUICCrashIngressAdmission is a bounded, journal-bound Engine authority
// callback for the one initial QUIC guard effect. It re-attests the exact
// protected original generation and pinned executable, then invokes perform
// while maintenance, Link and resource locks are held. The callback is not a
// publisher interface, injectable production backend, durable nft witness or
// independent permission to adopt/retire any host resource. A successful
// callback does NOT prove creation; the fixed production dispatch in
// internal/quicguard.StageOriginal performs the real CREATE and strict
// readback before returning success. No CLI invokes this source-only path.
func (e *Engine) WithQUICCrashIngressAdmission(ctx context.Context, id domain.LinkID,
	perform func(context.Context, domain.LinkID, string, domain.WireGuardOptions) error) error {
	if perform == nil {
		return stlerr.New(stlerr.CodeInvalid, "quic_admit_crash_ingress", string(id), "quic",
			"QUIC original guard admission needs a bounded effect callback")
	}
	return e.withQUICCrashIngressAdmission(ctx, id,
		func(root string, plan quic.Plan, port uint16, op state.QUICCrashOperation) error {
			expected := quicExpectedMaterialIdentity(op)
			actual, err := quic.InspectJournalGeneration(root, plan, port,
				op.ExecutablePath, op.Nonce, expected)
			if err != nil || actual != expected {
				return errors.New("original protected QUIC generation unverified")
			}
			return nil
		}, perform)
}

// Test-only seam: do not infer actual host creation from an injected callback;
// the fixed production quicguard writer independently validates post-effect nft.
func (e *Engine) withQUICCrashIngressAdmission(ctx context.Context, id domain.LinkID,
	inspect func(string, quic.Plan, uint16, state.QUICCrashOperation) error,
	perform func(context.Context, domain.LinkID, string, domain.WireGuardOptions) error) error {
	const action = "quic_admit_crash_ingress"
	if inspect == nil || perform == nil {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic",
			"original QUIC ingress needs material and host ownership gates")
	}
	return e.withQUICCrashMaterialLocks(ctx, id, action,
		func(root string, plan quic.Plan, port uint16, op state.QUICCrashOperation) error {
			if err := inspect(root, plan, port, op); err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original material or executable generation unverified; preserve journal")
			}
			if err := perform(ctx, id, op.Nonce, op.WireGuard); err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original ingress creation failed or uncertain; preserve journal and host protection")
			}
			return nil
		})
}
