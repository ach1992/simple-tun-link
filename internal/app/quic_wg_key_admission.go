package app

import (
	"context"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// WithQUICCrashWireGuardKeyAdmission gates only original private native WG
// credential staging. The caller-provided derived public key must equal the
// immutable journal's local public key under canonical maintenance, Link and
// resource locks. The callback is an admission scope, not a host-effect or
// ownership witness. The fixed source-only key stager is in quicwgkey.
func (e *Engine) WithQUICCrashWireGuardKeyAdmission(ctx context.Context, id domain.LinkID,
	derivedPublic string, stage func(root, journalPublic string) error) error {
	const action = "quic_stage_crash_wg_key"
	if stage == nil || derivedPublic == "" {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic",
			"QUIC private WireGuard key requires a derived public identity and stager")
	}
	return e.withQUICCrashMaterialLocks(ctx, id, action,
		func(root string, _ quic.Plan, _ uint16, op state.QUICCrashOperation) error {
			if derivedPublic != op.WireGuard.LocalPublicKey {
				return stlerr.New(stlerr.CodeConflict, action, string(id), "quic",
					"private WireGuard key differs from immutable QUIC journal public identity")
			}
			if ctx.Err() != nil || stage(root, op.WireGuard.LocalPublicKey) != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC private WireGuard credential staging failed or uncertain; preserve journal")
			}
			return nil
		})
}

// WithQUICCrashWireGuardKeyObservation checks the same immutable journal
// generation and locks for a read-only private credential reader. The callback
// cannot grant original-file identity, kernel ownership or recovery authority.
func (e *Engine) WithQUICCrashWireGuardKeyObservation(ctx context.Context, id domain.LinkID,
	inspect func(root, journalPublic string) error) error {
	const action = "quic_inspect_crash_wg_key"
	if inspect == nil {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic",
			"QUIC private WireGuard key observer is required")
	}
	return e.withQUICCrashMaterialLocks(ctx, id, action,
		func(root string, _ quic.Plan, _ uint16, op state.QUICCrashOperation) error {
			if ctx.Err() != nil || inspect(root, op.WireGuard.LocalPublicKey) != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"journal-bound QUIC private WireGuard key unavailable or unverified")
			}
			return nil
		})
}
