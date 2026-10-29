package app

import (
	"context"
	"errors"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// QUICIngressOriginalPublisher is the Linux adapter boundary; the Engine
// provides the immutable journal-derived identity, never caller-substituted
// guard names, rules or ingress ports.
type QUICIngressOriginalPublisher interface {
	PublishOriginalQUICWGIngress(context.Context, domain.LinkID, string, uint16) error
}

// StageQUICCrashIngressGuard is the first, still non-runnable QUIC host
// effect. It uses the existing immutable State v4 journal, canonical Engine
// maintenance/Link/resource locks, exact protected create-time generation
// receipt and pinned official binary before an exclusive nft CREATE.
//
// Its successful result witnesses only the NEW guard creation in this call.
// An interrupted call retains the journal and any possible nft table in
// quarantine. It does not commit a Link, configure kernel WG, start Hysteria,
// adopt a preexisting guard or grant subsequent destructive permissions.
func (e *Engine) StageQUICCrashIngressGuard(ctx context.Context, id domain.LinkID, host QUICIngressOriginalPublisher) error {
	if host == nil {
		return stlerr.New(stlerr.CodeInvalid, "quic_stage_crash_ingress", string(id), "quic", "original QUIC ingress requires an admitted Linux host")
	}
	return e.stageQUICCrashIngressGuard(ctx, id,
		func(root string, plan quic.Plan, port uint16, op state.QUICCrashOperation) error {
			actual, err := quic.InspectJournalGeneration(root, plan, port, op.ExecutablePath,
				op.Nonce, quicExpectedMaterialIdentity(op))
			if err != nil || actual != quicExpectedMaterialIdentity(op) {
				return errors.New("original protected QUIC generation unverified")
			}
			return nil
		},
		host.PublishOriginalQUICWGIngress)
}

// Test seam only: production always re-attests the exact journal receipt,
// credentials/config and executable and uses the real bounded host reader.
func (e *Engine) stageQUICCrashIngressGuard(ctx context.Context, id domain.LinkID,
	inspect func(string, quic.Plan, uint16, state.QUICCrashOperation) error,
	publish func(context.Context, domain.LinkID, string, uint16) error) error {
	const action = "quic_stage_crash_ingress"
	if inspect == nil || publish == nil {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic",
			"original QUIC ingress needs material and host ownership gates")
	}
	return e.withQUICCrashMaterialLocks(ctx, id, action,
		func(root string, plan quic.Plan, port uint16, op state.QUICCrashOperation) error {
			if err := inspect(root, plan, port, op); err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original material or executable generation unverified; preserve journal")
			}
			if err := publish(ctx, id, op.Nonce, op.WireGuard.ListenPort); err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original ingress creation failed or uncertain; preserve journal and host protection")
			}
			return nil
		})
}
