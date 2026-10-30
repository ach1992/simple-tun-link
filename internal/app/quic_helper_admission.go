package app

import (
	"context"
	"errors"
	"reflect"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// WithQUICCrashHelperAdmission is a source-only admission scope for the
// original helper's first activation. The immutable pre-effect journal and
// exact protected generation are checked under the existing maintenance,
// Link and resource locks before and after the bounded callback. The callback
// receives only the canonical root and journal-derived topology and identity.
//
// Admission success is not process-creation evidence: internal/quichelper's
// fixed production adapter must establish the original unit/process itself.
// The callback must not reacquire Engine locks. This method never consumes the
// journal, commits a Link, or grants adoption, restart or retirement authority.
func (e *Engine) WithQUICCrashHelperAdmission(ctx context.Context, id domain.LinkID,
	perform func(context.Context, string, quic.Plan, state.QUICCrashOperation) error) error {
	return e.withQUICCrashHelperAdmission(ctx, id,
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

// Only package tests replace the material inspector. The public path always
// verifies the original protected generation and officially pinned executable.
func (e *Engine) withQUICCrashHelperAdmission(ctx context.Context, id domain.LinkID,
	inspect func(string, quic.Plan, uint16, state.QUICCrashOperation) error,
	perform func(context.Context, string, quic.Plan, state.QUICCrashOperation) error) error {
	const action = "quic_admit_crash_helper"
	if inspect == nil || perform == nil {
		return stlerr.New(stlerr.CodeInvalid, action, string(id), "quic",
			"original QUIC helper needs material and process ownership gates")
	}
	return e.withQUICCrashMaterialLocks(ctx, id, action,
		func(root string, plan quic.Plan, port uint16, op state.QUICCrashOperation) error {
			if err := inspect(root, plan, port, op); err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original helper material or executable generation unverified; preserve journal")
			}
			// Resources are the journal's only reference-valued field. A
			// callback cannot change the expected record through a slice alias.
			callbackOp := op
			callbackOp.Resources = append([]domain.ResourceClaim(nil), op.Resources...)
			if err := perform(ctx, root, plan, callbackOp); err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original helper first activation failed or uncertain; preserve journal and possible process")
			}
			// A successful process callback cannot erase or rewrite its
			// pre-effect intent. Do not overwrite drift or attempt compensation.
			fresh, err := e.store.Load(ctx)
			if err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original helper journal readback uncertain; preserve journal and possible process")
			}
			latest, present := fresh.FindQUICCrashOperation(id)
			if !present || !reflect.DeepEqual(latest, op) {
				return stlerr.New(stlerr.CodeConflict, action, string(id), "quic",
					"QUIC original helper journal changed during activation; preserve remaining evidence")
			}
			if err := inspect(root, plan, port, op); err != nil || ctx.Err() != nil {
				return stlerr.New(stlerr.CodeState, action, string(id), "quic",
					"QUIC original helper protected generation changed during activation; preserve journal and possible process")
			}
			return nil
		})
}
