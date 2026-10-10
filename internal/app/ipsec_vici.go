package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// IPsecScopedVICIWriter exposes ONLY the bounded per-object operations
// required before XFRM interface installation. No unload, global operation,
// wildcard, SA termination or credential retirement is present in this seam.
type IPsecScopedVICIWriter interface {
	LoadShared(context.Context, ipsec.Profile, *ipsec.PSK) error
	LoadConnection(context.Context, ipsec.Profile) error
}

// PrepareIPsecVICI durably records intent BEFORE any daemon effect. This
// marker is intentionally not an ownership token and is never sufficient
// to resume an interrupted VICI call or to unload matching daemon names.
// All checks and state writes happen under canonical Engine locks.
func (e *Engine) PrepareIPsecVICI(ctx context.Context, id domain.LinkID, keys IPsecProtectedKeyReader, reader IPsecVICIInventory, xfrm IPsecXFRMVacancy) error {
	const op = "ipsec_vici_prepare"
	return e.withIPsecActivationVacancy(ctx, id, keys, reader, xfrm, func(p ipsec.Profile, _ *ipsec.PSK) error {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "unable to allocate a private transaction identity")
		}
		if err := e.store.Update(ctx, func(s *state.Snapshot) error {
			pending, exists := s.FindPendingIPsec(id)
			if !exists || pending.Link != p.Link {
				return fmt.Errorf("IPsec intent changed")
			}
			if current, exists := s.FindIPsecVICIOperation(id); exists {
				if current.Intent != pending || current.Phase != state.IPsecVICIPrepared {
					return fmt.Errorf("IPsec daemon transaction requires explicit reconciliation")
				}
				return nil // exact replay BEFORE any daemon effect
			}
			s.IPsecVICIOperations = append(s.IPsecVICIOperations, state.IPsecVICIOperation{
				Intent: pending, Nonce: hex.EncodeToString(nonce[:]), Phase: state.IPsecVICIPrepared,
			})
			return nil
		}); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "IPsec daemon preparation not proven durable; no daemon effect attempted")
		}
		return nil
	})
}

// ApplyPreparedIPsecVICI is a deliberately isolated VICI configuration phase.
// It does NOT register an operational Link or start IKE/XFRM traffic. Each
// potentially side-effectful call is preceded by a durable ISSUING marker.
// If any call/reply/check/state update is uncertain, retain that marker and
// STOP; never retry or unload a same-name object without independent host
// ownership proof. This remains an unregistered source-only Engine path.
func (e *Engine) ApplyPreparedIPsecVICI(ctx context.Context, id domain.LinkID, keys IPsecProtectedKeyReader, reader IPsecVICIInventory, xfrm IPsecXFRMVacancy, writer IPsecScopedVICIWriter) error {
	const op = "ipsec_vici_apply"
	if writer == nil {
		return stlerr.New(stlerr.CodeInvalid, op, string(id), "ipsec", "scoped VICI writer is required")
	}
	return e.withIPsecActivationVacancy(ctx, id, keys, reader, xfrm, func(p ipsec.Profile, key *ipsec.PSK) error {
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICIPrepared, state.IPsecVICIIssuingShared); err != nil {
			return stlerr.New(stlerr.CodeConflict, op, string(id), "ipsec", "durable prepared IPsec transaction is required; no VICI call made")
		}
		if err := writer.LoadShared(ctx, p, key); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "scoped shared-key call uncertain; retain transaction journal for manual reconciliation")
		}
		view, err := reader.Inspect(ctx, p)
		if err != nil || !view.SecretNamePresent || view.ConnectionNamePresent {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "strongSwan shared-key result unverified; retain transaction journal")
		}
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICIIssuingShared, state.IPsecVICISharedObserved); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "shared-key observation not durable; no connection call made")
		}
		// Repeat immediately before connection load: an outside writer may
		// have introduced a colliding connection during the shared-key step.
		view, err = reader.Inspect(ctx, p)
		if err != nil || !view.SecretNamePresent || view.ConnectionNamePresent {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "strongSwan connection namespace changed; do not overwrite")
		}
		if err := xfrm.RequireVacant(ctx, p); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "XFRM namespace changed; do not load connection")
		}
		if err := ctx.Err(); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "IPsec VICI transaction interrupted before connection call")
		}
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICISharedObserved, state.IPsecVICIIssuingConnection); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "connection issue journal not proven durable; no connection call made")
		}
		if err := writer.LoadConnection(ctx, p); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "scoped connection call uncertain; retain transaction journal")
		}
		view, err = reader.Inspect(ctx, p)
		if err != nil || !view.ConnectionNamePresent || !view.SecretNamePresent {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "strongSwan connection result unverified; retain transaction journal")
		}
		if err := e.advanceIPsecVICIPhase(ctx, p, state.IPsecVICIIssuingConnection, state.IPsecVICIConnectionSeen); err != nil {
			return stlerr.New(stlerr.CodeState, op, string(id), "ipsec", "connection observation not durable; retain transaction journal")
		}
		// Presence is not ownership proof. XFRM, IKE negotiation, scoped
		// cleanup/reapply and canonical Link commit are separate gated work.
		return nil
	})
}

// This helper is called only from a transaction holding maintenance/Link/
// resource locks. It refuses phase skips and journal/link substitutions.
// State publication uncertainty must stop calls, not trigger best-effort
// cleanup against another administrator's possible daemon objects.
func (e *Engine) advanceIPsecVICIPhase(ctx context.Context, p ipsec.Profile, from, to string) error {
	return e.store.Update(ctx, func(s *state.Snapshot) error {
		pending, ok := s.FindPendingIPsec(p.Link.ID)
		current, exists := s.FindIPsecVICIOperation(p.Link.ID)
		if !ok || pending.Link != p.Link || !exists || current.Intent != pending || current.Phase != from {
			return fmt.Errorf("IPsec VICI transaction changed")
		}
		for i := range s.IPsecVICIOperations {
			if s.IPsecVICIOperations[i].Intent.Link.ID == p.Link.ID {
				s.IPsecVICIOperations[i].Phase = to
				return nil
			}
		}
		return fmt.Errorf("missing VICI transaction")
	})
}
