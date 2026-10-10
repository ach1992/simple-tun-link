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

// advanceIPsecVICIPhase is a pure state-journal transition; no production
// caller currently advances beyond prepared. Only the test simulator uses
// this method until an independently proven no-clobber ownership protocol
// exists. It enforces exact intent binding and allowed adjacent phases, but
// does not contact VICI, modify XFRM, or confer any daemon ownership.
func (e *Engine) advanceIPsecVICIPhase(ctx context.Context, p ipsec.Profile, from, to string) error {
	// Even internal callers may not skip phases to manufacture evidence
	// of a daemon call that was never actually issued/observed.
	valid := (from == state.IPsecVICIPrepared && to == state.IPsecVICIIssuingShared) ||
		(from == state.IPsecVICIIssuingShared && to == state.IPsecVICISharedObserved) ||
		(from == state.IPsecVICISharedObserved && to == state.IPsecVICIIssuingConnection) ||
		(from == state.IPsecVICIIssuingConnection && to == state.IPsecVICIConnectionSeen)
	if !valid {
		return fmt.Errorf("invalid IPsec VICI journal phase transition")
	}
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
