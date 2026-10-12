package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// ReconcileIPsecRemove is an explicit exact-Link recovery operation, never a
// background repair. It holds canonical maintenance, Link and resource locks,
// then resumes ONLY the durable committed-Link Remove transaction.
func (e *Engine) ReconcileIPsecRemove(ctx context.Context, id domain.LinkID) (Result, error) {
	if e == nil || ctx == nil || id.Validate() != nil {
		return Result{}, stlerr.New(stlerr.CodeInvalid, "ipsec_reconcile_remove", string(id), "ipsec", "invalid Link identity")
	}
	return e.remove(ctx, id, nil, true)
}

func (e *Engine) ipsecRemovalCheckpoint(ctx context.Context, p ipsec.Profile) (ipsec.RemovalCheckpoint, error) {
	if ctx == nil {
		return ipsec.RemovalCheckpoint{}, fmt.Errorf("missing IPsec Remove context")
	}
	s, err := e.store.Load(ctx)
	if err != nil {
		return ipsec.RemovalCheckpoint{}, fmt.Errorf("IPsec Remove state unavailable")
	}
	rec, ok := s.Find(p.Link.ID)
	journal, has := s.FindIPsecRemoveOperation(p.Link.ID)
	if !ok || !has || rec.Desired != p.Link || journal.Intent != p.Link ||
		!ipsecClaimsRecordedEngine(rec.OwnedResources, p) {
		return ipsec.RemovalCheckpoint{}, fmt.Errorf("no exact committed IPsec Remove authorization")
	}
	return ipsec.RemovalCheckpoint{Phase: journal.Phase, IfIndex: journal.IfIndex}, nil
}

func ipsecClaimsRecordedEngine(owned []domain.ResourceClaim, p ipsec.Profile) bool {
	for _, required := range p.ResourceClaims() {
		matched := false
		for _, claim := range owned {
			if claim.Canonical() == required.Canonical() {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (e *Engine) advanceIPsecRemovePhase(ctx context.Context, p ipsec.Profile, from, to string) error {
	if !state.IPsecRemoveNextPhase(from, to) {
		return fmt.Errorf("non-adjacent IPsec Remove transaction")
	}
	return e.store.Update(ctx, func(s *state.Snapshot) error {
		committed, ok := s.Find(p.Link.ID)
		journal, has := s.FindIPsecRemoveOperation(p.Link.ID)
		if !ok || !has || committed.Desired != p.Link || journal.Intent != p.Link ||
			!ipsecClaimsRecordedEngine(committed.OwnedResources, p) || journal.Phase != from {
			return fmt.Errorf("IPsec committed Remove identity or phase changed")
		}
		for i := range s.IPsecRemoveOperations {
			if s.IPsecRemoveOperations[i].Intent.ID == p.Link.ID {
				s.IPsecRemoveOperations[i].Phase = to
				return nil
			}
		}
		return fmt.Errorf("IPsec Remove checkpoint disappeared")
	})
}
