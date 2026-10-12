package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// RetireIPsecCredential is an explicit, idempotent retry ONLY for a key
// whose Link was already durably removed with an exact non-secret digest
// receipt. It can never remove keys for active, staged or unrecorded Links.
func (e *Engine) RetireIPsecCredential(ctx context.Context, id domain.LinkID) error {
	if e == nil || ctx == nil || id.Validate() != nil {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_retire", string(id), "ipsec", "invalid protected retirement request")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_retire", string(id), "ipsec", "maintenance guard unavailable")
	}
	defer release()
	unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_retire", string(id), "ipsec", "Link lock unavailable")
	}
	defer unlock()
	return e.retireIPsecCredentialLocked(ctx, id)
}

// Caller already holds maintenance and exact Link lock.
func (e *Engine) retireIPsecCredentialLocked(ctx context.Context, id domain.LinkID) error {
	snap, err := e.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("cannot load IPsec retirement receipt state")
	}
	receipt, has := snap.FindIPsecRemovalReceipt(id)
	if !has {
		return fmt.Errorf("no durable IPsec removal authorizes credential deletion")
	}
	if _, active := snap.Find(id); active {
		return fmt.Errorf("IPsec Link still committed; key retirement forbidden")
	}
	if _, pending := snap.FindPendingIPsec(id); pending {
		return fmt.Errorf("protected IPsec staging still reserves Link")
	}
	if _, journal := snap.FindIPsecVICIOperation(id); journal {
		return fmt.Errorf("interrupted IPsec activation still holds Link")
	}
	if _, journal := snap.FindIPsecReapplyOperation(id); journal {
		return fmt.Errorf("interrupted IPsec reapply still holds Link")
	}
	if receipt.Retired {
		return nil
	}
	implementation, registered := e.backends.Get(domain.BackendIPsec)
	if !registered {
		return fmt.Errorf("protected IPsec backend unavailable for exact key retirement")
	}
	retire, ok := implementation.(interface {
		RetireCredential(domain.LinkID, string) error
	})
	if !ok {
		return fmt.Errorf("backend has no receipt-bound IPsec key retirement")
	}
	if err := retire.RetireCredential(id, receipt.PSKSHA256); err != nil {
		return fmt.Errorf("IPsec key retirement unconfirmed; protected credential retained for exact reconciliation")
	}
	if err := e.store.Update(ctx, func(s *state.Snapshot) error {
		fresh, present := s.FindIPsecRemovalReceipt(id)
		if !present || fresh != receipt {
			return fmt.Errorf("retirement receipt changed before state finalization")
		}
		if _, active := s.Find(id); active {
			return fmt.Errorf("IPsec Link reappeared during credential retirement")
		}
		for i := range s.IPsecRemovalReceipts {
			if s.IPsecRemovalReceipts[i].LinkID == id {
				s.IPsecRemovalReceipts[i].Retired = true
				return nil
			}
		}
		return fmt.Errorf("IPsec retirement receipt disappeared")
	}); err != nil {
		return fmt.Errorf("protected IPsec key was removed but durable retired marker is not confirmed")
	}
	return nil
}
