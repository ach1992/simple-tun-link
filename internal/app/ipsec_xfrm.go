package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// advanceIPsecXFRMPhase runs under canonical Engine maintenance/Link/resource
// locks. The original kernel ifindex is fsynced in state.json before the
// separate alias mutation, never inferred from a later same-name interface.
func (e *Engine) advanceIPsecXFRMPhase(ctx context.Context, p ipsec.Profile, from, to string, index int) error {
	if !state.IPsecXFRMNextPhase(from, to) {
		return fmt.Errorf("invalid XFRM phase transition")
	}
	return e.store.Update(ctx, func(s *state.Snapshot) error {
		journal, ok := s.FindIPsecXFRMOperation(p.Link.ID)
		if !ok || journal.Intent != p.Link || journal.Phase != from {
			return fmt.Errorf("XFRM staged/committed ownership changed")
		}
		pending, pendingExists := s.FindPendingIPsec(p.Link.ID)
		committed, committedExists := s.Find(p.Link.ID)
		if pendingExists == committedExists ||
			(pendingExists && pending.Link != p.Link) ||
			(committedExists && (committed.Desired != p.Link ||
				!ipsecClaimsRecordedEngine(committed.OwnedResources, p))) {
			return fmt.Errorf("XFRM owner intent not persistent")
		}
		if from == state.IPsecXFRMPrepared || from == state.IPsecXFRMIssuingCreate {
			if journal.IfIndex != 0 {
				return fmt.Errorf("pre-index XFRM evidence forged")
			}
		} else if journal.IfIndex <= 0 || index != journal.IfIndex {
			return fmt.Errorf("XFRM original ifindex does not match journal")
		}
		if to == state.IPsecXFRMIndexed && index <= 0 {
			return fmt.Errorf("cannot publish zero kernel ifindex")
		}
		if to == state.IPsecXFRMIssuingAbort && journal.IfIndex != index {
			return fmt.Errorf("XFRM abort lost original ifindex")
		}
		if from == state.IPsecXFRMPrepared && to == state.IPsecXFRMIssuingAbort && index != 0 {
			return fmt.Errorf("unexpected pre-effect XFRM abort identity")
		}
		for i := range s.IPsecXFRMOperations {
			if s.IPsecXFRMOperations[i].Intent.ID == p.Link.ID {
				s.IPsecXFRMOperations[i].Phase = to
				if to == state.IPsecXFRMIndexed {
					s.IPsecXFRMOperations[i].IfIndex = index
				}
				return nil
			}
		}
		return fmt.Errorf("XFRM journal disappeared")
	})
}

// ReconcileIPsecXFRM safely aborts an incomplete owned XFRM creation.
// It is explicit (never status/doctor/restore) and does not regenerate keys.
// A crash in the unidentifiable kernel-create/ifindex-journal window is
// fail-closed: do not delete or adopt any matching but unproven interface.
func (e *Engine) ReconcileIPsecXFRM(ctx context.Context, id domain.LinkID) error {
	if e == nil || ctx == nil || id.Validate() != nil {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_xfrm_reconcile", string(id), "ipsec", "invalid exact XFRM reconcile identity")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return fmt.Errorf("XFRM reconciliation maintenance guard unavailable")
	}
	defer release()
	unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return fmt.Errorf("XFRM reconcile Link lock unavailable")
	}
	defer unlock()
	snap, err := e.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("cannot inspect durable XFRM identity")
	}
	journal, ok := snap.FindIPsecXFRMOperation(id)
	if !ok {
		return fmt.Errorf("no durable IPsec XFRM recovery intent")
	}
	p, err := ipsec.NewProfile(journal.Intent)
	if err != nil {
		return fmt.Errorf("invalid persisted XFRM identity")
	}
	resources, err := resourceLockClaims(p.ResourceClaims())
	if err != nil {
		return fmt.Errorf("invalid XFRM recovery resource locks")
	}
	releaseResources, err := e.locks.Acquire(ctx, resources)
	if err != nil {
		return fmt.Errorf("XFRM reconcile resource lock unavailable")
	}
	defer releaseResources()
	snap, err = e.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("cannot recheck XFRM journal")
	}
	fresh, ok := snap.FindIPsecXFRMOperation(id)
	if !ok || fresh != journal {
		return fmt.Errorf("XFRM journal changed while acquiring locks")
	}
	// No VICI write may have been issued for this abort path. A prepared
	// journal is a durable negative capability: no sensitive operation yet.
	if staged, exists := snap.FindPendingIPsec(id); exists {
		vici, has := snap.FindIPsecVICIOperation(id)
		if staged.Link != p.Link || !has || vici.Intent.Link != p.Link || vici.Phase != state.IPsecVICIPrepared {
			return fmt.Errorf("XFRM cannot be aborted after VICI issuing began")
		}
	} else {
		rec, exists := snap.Find(id)
		vici, has := snap.FindIPsecReapplyOperation(id)
		if !exists || rec.Desired != p.Link || !ipsecClaimsRecordedEngine(rec.OwnedResources, p) ||
			!has || vici.Phase != state.IPsecVICIPrepared || vici.Intent != p.Link {
			return fmt.Errorf("committed XFRM reapply cannot be aborted after VICI issuing")
		}
	}
	impl, present := e.backends.Get(domain.BackendIPsec)
	backend, ok := impl.(*ipsec.OperationalBackend)
	if !present || !ok {
		return fmt.Errorf("operational IPsec admission unavailable for XFRM reconciliation")
	}
	if err := backend.CheckAdmission(ctx); err != nil {
		return fmt.Errorf("native daemon admission not verified")
	}
	if err := backend.AbortJournalledDevice(ctx, p,
		ipsec.DeviceCheckpoint{Phase: journal.Phase, IfIndex: journal.IfIndex},
		func(from, to string, index int) error { return e.advanceIPsecXFRMPhase(ctx, p, from, to, index) }); err != nil {
		return err
	}
	// Complete the abort only after proving kernel vacancy, while retaining
	// the original protected PSK and staged/committed public Link for retry.
	if err := e.store.Update(ctx, func(s *state.Snapshot) error {
		current, exists := s.FindIPsecXFRMOperation(id)
		if !exists || current.Intent != p.Link || current.Nonce != journal.Nonce ||
			current.IfIndex != journal.IfIndex ||
			(current.Phase != journal.Phase && current.Phase != state.IPsecXFRMIssuingAbort) {
			return fmt.Errorf("XFRM journal changed during explicit abort")
		}
		if !s.DeleteIPsecXFRMOperation(id) {
			return fmt.Errorf("cannot clear XFRM abort journal")
		}
		if _, pending := s.FindPendingIPsec(id); pending {
			vici, exists := s.FindIPsecVICIOperation(id)
			if !exists || vici.Phase != state.IPsecVICIPrepared {
				return fmt.Errorf("pending VICI issuance changed")
			}
			for i := range s.IPsecVICIOperations {
				if s.IPsecVICIOperations[i].Intent.Link.ID == id {
					s.IPsecVICIOperations = append(s.IPsecVICIOperations[:i], s.IPsecVICIOperations[i+1:]...)
					break
				}
			}
		} else {
			vici, exists := s.FindIPsecReapplyOperation(id)
			if !exists || vici.Phase != state.IPsecVICIPrepared {
				return fmt.Errorf("reapply VICI issuance changed")
			}
			s.DeleteIPsecReapplyOperation(id)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("XFRM kernel removed but durable recovery clearance is uncertain")
	}
	return nil
}
