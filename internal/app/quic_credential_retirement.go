package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

type QUICRetirementStore interface {
	RetireAfterRemove(context.Context, domain.Link, state.QUICGeneration) error
	VerifyAbsent(context.Context, domain.Link, state.QUICGeneration) error
}

func (e *Engine) SetQUICRetirementStore(store QUICRetirementStore) { e.quicRetirement = store }

// RetireQUICCredential consumes only an exact successful-Remove receipt. It
// is deliberately outside Remove rollback, and repeat calls are read-only
// after the receipt was marked retired.
func (e *Engine) RetireQUICCredential(ctx context.Context, id domain.LinkID) error {
	if ctx == nil || id.Validate() != nil || e.quicRetirement == nil {
		return fmt.Errorf("managed QUIC retirement unavailable")
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return err
	}
	defer maintenance()
	linkLockRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return err
	}
	defer linkLockRelease()
	return e.retireQUICCredentialLocked(ctx, id)
}

func (e *Engine) retireQUICCredentialLocked(ctx context.Context, id domain.LinkID) error {
	if e.quicRetirement == nil {
		return fmt.Errorf("managed QUIC retirement unavailable")
	}
	publication, ok := e.store.(interface {
		HasCommittedState(context.Context) (bool, error)
	})
	if !ok {
		return fmt.Errorf("committed QUIC receipt publication unavailable")
	}
	present, err := publication.HasCommittedState(ctx)
	if err != nil || !present {
		return fmt.Errorf("committed QUIC receipt unavailable")
	}
	s, err := e.store.Load(ctx)
	if err != nil {
		return err
	}
	r, ok := s.FindRemovalReceipt(id)
	if !ok || r.Backend != domain.BackendWireGuardQUIC || r.QUICLink.ID != id || r.QUICGeneration.Validate(r.QUICLink) != nil || !state.ValidQUICOriginalTerminationProof(r.QUICOriginalTermination) {
		return fmt.Errorf("exact QUIC original termination receipt required")
	}
	path, err := composition.Build(r.QUICLink, composition.CarrierForLink(r.QUICLink))
	if err != nil {
		return err
	}
	provider, err := composition.WireGuardProviderClaims(id, r.QUICLink.Addresses.Local, r.QUICLink.WireGuard)
	if err != nil {
		return err
	}
	claims, err := resourceLockClaims(append(provider, path.CarrierClaims()...))
	if err != nil {
		return err
	}
	release, err := e.locks.Acquire(ctx, claims)
	if err != nil {
		return err
	}
	defer release()
	s, err = e.store.Load(ctx)
	if err != nil {
		return err
	}
	current, ok := s.FindRemovalReceipt(id)
	if !ok || current != r {
		return fmt.Errorf("QUIC retirement receipt changed")
	}
	if _, live := s.Find(id); live {
		return fmt.Errorf("QUIC Link is still committed")
	}
	if _, pending := s.FindQUICCrashOperation(id); pending {
		return fmt.Errorf("QUIC journal still reserves original material")
	}
	if _, pending := s.FindPendingSender(id); pending {
		return fmt.Errorf("QUIC sender still owns material")
	}
	if r.Retired {
		return e.quicRetirement.VerifyAbsent(ctx, r.QUICLink, r.QUICGeneration)
	}
	if err := e.quicRetirement.RetireAfterRemove(ctx, r.QUICLink, r.QUICGeneration); err != nil {
		return fmt.Errorf("QUIC protected credential retirement incomplete: %w", err)
	}
	return e.store.Update(ctx, func(s *state.Snapshot) error {
		if _, live := s.Find(id); live {
			return fmt.Errorf("QUIC Link reappeared during retirement")
		}
		if _, pending := s.FindQUICCrashOperation(id); pending {
			return fmt.Errorf("QUIC journal reappeared during retirement")
		}
		current, ok := s.FindRemovalReceipt(id)
		if !ok || current != r {
			return fmt.Errorf("QUIC receipt changed during retirement")
		}
		for i := range s.RemovalReceipts {
			if s.RemovalReceipts[i].LinkID == id {
				s.RemovalReceipts[i].Retired = true
				return nil
			}
		}
		return fmt.Errorf("QUIC receipt vanished")
	})
}
