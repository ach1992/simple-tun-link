package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// RetireWSSCredential is the explicit idempotent recovery path after a
// committed WSS Remove whose protected file cleanup was interrupted.
func (e *Engine) RetireWSSCredential(ctx context.Context, id domain.LinkID) error {
	if id.Validate() != nil {
		return stlerr.New(stlerr.CodeInvalid, "wss_retire", string(id), "", "invalid WSS receipt Link ID")
	}
	maintenance, err := e.acquireMaintenance(ctx)
	if err != nil {
		return err
	}
	defer maintenance()
	release, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return err
	}
	defer release()
	return e.retireWSSCredentialLocked(ctx, id)
}

// This internal phase MUST execute with the Engine's maintenance and exact
// Link lock already held. The WSS removal receipt was durably written in the
// very same state commit as deleting its live desired Link record.
func (e *Engine) retireWSSCredentialLocked(ctx context.Context, id domain.LinkID) error {
	if e.wssRetirement == nil {
		return stlerr.New(stlerr.CodeState, "wss_retire", string(id), "wireguard-wss",
			"no protected WSS credential retirement backend is configured")
	}
	published, ok := e.store.(interface {
		HasCommittedState(context.Context) (bool, error)
	})
	if !ok {
		return fmt.Errorf("cannot prove a committed WSS removal snapshot")
	}
	present, err := published.HasCommittedState(ctx)
	if err != nil || !present {
		return fmt.Errorf("durable State unavailable; preserve WSS credentials")
	}
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return err
	}
	if _, exists := snapshot.Find(id); exists {
		return fmt.Errorf("WSS Link still has committed desired State")
	}
	if _, pending := snapshot.FindPendingSender(id); pending {
		return fmt.Errorf("pending sender still references WSS Link")
	}
	receipt, ok := snapshot.FindRemovalReceipt(id)
	if !ok || receipt.Backend != domain.BackendWireGuardWSS ||
		receipt.LocalPublicKey == "" || receipt.WSSLink.Validate() != nil ||
		receipt.WSSLink.ID != id || receipt.WSSLink.Backend != receipt.Backend ||
		receipt.WSSLink.WireGuard.LocalPublicKey != receipt.LocalPublicKey {
		return fmt.Errorf("no exact WSS removal authorization in committed State")
	}
	identity := receipt.WSSLink
	if receipt.Retired {
		// Retry is read-only: an already-consumed receipt never grants
		// permission to delete a newly created file using the same Link ID.
		if err := e.wssRetirement.VerifyAbsent(ctx, identity); err != nil {
			return fmt.Errorf("retired WSS Link has new or uncertain resources: %w", err)
		}
		return nil
	}
	if err := e.wssRetirement.RetireAfterRemove(ctx, identity); err != nil {
		return fmt.Errorf("WSS post-Remove credentials are not confirmed retired: %w", err)
	}
	if err := e.store.Update(ctx, func(s *state.Snapshot) error {
		if _, exists := s.Find(id); exists {
			return fmt.Errorf("WSS Link reappeared")
		}
		newReceipt, exists := s.FindRemovalReceipt(id)
		if !exists || newReceipt != receipt {
			return fmt.Errorf("WSS receipt changed while retiring credentials")
		}
		for i := range s.RemovalReceipts {
			if s.RemovalReceipts[i].LinkID == id {
				s.RemovalReceipts[i].Retired = true
				return nil
			}
		}
		return fmt.Errorf("WSS credential receipt vanished")
	}); err != nil {
		return fmt.Errorf("WSS protected credentials retired but receipt durability uncertain: %w", err)
	}
	return nil
}
