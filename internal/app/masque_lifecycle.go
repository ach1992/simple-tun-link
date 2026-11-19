package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// prepareMASQUEOperation runs after the canonical Engine's maintenance,
// Link and resource locks, fresh host inventory and backend Validate. Every
// future host service/TUN mutation must be preceded by this durable
// credential-free pre-effect reservation. Unknown process/commit outcomes
// retain it, blocking accidental adoption or unsafe automatic retry.
func (e *Engine) prepareMASQUEOperation(ctx context.Context, request backend.Request,
	prior state.LinkRecord, resources []domain.ResourceClaim) (state.MASQUEOperation, error) {
	if request.Link.Backend != domain.BackendMASQUE ||
		(request.Operation != backend.OperationEnsure && request.Operation != backend.OperationRemove) {
		return state.MASQUEOperation{}, errors.New("MASQUE pre-effect operation invalid")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return state.MASQUEOperation{}, errors.New("MASQUE origin nonce unavailable")
	}
	op := state.MASQUEOperation{
		Intent: request.Link, Operation: string(request.Operation),
		HadCommittedLink: prior.Desired.ID == request.Link.ID,
		Nonce:            hex.EncodeToString(random[:]), Resources: slices.Clone(resources),
	}
	// Resource claims are already sorted/validated by the one Engine.
	if err := e.store.Update(ctx, func(snapshot *state.Snapshot) error {
		if _, blocked := snapshot.FindMASQUEOperation(request.Link.ID); blocked {
			return errors.New("unresolved MASQUE operation already reserves this Link")
		}
		if _, retired := snapshot.FindMASQUERemovalReceipt(request.Link.ID); retired {
			return errors.New("MASQUE removed Link identity cannot be reused")
		}
		existing, found := snapshot.Find(request.Link.ID)
		if found != op.HadCommittedLink {
			return errors.New("MASQUE original State presence changed during preparation")
		}
		if found && (existing.Desired != prior.Desired ||
			!slices.Equal(existing.OwnedResources, prior.OwnedResources)) {
			return errors.New("MASQUE committed owner changed before preparing host effects")
		}
		if !found && request.Operation == backend.OperationRemove {
			return errors.New("MASQUE cannot remove without a committed Link")
		}
		snapshot.MASQUEOperations = append(snapshot.MASQUEOperations, op)
		return nil
	}); err != nil {
		return state.MASQUEOperation{}, fmt.Errorf("MASQUE pre-effect journal publication failed: %w", err)
	}
	return op, nil
}
