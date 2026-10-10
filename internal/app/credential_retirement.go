package app

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// CredentialRetirementStore never blindly removes a protected key. Its
// identity-bound unlink is called only after Engine proves durable absence
// and delegated read-only host inspection proves no surviving owner resources.
type CredentialRetirementStore interface {
	RetireExact(domain.LinkID, string) (bool, error)
}
type CredentialRetirementGuard interface {
	VerifyUnused(context.Context, domain.LinkID, string) error
}

// RetireWireGuardCredential is the explicit final stage AFTER successful
// canonical Link removal; it is not part of Remove rollback or state commit.
// All STL operations for this Link are serialized under the same maintenance
// and per-Link lock as Ensure, Remove and restored state.
func (e *Engine) RetireWireGuardCredential(ctx context.Context, id domain.LinkID, expectedPublic string,
	store CredentialRetirementStore, guard CredentialRetirementGuard) (bool, error) {
	if id.Validate() != nil || expectedPublic == "" || store == nil || guard == nil {
		return false, stlerr.New(stlerr.CodeInvalid, "credential_retire", string(id), "", "invalid confirmed WireGuard retirement request")
	}
	maintenanceRelease, err := e.acquireMaintenance(ctx)
	if err != nil {
		return false, stlerr.Wrap(stlerr.CodeState, "credential_retire", string(id), "", "maintenance gate unavailable; no retirement attempted", err)
	}
	defer maintenanceRelease()
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return false, stlerr.Wrap(stlerr.CodeState, "credential_retire", string(id), "", "cannot lock Link for credential retirement", err)
	}
	defer linkRelease()
	// A missing/unmounted/corrupted state file is NOT evidence that a Link
	// was durably removed. Retirement requires a previously published,
	// regular state file (FileStore.HasCommittedState) before checking its
	// contents. Uncommitted orphan keys require separate reconciliation.
	published, ok := e.store.(interface {
		HasCommittedState(context.Context) (bool, error)
	})
	if !ok {
		return false, stlerr.New(stlerr.CodeState, "credential_retire", string(id), "", "cannot prove a committed desired-state snapshot; preserve private key")
	}
	present, err := published.HasCommittedState(ctx)
	if err != nil || !present {
		return false, stlerr.New(stlerr.CodeState, "credential_retire", string(id), "", "committed state file unavailable or unproven; preserve private key")
	}
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return false, stlerr.Wrap(stlerr.CodeState, "credential_retire", string(id), "", "cannot inspect committed desired state", err)
	}
	if _, exists := snapshot.Find(id); exists {
		return false, stlerr.New(stlerr.CodeConflict, "credential_retire", string(id), "", "Link still has committed desired state; remove and verify the Link before retiring its private key")
	}
	if err = guard.VerifyUnused(ctx, id, expectedPublic); err != nil {
		return false, stlerr.Wrap(stlerr.CodeConflict, "credential_retire", string(id), "", "host resource absence cannot be proved; preserve credential", err)
	}
	retired, err := store.RetireExact(id, expectedPublic)
	if err != nil {
		return false, stlerr.Wrap(stlerr.CodeState, "credential_retire", string(id), "", fmt.Sprintf("protected credential retirement failed or is uncertain for Link %s", id), err)
	}
	return retired, nil
}
