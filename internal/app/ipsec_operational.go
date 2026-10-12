package app

import (
	"context"
	"github.com/ach1992/simple-tun-link/internal/state"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// ActivateStagedIPsec consumes exactly one protected Quick Link staging intent
// through the SAME Engine locks, backend plan/validate/apply, verification,
// host restore persistence and state commit as ordinary Ensure.
//
// A previously interrupted VICI transaction is never silently retried,
// even if its names now appear vacant. A failed/unknown host operation keeps
// the original public pending intent and protected PSK for reconciliation.
func (e *Engine) ActivateStagedIPsec(ctx context.Context, id domain.LinkID) (Result, error) {
	if e == nil || ctx == nil || id.Validate() != nil {
		return Result{}, stlerr.New(stlerr.CodeInvalid, "ipsec_activate", string(id), "ipsec", "valid canonical Engine, context and Link ID required")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return Result{}, stlerr.New(stlerr.CodeState, "ipsec_activate", string(id), "ipsec", "maintenance gate unavailable")
	}
	defer release()
	unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return Result{}, stlerr.New(stlerr.CodeState, "ipsec_activate", string(id), "ipsec", "Link lock unavailable")
	}
	defer unlock()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.New(stlerr.CodeState, "ipsec_activate", string(id), "ipsec", "cannot read protected public intent")
	}
	pending, present := snapshot.FindPendingIPsec(id)
	if !present {
		return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_activate", string(id), "ipsec", "no protected staged IPsec Quick Link")
	}
	if _, existing := snapshot.Find(id); existing {
		return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_activate", string(id), "ipsec", "IPsec Link already committed")
	}
	if _, journal := snapshot.FindIPsecVICIOperation(id); journal {
		return Result{}, stlerr.New(stlerr.CodeConflict, "ipsec_activate", string(id), "ipsec", "interrupted IPsec journal needs reconciliation before retry")
	}
	if _, registered := e.backends.Get(domain.BackendIPsec); !registered {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, "ipsec_activate", string(id), "ipsec", "IPsec backend not admitted on this runtime")
	}
	return e.executeLockedWithIPsec(ctx, backend.Request{Operation: backend.OperationEnsure, Link: pending.Link},
		state.LinkRecord{}, "", true)
}

// ConnectIPsec explicitly starts IKEv2 after both endpoints have been
// configured. It must not bypass committed-state and resource ownership
// checks or initiate a connection based solely on an untrusted Link ID.
func (e *Engine) ConnectIPsec(ctx context.Context, id domain.LinkID) error {
	if e == nil || ctx == nil || id.Validate() != nil {
		return stlerr.New(stlerr.CodeInvalid, "ipsec_connect", string(id), "ipsec", "invalid canonical IPsec Connect request")
	}
	release, err := e.acquireMaintenance(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_connect", string(id), "ipsec", "maintenance gate unavailable")
	}
	defer release()
	unlock, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_connect", string(id), "ipsec", "Link lock unavailable")
	}
	defer unlock()
	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_connect", string(id), "ipsec", "cannot inspect Link state")
	}
	record, exists := snapshot.Find(id)
	if !exists || record.Desired.Backend != domain.BackendIPsec {
		return stlerr.New(stlerr.CodeConflict, "ipsec_connect", string(id), "ipsec", "IPsec Link is not committed")
	}
	locks, err := resourceLockClaims(record.OwnedResources)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_connect", string(id), "ipsec", "invalid committed resource locks")
	}
	unlockResources, err := e.locks.Acquire(ctx, locks)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_connect", string(id), "ipsec", "resource lock unavailable")
	}
	defer unlockResources()
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return stlerr.New(stlerr.CodeState, "ipsec_connect", string(id), "ipsec", "cannot revalidate committed Link")
	}
	exact, ok := fresh.Find(id)
	if !ok || exact.Desired != record.Desired ||
		!slices.EqualFunc(exact.OwnedResources, record.OwnedResources,
			func(a, b domain.ResourceClaim) bool { return a.Canonical() == b.Canonical() }) {
		return stlerr.New(stlerr.CodeConflict, "ipsec_connect", string(id), "ipsec", "IPsec committed identity changed")
	}
	if _, uncertain := fresh.FindIPsecReapplyOperation(id); uncertain {
		return stlerr.New(stlerr.CodeConflict, "ipsec_connect", string(id), "ipsec",
			"interrupted IPsec reapply must be reconciled before IKE initiation")
	}
	impl, ok := e.backends.Get(domain.BackendIPsec)
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "ipsec_connect", string(id), "ipsec", "operational IPsec backend unavailable")
	}
	connectable, ok := impl.(interface {
		Connect(context.Context, domain.Link, []domain.ResourceClaim) error
	})
	if !ok {
		return stlerr.New(stlerr.CodeUnsupported, "ipsec_connect", string(id), "ipsec", "operational IPsec Connect unavailable")
	}
	if err := connectable.Connect(ctx, exact.Desired, exact.OwnedResources); err != nil {
		// The original VICI result is intentionally not exposed. An IKE
		// timeout can be indeterminate; status must be checked read-only.
		return stlerr.New(stlerr.CodeState, "ipsec_connect", string(id), "ipsec", "IKEv2 initiation failed or outcome unknown; inspect protected connection and peer configuration")
	}
	return nil
}
