package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type Locker interface {
	Acquire(context.Context, []domain.ResourceClaim) (func() error, error)
}

type Engine struct {
	backends           *backend.Registry
	store              state.Store
	locks              Locker
	restorePersistence RestorePersistence
	restoreExecutable  string
}

type Result struct {
	LinkID  domain.LinkID
	Changed bool
	Removed bool
}

func New(backends *backend.Registry, store state.Store, locks Locker) (*Engine, error) {
	if backends == nil || store == nil || locks == nil {
		return nil, fmt.Errorf("backends, store, and locks are required")
	}
	return &Engine{backends: backends, store: store, locks: locks}, nil
}

func (e *Engine) Ensure(ctx context.Context, desired domain.Link) (Result, error) {
	if err := desired.Validate(); err != nil {
		return Result{}, contextualize(err, stlerr.CodeInvalid, "ensure", desired, "invalid desired Link")
	}
	return e.executeEnsure(ctx, desired)
}

func (e *Engine) Remove(ctx context.Context, id domain.LinkID) (Result, error) {
	if err := id.Validate(); err != nil {
		return Result{}, contextualize(err, stlerr.CodeInvalid, "remove", domain.Link{ID: id}, "invalid Link ID")
	}

	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(id)})
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "remove", string(id), "", "cannot lock Link", err)
	}
	defer linkRelease()

	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "remove", string(id), "", "cannot load local state", err)
	}
	record, ok := snapshot.Find(id)
	if !ok {
		return Result{}, stlerr.New(stlerr.CodeInvalid, "remove", string(id), "", "Link is not present in local state")
	}
	prior := record.Desired
	return e.executeLocked(ctx, backend.Request{Operation: backend.OperationRemove, Prior: &prior, Link: record.Desired}, record)
}

func (e *Engine) executeEnsure(ctx context.Context, desired domain.Link) (Result, error) {
	linkRelease, err := e.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(desired.ID)})
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "ensure", string(desired.ID), string(desired.Backend), "cannot lock Link", err)
	}
	defer linkRelease()

	snapshot, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, "ensure", string(desired.ID), string(desired.Backend), "cannot load local state", err)
	}
	record, exists := snapshot.Find(desired.ID)
	if exists && record.Desired.Backend != desired.Backend {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, "ensure", string(desired.ID), string(desired.Backend), "changing backend for an existing Link is not supported by this lifecycle yet")
	}
	var prior *domain.Link
	if exists {
		previous := record.Desired
		prior = &previous
	}
	return e.executeLocked(ctx, backend.Request{Operation: backend.OperationEnsure, Prior: prior, Link: desired}, record)
}

func (e *Engine) executeLocked(ctx context.Context, request backend.Request, prior state.LinkRecord) (Result, error) {
	request.OwnedResources = append([]domain.ResourceClaim(nil), prior.OwnedResources...)
	link := request.Link
	impl, ok := e.backends.Get(link.Backend)
	if !ok {
		return Result{}, stlerr.New(stlerr.CodeUnsupported, string(request.Operation), string(link.ID), string(link.Backend), "backend is not registered")
	}

	observed, err := impl.Inspect(ctx, link)
	if err != nil {
		return Result{}, contextualize(err, stlerr.CodeInspect, string(request.Operation), link, "backend inspection failed")
	}
	plan, err := impl.Plan(ctx, request, observed)
	if err != nil {
		return Result{}, contextualize(err, stlerr.CodePlan, string(request.Operation), link, "backend planning failed")
	}
	if plan == nil {
		return Result{}, stlerr.New(stlerr.CodeInternal, string(request.Operation), string(link.ID), string(link.Backend), "backend returned a nil plan")
	}

	resources, err := validatedClaims(plan.Resources())
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodePlan, string(request.Operation), string(link.ID), string(link.Backend), "backend plan contains an invalid resource claim", err)
	}
	lockClaims, err := resourceLockClaims(prior.OwnedResources, resources)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot derive resource locks", err)
	}
	resourceRelease, err := e.locks.Acquire(ctx, lockClaims)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot lock Link resources", err)
	}
	defer resourceRelease()

	// Resource locks can wait behind another Link operation. Refresh observed and
	// persisted state after acquiring them so stale plans cannot silently claim a
	// resource that was committed while this operation waited.
	observed, err = impl.Inspect(ctx, link)
	if err != nil {
		return Result{}, contextualize(err, stlerr.CodeInspect, string(request.Operation), link, "backend re-inspection failed")
	}
	fresh, err := e.store.Load(ctx)
	if err != nil {
		return Result{}, stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot reload local state", err)
	}
	if request.Operation == backend.OperationEnsure {
		if err := rejectResourceConflicts(fresh, link.ID, resources); err != nil {
			return Result{}, err
		}
	}
	if err := impl.Validate(ctx, request, observed, plan); err != nil {
		return Result{}, contextualize(err, stlerr.CodeValidate, string(request.Operation), link, "backend validation failed")
	}

	changed := !plan.Empty()
	var undo backend.Rollback
	if changed {
		undo, err = impl.Apply(ctx, request, observed, plan)
		if err != nil {
			return Result{}, e.rollbackFailure(ctx, request, link, undo, contextualize(err, stlerr.CodeApply, string(request.Operation), link, "backend apply failed"))
		}
		if undo == nil {
			return Result{}, stlerr.New(stlerr.CodeInternal, string(request.Operation), string(link.ID), string(link.Backend), "backend changed state without providing rollback")
		}
	}

	if _, err := impl.Verify(ctx, request); err != nil {
		return Result{}, e.rollbackFailure(ctx, request, link, undo, contextualize(err, stlerr.CodeVerify, string(request.Operation), link, "backend verification failed"))
	}

	// Serialize only the host-wide persistence transition and state commit.
	// Backend inspection/apply stays per-Link to preserve Multi-Link concurrency.
	var persistenceUndo func(context.Context) error
	if e.restorePersistence != nil {
		persistenceRelease, lockErr := e.locks.Acquire(ctx, []domain.ResourceClaim{restoreLockClaim()})
		if lockErr != nil {
			return Result{}, e.rollbackFailure(ctx, request, link, undo,
				stlerr.Wrap(stlerr.CodeState, string(request.Operation), string(link.ID), string(link.Backend), "cannot lock restore persistence", lockErr))
		}
		defer persistenceRelease()

		if request.Operation == backend.OperationEnsure {
			var ensureErr error
			persistenceUndo, _, ensureErr = e.restorePersistence.EnsureRestore(ctx, e.restoreExecutable)
			if ensureErr != nil {
				return Result{}, e.rollbackFailure(ctx, request, link, undo,
					stlerr.Wrap(stlerr.CodeState, "ensure", string(link.ID), string(link.Backend), "cannot activate restore persistence", ensureErr))
			}
		}
	}

	remaining := -1
	commitErr := e.store.Update(ctx, func(snapshot *state.Snapshot) error {
		switch request.Operation {
		case backend.OperationEnsure:
			if err := rejectResourceConflicts(*snapshot, link.ID, resources); err != nil {
				return err
			}
			snapshot.Upsert(state.LinkRecord{Desired: link, OwnedResources: resources})
		case backend.OperationRemove:
			if !snapshot.Delete(link.ID) {
				return state.ErrNotFound
			}
		default:
			return fmt.Errorf("unsupported operation %q", request.Operation)
		}
		remaining = len(snapshot.Links)
		return nil
	})
	if commitErr != nil {
		commitPublic := contextualize(commitErr, stlerr.CodeState, string(request.Operation), link, "cannot commit local state")
		if persistenceUndo != nil {
			if rollbackErr := persistenceUndo(context.WithoutCancel(ctx)); rollbackErr != nil {
				commitPublic = stlerr.Wrap(stlerr.CodeRollback, string(request.Operation), string(link.ID), string(link.Backend),
					"state commit failed and restore persistence rollback did not complete", errors.Join(commitPublic, rollbackErr))
			}
		}
		return Result{}, e.rollbackFailure(ctx, request, link, undo, commitPublic)
	}

	// After the final desired Link is durably deleted, its owned reboot unit
	// is no longer needed. An uncertain cleanup is reported as partial failure;
	// never roll a removed Link back solely to conceal a unit cleanup error.
	if request.Operation == backend.OperationRemove && remaining == 0 && e.restorePersistence != nil {
		if err := e.restorePersistence.RemoveRestore(ctx); err != nil {
			return Result{LinkID: link.ID, Changed: changed, Removed: true},
				stlerr.Wrap(stlerr.CodeState, "remove", string(link.ID), string(link.Backend),
					"Link removed, but restore persistence cleanup failed", err)
		}
	}

	return Result{
		LinkID:  link.ID,
		Changed: changed,
		Removed: request.Operation == backend.OperationRemove,
	}, nil
}

func (e *Engine) rollbackFailure(ctx context.Context, request backend.Request, link domain.Link, undo backend.Rollback, original error) error {
	if undo == nil {
		return original
	}
	if err := undo(ctx); err != nil {
		return stlerr.Wrap(stlerr.CodeRollback, string(request.Operation), string(link.ID), string(link.Backend), "operation failed and rollback did not complete", errors.Join(original, err))
	}
	return original
}

func rejectResourceConflicts(snapshot state.Snapshot, id domain.LinkID, wanted []domain.ResourceClaim) error {
	for _, record := range snapshot.Links {
		if record.Desired.ID == id {
			continue
		}
		for _, wantedClaim := range wanted {
			for _, ownedClaim := range record.OwnedResources {
				conflict, err := domain.ResourceClaimsConflict(wantedClaim, ownedClaim)
				if err != nil {
					return stlerr.Wrap(stlerr.CodeState, "validate_resources", string(id), "", "cannot compare resource ownership", err)
				}
				if conflict {
					return stlerr.New(
						stlerr.CodeConflict,
						"validate_resources",
						string(id),
						"",
						fmt.Sprintf("resource %s conflicts with Link %s", wantedClaim.Kind, record.Desired.ID),
					)
				}
			}
		}
	}
	return nil
}

func contextualize(err error, fallback stlerr.Code, operation string, link domain.Link, detail string) error {
	var typed *stlerr.Error
	if errors.As(err, &typed) {
		safeDetail := typed.Detail
		if safeDetail == "" {
			safeDetail = detail
		}
		return stlerr.Wrap(typed.Code, operation, string(link.ID), string(link.Backend), safeDetail, err)
	}
	return stlerr.Wrap(fallback, operation, string(link.ID), string(link.Backend), detail, err)
}

func linkLock(id domain.LinkID) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: "stl-link", Key: string(id)}
}

func resourceLockClaims(groups ...[]domain.ResourceClaim) ([]domain.ResourceClaim, error) {
	claims := unionClaims(groups...)
	for _, claim := range claims {
		switch claim.Kind {
		case domain.ResourceLinkAddress, domain.ResourceLinkSubnet:
			family, err := addressFamily(claim)
			if err != nil {
				return nil, err
			}
			claims = append(claims, domain.ResourceClaim{Kind: "stl-address-space", Key: family})
		}
	}
	return unionClaims(claims), nil
}

func addressFamily(claim domain.ResourceClaim) (string, error) {
	if err := claim.Validate(); err != nil {
		return "", err
	}
	var addr netip.Addr
	switch claim.Kind {
	case domain.ResourceLinkAddress:
		addr, _ = netip.ParseAddr(claim.Key)
	case domain.ResourceLinkSubnet:
		prefix, _ := netip.ParsePrefix(claim.Key)
		addr = prefix.Addr()
	default:
		return "", fmt.Errorf("resource kind %q has no address family", claim.Kind)
	}
	if addr.Is4() {
		return "ipv4", nil
	}
	return "ipv6", nil
}

func validatedClaims(claims []domain.ResourceClaim) ([]domain.ResourceClaim, error) {
	out := unionClaims(claims)
	for _, claim := range out {
		if err := claim.Validate(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(claim.Kind, "stl-") {
			return nil, fmt.Errorf("resource claim kind %q is reserved by the core engine", claim.Kind)
		}
	}
	return out, nil
}

func unionClaims(groups ...[]domain.ResourceClaim) []domain.ResourceClaim {
	set := make(map[string]domain.ResourceClaim)
	for _, claims := range groups {
		for _, claim := range claims {
			set[claim.Canonical()] = claim
		}
	}
	out := make([]domain.ResourceClaim, 0, len(set))
	for _, claim := range set {
		out = append(out, claim)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Canonical() < out[j].Canonical() })
	return out
}

// restoreLockClaim protects the host-wide unit lifecycle and desired-state
// transition without serializing the independent backend apply steps.
func restoreLockClaim() domain.ResourceClaim {
	return domain.ResourceClaim{Kind: "stl-restore-unit", Key: "host"}
}
