package backend

import (
	"context"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type Operation string

const (
	OperationEnsure Operation = "ensure"
	OperationRemove Operation = "remove"
)

type Request struct {
	Operation Operation
	// Prior is the last committed desired Link, when one exists. It lets a
	// backend plan an update without deriving previous ownership from the new
	// desired state. It is nil for first creation.
	Prior *domain.Link
	Link  domain.Link
	// OwnedResources is the exact exclusive ownership set committed for Prior.
	// Backends use it to prove ownership before destructive repair/remove work;
	// overlapping/conflicting identity is not by itself proof of ownership.
	OwnedResources []domain.ResourceClaim
}

// Observation is backend-owned observed host state. It is intentionally
// distinct from persisted desired Link state.
type Observation interface {
	ObservedResources() []domain.ResourceClaim
}

// Plan is backend-owned executable intent. Resources must return the complete
// secret-free resource set that the Link should own after a successful Ensure.
// For Remove, it may be empty because the persisted ownership set is locked by
// the engine before mutation.
type Plan interface {
	Empty() bool
	Resources() []domain.ResourceClaim
}

// Rollback undoes only the delta created by the current Apply call. If Apply
// mutates state, it must return a non-nil Rollback even on a later error so the
// engine can restore only that owned delta.
type Rollback func(context.Context) error

// Backend is the minimum lifecycle boundary needed by the core engine. It is
// private under internal/ and is not a dynamic/public plugin API. Validate runs
// after resource locks are acquired and host state is re-inspected, so it must
// reject a plan whose assumptions are no longer true instead of applying stale
// intent. Apply must not mutate resources outside the supplied Plan.
type Backend interface {
	Kind() domain.Backend
	Inspect(context.Context, domain.Link) (Observation, error)
	Plan(context.Context, Request, Observation) (Plan, error)
	Validate(context.Context, Request, Observation, Plan) error
	Apply(context.Context, Request, Observation, Plan) (Rollback, error)
	Verify(context.Context, Request) (Observation, error)
}
