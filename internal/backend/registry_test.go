package backend

import (
	"context"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type registryBackend struct{ kind domain.Backend }

func (b registryBackend) Kind() domain.Backend                                     { return b.kind }
func (registryBackend) Inspect(context.Context, domain.Link) (Observation, error)  { return nil, nil }
func (registryBackend) Plan(context.Context, Request, Observation) (Plan, error)   { return nil, nil }
func (registryBackend) Validate(context.Context, Request, Observation, Plan) error { return nil }
func (registryBackend) Apply(context.Context, Request, Observation, Plan) (Rollback, error) {
	return nil, nil
}
func (registryBackend) Verify(context.Context, Request) (Observation, error) { return nil, nil }

func TestRegistryRejectsDuplicateKinds(t *testing.T) {
	_, err := NewRegistry(registryBackend{domain.BackendGRE}, registryBackend{domain.BackendGRE})
	if err == nil {
		t.Fatal("expected duplicate backend error")
	}
}
