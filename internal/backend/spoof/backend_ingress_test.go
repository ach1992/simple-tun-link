package spoof

import (
	"context"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestSpoofManagedIngressRestoresRulesWithoutRestartingHealthyHelper(t *testing.T) {
	link := spoofFixture(t, "auto")
	link.Spoof.ManageIngress = true
	link.Spoof.IngressInterface = "eth0"
	ctx := context.Background()
	host := &fixtureHost{
		current: HostObservation{
			UnitExists: true, UnitOwned: true, UnitActive: true,
			InterfaceExists: true, InterfaceOwned: true, AddressReady: true, PeerRoute: true,
			RuntimeReady: true, FirewallReady: false, FirewallExists: false,
		},
	}
	backend, _ := New(host)
	observation, err := backend.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := expectedClaims(link)
	if err != nil {
		t.Fatal(err)
	}
	prior := link
	request := core.Request{Operation: core.OperationEnsure, Link: link, Prior: &prior, OwnedResources: claim}
	plan, err := backend.Plan(ctx, request, observation)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Empty() {
		t.Fatal("missing original managed firewall rules were not scheduled for reconciliation")
	}
	if err := backend.Validate(ctx, request, observation, plan); err != nil {
		t.Fatal(err)
	}
	host.current.FirewallReady = true
	healthy, _ := backend.Inspect(ctx, link)
	plan, err = backend.Plan(ctx, request, healthy)
	if err != nil || !plan.Empty() {
		t.Fatalf("healthy already-owned Link should be idempotent, err=%v", err)
	}
}
func TestSpoofManagedIngressRemovalSchedulesExactOwnedResource(t *testing.T) {
	link := spoofFixture(t, "auto")
	link.Spoof.ManageIngress = true
	link.Spoof.IngressInterface = "eth0"
	ctx := context.Background()
	host := &fixtureHost{current: HostObservation{FirewallExists: true, FirewallReady: false}}
	backend, _ := New(host)
	obs, err := backend.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := expectedClaims(link)
	if err != nil {
		t.Fatal(err)
	}
	previous := link
	req := core.Request{Operation: core.OperationRemove, Link: link, Prior: &previous, OwnedResources: claims}
	plan, err := backend.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Empty() {
		t.Fatal("orphaned exact original ingress rule not scheduled for cleanup")
	}
	if err := backend.Validate(ctx, req, obs, plan); err != nil {
		t.Fatal(err)
	}
}

var _ domain.Backend = domain.BackendSpoof
