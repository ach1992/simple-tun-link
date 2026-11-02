package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type removedUnderlayRoute struct{ calls int }

func (r *removedUnderlayRoute) Resolve(context.Context, netip.Addr) (linux.Route, error) {
	r.calls++
	return linux.Route{}, errors.New("underlay / parent Link no longer has a route")
}

func TestNativeWireGuardRemoveWithoutAnyPeerRoute(t *testing.T) {
	engine, b, link, _, kernel, firewall, store := engineFixture(t)
	offline := &removedUnderlayRoute{}
	b.routes = offline
	result, err := engine.Remove(context.Background(), link.ID)
	if err != nil || !result.Removed || offline.calls != 0 || kernel.target.Exists || firewall.exists {
		t.Fatalf("native WireGuard removal depended on disconnected underlay: result=%+v err=%v routeCalls=%d", result, err, offline.calls)
	}
	snapshot, err := store.Load(context.Background())
	if err != nil || len(snapshot.Links) != 0 {
		t.Fatalf("retired Link still committed: %v %v", snapshot.Links, err)
	}
}

func TestManagedCarrierRemovePlanningNeedsNoPeerRoute(t *testing.T) {
	for _, kind := range []domain.Backend{domain.BackendWireGuardWSS, domain.BackendWireGuardQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			var b *Backend
			var link domain.Link
			var ctx context.Context
			if kind == domain.BackendWireGuardWSS {
				b, link, _, _, ctx = ordinaryWSSFixture(t)
			} else {
				b, link, _, ctx = ordinaryQUICFixture(t)
			}
			offline := &removedUnderlayRoute{}
			b.routes = offline
			req := core.Request{Operation: core.OperationRemove, Link: link, Prior: &link, OwnedResources: []domain.ResourceClaim{
				{Kind: domain.ResourceInterface, Key: mustWGInterfaceName(t, link.ID)},
				managedGuardClaim(link), managedHelperClaim(link),
			}}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatalf("Remove Plan blocked by offline underlay: %v", err)
			}
			if err := b.Validate(ctx, req, obs, plan); err != nil {
				t.Fatalf("Remove Validate blocked by offline underlay or safe owned local state: %v", err)
			}
			if offline.calls != 0 {
				t.Fatalf("Remove queried unavailable remote underlay route %d times", offline.calls)
			}
		})
	}
}

func mustWGInterfaceName(t *testing.T, id domain.LinkID) string {
	t.Helper()
	name, err := InterfaceName(id)
	if err != nil {
		t.Fatal(err)
	}
	return name
}
