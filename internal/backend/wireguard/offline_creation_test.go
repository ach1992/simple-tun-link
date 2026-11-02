package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type disconnectedWireGuardPeer struct{ queries int }

func (r *disconnectedWireGuardPeer) Resolve(context.Context, netip.Addr) (linux.Route, error) {
	r.queries++
	return linux.Route{}, errors.New("remote unreachable")
}

type localOnlyWGKernel struct {
	*fakeKernel
	inventoryReads int
}

func (k *localOnlyWGKernel) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && reflect.DeepEqual(args, []string{"-json", "address", "show"}) {
		k.inventoryReads++
		return linux.CommandResult{Stdout: []byte(`[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`)}, nil
	}
	return k.fakeKernel.Run(ctx, name, args...)
}

func TestNativeWireGuardCanCreateWithoutRemoteRoute(t *testing.T) {
	b, link, _, k, fw := fixture(t)
	host := &localOnlyWGKernel{fakeKernel: k}
	b.runner = host
	missing := &disconnectedWireGuardPeer{}
	b.routes = missing
	ctx := context.Background()
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Validate(ctx, req, obs, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Apply(ctx, req, obs, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Verify(ctx, req); err != nil {
		t.Fatal(err)
	}
	if !k.target.Exists || !fw.exists || host.inventoryReads < 2 || missing.queries < 2 {
		t.Fatalf("native local WG was not completed independently of peer route: reads=%d queries=%d target=%+v firewall=%t", host.inventoryReads, missing.queries, k.target, fw.exists)
	}
}

func TestWSSAndQUICLocalEnsurePlanUsesAssignedIPv4WithoutPeer(t *testing.T) {
	for _, kind := range []domain.Backend{domain.BackendWireGuardWSS, domain.BackendWireGuardQUIC} {
		t.Run(string(kind), func(t *testing.T) {
			var b *Backend
			var link domain.Link
			var k *fakeKernel
			var ctx context.Context
			if kind == domain.BackendWireGuardWSS {
				b, link, k, _, ctx = ordinaryWSSFixture(t)
			} else {
				b, link, k, ctx = ordinaryQUICFixture(t)
			}
			host := &localOnlyWGKernel{fakeKernel: k}
			b.runner = host
			missing := &disconnectedWireGuardPeer{}
			b.routes = missing
			req := core.Request{Operation: core.OperationEnsure, Link: link, Prior: &link}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatalf("managed carrier Ensure Plan relied on remote route: %v", err)
			}
			req.OwnedResources = plan.Resources()
			if err = b.Validate(ctx, req, obs, plan); err != nil {
				t.Fatalf("managed carrier Ensure Validate depended on peer route: %v", err)
			}
			if host.inventoryReads < 2 || missing.queries < 2 {
				t.Fatal("managed carrier did not recheck local underlay identity")
			}
		})
	}
}

// Test double for a capture-bounded host inventory read. It must never
// turn a call to RunBounded into an unchecked unbounded success.
func (k *localOnlyWGKernel) RunBounded(ctx context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if limits.Stdout <= 0 || limits.Stderr <= 0 {
		return linux.CommandResult{}, linux.ErrOutputLimit
	}
	if err := ctx.Err(); err != nil {
		return linux.CommandResult{}, err
	}
	output, err := k.Run(ctx, name, args...)
	if len(output.Stdout) > limits.Stdout || len(output.Stderr) > limits.Stderr {
		return linux.CommandResult{}, linux.ErrOutputLimit
	}
	return output, err
}
