package l2tpv3

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type disconnectedL2TPRoutes struct{}

func (disconnectedL2TPRoutes) Resolve(context.Context, netip.Addr) (linux.Route, error) {
	return linux.Route{}, errors.New("remote disconnected")
}

type offlineL2TPKernel struct {
	original   *fakeKernel
	localReads int
}

func (k *offlineL2TPKernel) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && len(args) == 3 && args[0] == "-json" && args[1] == "address" && args[2] == "show" {
		k.localReads++
		return linux.CommandResult{Stdout: []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.1"}]}]`)}, nil
	}
	return k.original.Run(ctx, name, args...)
}
func TestL2TPv3CanCreateWithoutAnyPeerRoute(t *testing.T) {
	link := testLink()
	kernel := newFakeKernel(t, link)
	fw := &fakeFirewall{}
	b := testBackend(t, link, kernel, fw, fakeCollisions{})
	host := &offlineL2TPKernel{original: kernel}
	b.runner = host
	b.routes = disconnectedL2TPRoutes{}
	plan, _, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: link})
	if err != nil || plan.Empty() || !fw.active || kernel.ifc == nil || len(kernel.tunnels) != 1 || len(kernel.sessions) != 1 || host.localReads < 3 {
		t.Fatalf("L2TPv3 could not create local resources without peer route: %v %+v", err, plan)
	}
}

// Test double for a capture-bounded host inventory read. It must never
// turn a call to RunBounded into an unchecked unbounded success.
func (k *offlineL2TPKernel) RunBounded(ctx context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
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
