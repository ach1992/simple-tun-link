package l2tpv3

import (
	"context"
	"errors"
	"net/netip"
	"strings"
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
	captureErr error
}

func (k *offlineL2TPKernel) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && len(args) == 3 && args[0] == "-json" && args[1] == "address" && args[2] == "show" {
		k.localReads++
		return linux.CommandResult{Stdout: []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.1"}]}]`)}, nil
	}
	return k.original.Run(ctx, name, args...)
}

// A successful Plan cannot erase the actual second, bounded inventory error
// during Validate. The route hint may differ, but local inventory is required.
func TestL2TPv3ValidatePreservesCaptureFailureOnMisleadingRoute(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
	}{
		{"capture_overflow", linux.ErrOutputLimit},
		{"deadline", context.DeadlineExceeded},
		{"cancelled", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := testLink()
			kernel := newFakeKernel(t, link)
			firewall := &fakeFirewall{}
			b := testBackend(t, link, kernel, firewall, fakeCollisions{})
			host := &offlineL2TPKernel{original: kernel}
			b.runner = host
			b.routes = fakeRoutes{source: netip.MustParseAddr("203.0.113.99")}
			req := core.Request{Operation: core.OperationEnsure, Link: link}
			ctx := context.Background()
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatalf("valid assigned address with misleading route should plan: %v", err)
			}
			host.captureErr = errors.Join(tc.cause, errors.New("PRIVATE_KERNEL_OUTPUT_DO_NOT_ECHO"))
			err = b.Validate(ctx, req, obs, plan)
			if !errors.Is(err, tc.cause) || errors.Is(err, linux.ErrUnderlaySourceMismatch) {
				t.Fatalf("L2TPv3 Validate dropped inventory failure: %v", err)
			}
			if strings.Contains(err.Error(), "PRIVATE_KERNEL_OUTPUT_DO_NOT_ECHO") {
				t.Fatal("L2TPv3 Validation surfaced untrusted subprocess text")
			}
			if len(kernel.tunnels) != 0 || len(kernel.sessions) != 0 || kernel.ifc != nil || firewall.active {
				t.Fatal("L2TPv3 mutated the host during refused Validate")
			}
		})
	}
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
	if k.captureErr != nil && name == "ip" && len(args) == 3 &&
		args[0] == "-json" && args[1] == "address" && args[2] == "show" {
		return linux.CommandResult{}, k.captureErr
	}
	output, err := k.Run(ctx, name, args...)
	if len(output.Stdout) > limits.Stdout || len(output.Stderr) > limits.Stderr {
		return linux.CommandResult{}, linux.ErrOutputLimit
	}
	return output, err
}
