package ipip

import (
	"context"
	"errors"
	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"net/netip"
	"testing"
)

type offlineIPIPRoutes struct{}

func (offlineIPIPRoutes) Resolve(context.Context, netip.Addr) (linux.Route, error) {
	return linux.Route{}, errors.New("remote unreachable")
}

type offlineIPIPHost struct {
	original   *fakeRunner
	localReads int
}

func (h *offlineIPIPHost) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && len(args) == 3 && args[0] == "-json" && args[1] == "address" && args[2] == "show" {
		h.localReads++
		return linux.CommandResult{Stdout: []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`)}, nil
	}
	return h.original.Run(ctx, name, args...)
}
func TestAllIPIPEncapsulationsCreateOfflineWithAssignedLocalIPv4(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapNative, domain.EncapFOU, domain.EncapGUE} {
		t.Run(string(encap), func(t *testing.T) {
			link := testLink()
			link.Encapsulation = encap
			name, _ := InterfaceName(link.ID)
			original := &fakeRunner{link: link, name: name}
			fw := &fakeFirewall{}
			b := newTestBackend(t, original, fw, fakeCollisions{})
			host := &offlineIPIPHost{original: original}
			b.runner = host
			b.routes = offlineIPIPRoutes{}
			ctx := context.Background()
			req := core.Request{Operation: core.OperationEnsure, Link: link}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatalf("cannot plan offline native IPIP: %v", err)
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
			if host.localReads < 3 || !original.state.Exists || !fw.present {
				t.Fatal("offline IPIP did not create exact local resources")
			}
		})
	}
}

// Test double for a capture-bounded host inventory read. It must never
// turn a call to RunBounded into an unchecked unbounded success.
func (h *offlineIPIPHost) RunBounded(ctx context.Context, limits linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if limits.Stdout <= 0 || limits.Stderr <= 0 {
		return linux.CommandResult{}, linux.ErrOutputLimit
	}
	if err := ctx.Err(); err != nil {
		return linux.CommandResult{}, err
	}
	output, err := h.Run(ctx, name, args...)
	if len(output.Stdout) > limits.Stdout || len(output.Stderr) > limits.Stderr {
		return linux.CommandResult{}, linux.ErrOutputLimit
	}
	return output, err
}
