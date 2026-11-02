package gre

import (
	"context"
	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"testing"
)

type offlineGREHost struct {
	original   *fakeRunner
	localReads int
}

func (h *offlineGREHost) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && len(args) == 3 && args[0] == "-json" && args[1] == "address" && args[2] == "show" {
		h.localReads++
		return linux.CommandResult{Stdout: []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`)}, nil
	}
	return h.original.Run(ctx, name, args...)
}
func TestAllGREEncapsulationsCreateOfflineWithAssignedLocalIPv4(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapNative, domain.EncapFOU, domain.EncapGUE} {
		t.Run(string(encap), func(t *testing.T) {
			link := testLink()
			link.Encapsulation = encap
			if encap != domain.EncapNative {
				link.GRE.UDPPort = 51231
			}
			name, _ := InterfaceName(link.ID)
			original := &fakeRunner{link: link, name: name}
			fw := &fakeFirewall{}
			b := newTestBackend(t, original, fw, fakeCollisions{})
			host := &offlineGREHost{original: original}
			b.runner = host
			b.routes = brokenGREPlanRoute{}
			ctx := context.Background()
			req := core.Request{Operation: core.OperationEnsure, Link: link}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatalf("cannot plan offline native GRE: %v", err)
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
				t.Fatal("offline GRE did not create exact local resources")
			}
		})
	}
}
