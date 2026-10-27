//go:build linux

package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

type privateWSSQualityRunner struct {
	*scriptedLinuxRunner
	routeDevice, routeSource string
}

func newPrivateWSSQualityRunner() *privateWSSQualityRunner {
	r := newScriptedLinuxRunner()
	r.pingMax = 1400
	return &privateWSSQualityRunner{scriptedLinuxRunner: r, routeDevice: "stltest0", routeSource: "10.80.20.0"}
}

func (r *privateWSSQualityRunner) Run(ctx context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" && strings.Join(args, " ") == "-4 -json route get 10.80.20.1" {
		r.calls = append(r.calls, "ip -4 -json route get 10.80.20.1")
		return linux.CommandResult{Stdout: []byte(fmt.Sprintf(`[{"dst":"10.80.20.1","dev":%q,"prefsrc":%q}]`, r.routeDevice, r.routeSource))}, nil
	}
	return r.scriptedLinuxRunner.Run(ctx, name, args...)
}

func TestWSSPrivateQualityFiveRealBoundedEchoesWithoutInventingPMTU(t *testing.T) {
	link := diagnosticLink()
	link.Backend = domain.BackendWireGuardWSS
	link.Encapsulation = domain.EncapUDP
	link.DisplayName = "private_key=NEVER_PRINT"
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 443}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	r := newPrivateWSSQualityRunner()
	out, err := ObservePrivateLinkQuality(context.Background(), link, "stltest0", r)
	if err != nil {
		t.Fatal(err)
	}
	if out.LinkID != link.ID || out.MTU.SelectedMTU != 0 || out.MTU.Verified ||
		out.MTU.Mode != "not_measured" || out.Quality.PacketsSent != 5 ||
		out.Quality.PacketsReceived != 5 || r.pingTotalRequests != 5 {
		t.Fatalf("WSS five-ping projection incorrectly measured PMTU or traffic: %+v probes=%d", out, r.pingTotalRequests)
	}
	for _, command := range r.calls {
		if strings.Contains(command, "link set") || strings.Contains(command, "route add") ||
			strings.Contains(command, "address add") || strings.Contains(command, "-s 1392") {
			t.Fatal("WSS private quality attempted a host mutation or invented MTU probing")
		}
		if strings.HasPrefix(command, "env ") && (!strings.Contains(command, "-s 56") ||
			!strings.Contains(command, "-I stltest0 -I 10.80.20.0 10.80.20.1")) {
			t.Fatalf("WSS ICMP probe not bound to the selected private Link: %s", command)
		}
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "private_key") || strings.Contains(out.Summary(), "NEVER_PRINT") ||
		!strings.Contains(out.Summary(), "PMTU not measured") || !strings.Contains(out.Summary(), "5/5") {
		t.Fatalf("WSS false PMTU claim or secret leak: %s", out.Summary())
	}
}

func TestWSSPrivateQualityRejectsChangedRouteAndLocalIdentityBeforeProbing(t *testing.T) {
	link := diagnosticLink()
	link.Backend = domain.BackendWireGuardWSS
	link.Encapsulation = domain.EncapUDP
	link.WSS = domain.WSSOptions{Role: "listen", TCPPort: 443}
	for _, tc := range []struct {
		name   string
		mutate func(*privateWSSQualityRunner)
	}{
		{"wrong private route", func(r *privateWSSQualityRunner) { r.routeDevice = "eth0" }},
		{"wrong local source", func(r *privateWSSQualityRunner) { r.routeSource = "10.80.20.9" }},
		{"wrong saved address", func(r *privateWSSQualityRunner) { r.localPrefix = link.Addresses.Peer }},
		{"interface down", func(r *privateWSSQualityRunner) { r.linkUp = false }},
		{"untrusted ifindex", func(r *privateWSSQualityRunner) { r.addressIndex = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPrivateWSSQualityRunner()
			tc.mutate(r)
			if _, err := ObservePrivateLinkQuality(context.Background(), link, "stltest0", r); err == nil {
				t.Fatal("invalid owned Link admitted to ping")
			}
			if r.pingTotalRequests != 0 {
				t.Fatal("probe escaped failed preflight")
			}
		})
	}
}
