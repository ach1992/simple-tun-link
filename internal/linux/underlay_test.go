package linux

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type offlineUnderlayRoutes struct {
	calls  int
	source netip.Addr
}

func (r *offlineUnderlayRoutes) Resolve(_ context.Context, peer netip.Addr) (Route, error) {
	r.calls++
	if r.source.IsValid() {
		return Route{Peer: peer, Source: r.source, Device: "wrong0"}, nil
	}
	return Route{}, errors.New("network unreachable")
}
func TestLocalAddressInventoryAndPeerOfflineFallback(t *testing.T) {
	local, peer := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	host := &fakeRunner{result: CommandResult{Stdout: []byte(`[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1"}]},{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"},{"family":"inet6","local":"2001:db8::1"}]}]`)}}
	for _, route := range []*offlineUnderlayRoutes{{}, {source: netip.MustParseAddr("198.51.100.4")}} {
		got, err := ResolveConfiguredUnderlay(context.Background(), route, host, local, peer)
		if err != nil || got.Source != local || got.Device != "ens3" || got.Peer != peer || got.Gateway.IsValid() || route.calls != 1 {
			t.Fatalf("offline local creation failed: got=%+v err=%v calls=%d", got, err, route.calls)
		}
		if host.name != "ip" || len(host.args) != 3 || host.args[0] != "-json" || host.args[1] != "address" || host.args[2] != "show" {
			t.Fatal("fallback performed something other than local address inventory", host.args)
		}
	}
}
func TestLocalIPv4FallbackRejectsUnassignedAndAmbiguousSource(t *testing.T) {
	local, peer := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	for _, tc := range []struct{ name, json string }{
		{"unassigned", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.11"}]}]`},
		{"ambiguous", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]},{"ifname":"eth1","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`},
		{"malformed", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"UNTRUSTED"}]}]`},
		{"foreign interface", `[{"ifname":"bad space","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeRunner{result: CommandResult{Stdout: []byte(tc.json)}}
			if _, err := ResolveConfiguredUnderlay(context.Background(), &offlineUnderlayRoutes{}, host, local, peer); err == nil {
				t.Fatal("admitted unverified local address")
			}
		})
	}
}

func TestLocalInventoryRequiredEvenForMatchingRouteHint(t *testing.T) {
	local, peer := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.20")
	matching := &offlineUnderlayRoutes{source: local}
	for _, tc := range []struct {
		name, rows string
		wantDevice string
		mustReject bool
	}{
		{"matching-route-but-unassigned", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.99"}]}]`, "", true},
		{"matching-route-but-wrong-device", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`, "ens3", false},
		{"matching-route-but-ambiguous", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"}]},{"ifname":"eth1","addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`, "", true},
		{"matching-route-but-duplicate", `[{"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.10"},{"family":"inet","local":"192.0.2.10"}]}]`, "", true},
		{"matching-route-but-unknown-family", `[{"ifname":"ens3","addr_info":[{"local":"192.0.2.10"}]}]`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{result: CommandResult{Stdout: []byte(tc.rows)}}
			got, err := ResolveConfiguredUnderlay(context.Background(), matching, r, local, peer)
			if tc.mustReject {
				if err == nil {
					t.Fatalf("route suggestion bypassed assigned IPv4 proof: %+v", got)
				}
			} else if err != nil || got.Device != tc.wantDevice || got.Gateway.IsValid() || got.MTU != 0 {
				t.Fatalf("wrong route device not safely replaced by local inventory: %+v %v", got, err)
			}
		})
	}
}

func TestLocalAddressInventoryRejectsOversizedOrMissingContext(t *testing.T) {
	runner := &fakeRunner{result: CommandResult{Stdout: []byte("[" + strings.Repeat(" ", 256<<10) + "]")}}
	if _, err := ListLocalIPv4Endpoints(context.Background(), runner); err == nil {
		t.Fatal("unbounded host address inventory was accepted")
	}
	if _, err := ListLocalIPv4Endpoints(nil, runner); err == nil {
		t.Fatal("missing context accepted")
	}
}
