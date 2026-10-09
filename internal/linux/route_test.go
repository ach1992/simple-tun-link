package linux

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

type fakeRunner struct {
	result CommandResult
	err    error
	name   string
	args   []string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return r.result, r.err
}

func TestRouteResolverUsesActualPeerAndPreferredSource(t *testing.T) {
	runner := &fakeRunner{result: CommandResult{Stdout: []byte(`[{"dst":"203.0.113.9","gateway":"192.0.2.1","dev":"eth0","prefsrc":"192.0.2.10"}]`)}}
	resolver := RouteResolver{Runner: runner}
	peer := netip.MustParseAddr("203.0.113.9")

	route, err := resolver.Resolve(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"-4", "-json", "route", "get", "203.0.113.9"}
	if runner.name != "ip" || !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("command = %q %#v, want ip %#v", runner.name, runner.args, wantArgs)
	}
	if route.Source != netip.MustParseAddr("192.0.2.10") || route.Device != "eth0" || route.Gateway != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("route = %#v", route)
	}
}

func TestRouteResolverSupportsIPv6AndSourceFallback(t *testing.T) {
	runner := &fakeRunner{result: CommandResult{Stdout: []byte(`[{"dst":"2001:db8::20","dev":"ens3","src":"2001:db8::10"}]`)}}
	peer := netip.MustParseAddr("2001:db8::20")

	route, err := (RouteResolver{Runner: runner}).Resolve(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"-6", "-json", "route", "get", "2001:db8::20"}
	if !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", runner.args, wantArgs)
	}
	if route.Source != netip.MustParseAddr("2001:db8::10") || route.Gateway.IsValid() {
		t.Fatalf("route = %#v", route)
	}
}

func TestRouteResolverRejectsMissingSourceAndAmbiguousRows(t *testing.T) {
	peer := netip.MustParseAddr("203.0.113.9")
	for name, payload := range map[string]string{
		"missing source": `[{"dst":"203.0.113.9","dev":"eth0"}]`,
		"multiple rows":  `[{"dev":"eth0","prefsrc":"192.0.2.10"},{"dev":"eth1","prefsrc":"192.0.2.11"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{result: CommandResult{Stdout: []byte(payload)}}
			if _, err := (RouteResolver{Runner: runner}).Resolve(context.Background(), peer); err == nil {
				t.Fatal("expected route validation failure")
			}
		})
	}
}

func TestRouteResolverPropagatesCommandFailure(t *testing.T) {
	cause := errors.New("ip failed")
	runner := &fakeRunner{err: cause}
	_, err := (RouteResolver{Runner: runner}).Resolve(context.Background(), netip.MustParseAddr("203.0.113.9"))
	if err == nil || !errors.Is(err, cause) {
		t.Fatalf("err = %v, want wrapped command failure", err)
	}
}

func TestRouteResolverReportsOptionalRouteMTU(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantMTU int
		wantErr bool
	}{
		{"top level", `[{"dst":"203.0.113.9","dev":"eth0","prefsrc":"192.0.2.10","mtu":1410}]`, 1410, false},
		{"nested metric", `[{"dst":"203.0.113.9","dev":"eth0","prefsrc":"192.0.2.10","metrics":{"mtu":1390}}]`, 1390, false},
		{"both use lower", `[{"dst":"203.0.113.9","dev":"eth0","prefsrc":"192.0.2.10","mtu":1450,"metrics":{"mtu":1390}}]`, 1390, false},
		{"not specified", `[{"dst":"203.0.113.9","dev":"eth0","prefsrc":"192.0.2.10"}]`, 0, false},
		{"invalid negative", `[{"dst":"203.0.113.9","dev":"eth0","prefsrc":"192.0.2.10","mtu":-1}]`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{result: CommandResult{Stdout: []byte(tc.json)}}
			route, err := (RouteResolver{Runner: runner}).Resolve(context.Background(), netip.MustParseAddr("203.0.113.9"))
			if (err != nil) != tc.wantErr || (err == nil && route.MTU != tc.wantMTU) {
				t.Fatalf("Route.MTU=%d err=%v; want %d error=%v", route.MTU, err, tc.wantMTU, tc.wantErr)
			}
		})
	}
}
