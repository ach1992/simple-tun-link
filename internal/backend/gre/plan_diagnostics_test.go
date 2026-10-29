package gre

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type brokenGREPlanRoute struct{}

func (brokenGREPlanRoute) Resolve(context.Context, netip.Addr) (linux.Route, error) {
	return linux.Route{}, errors.New("private-secret=DO_NOT_PRINT")
}

type unverifiedGREFirewall struct{ *fakeFirewall }

func (*unverifiedGREFirewall) HasInbound(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error) {
	return false, errors.New("private-firewall-token=DO_NOT_PRINT")
}

func TestGREPlanReasonCodesAreSpecificWithoutLeakingKernelErrors(t *testing.T) {
	link := testLink()
	name, err := InterfaceName(link.ID)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{link: link, name: name}
	backend := newTestBackend(t, runner, &fakeFirewall{}, fakeCollisions{})
	ctx := context.Background()
	observed, err := backend.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, reason string
		setup        func()
	}{
		{"route lookup", "gre_underlay_route_unverified", func() { backend.routes = brokenGREPlanRoute{} }},
		{"source mismatch", "gre_underlay_source_mismatch", func() {
			backend.routes = fakeRoute{route: linux.Route{Peer: link.Underlay.Peer, Source: netip.MustParseAddr("192.0.2.99"), Device: "eth0"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			_, err := backend.Plan(ctx, core.Request{Operation: core.OperationEnsure, Link: link}, observed)
			public := stlerr.Public(err)
			if err == nil || public.ReasonCode != tc.reason || public.NextStep == "" ||
				!strings.Contains(public.NextStep, "ip -4 route get") ||
				strings.Contains(public.Error()+public.NextStep, "DO_NOT_PRINT") {
				t.Fatalf("bad route plan refusal: %+v err=%v", public, err)
			}
		})
	}
}
