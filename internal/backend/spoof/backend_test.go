package spoof

import (
	"context"
	"encoding/base64"
	"net/netip"
	"slices"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type fixtureHost struct {
	current                   HostObservation
	starts, stops, preflights int
}

func (h *fixtureHost) Inspect(context.Context, domain.Link) (HostObservation, error) {
	return h.current, nil
}
func (h *fixtureHost) Preflight(context.Context, domain.Link, bool) error { h.preflights++; return nil }
func (h *fixtureHost) Start(context.Context, domain.Link) (core.Rollback, error) {
	h.starts++
	h.current = HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true, InterfaceExists: true, InterfaceOwned: true, AddressReady: true, PeerRoute: true, RuntimeReady: true}
	return nil, nil
}
func (h *fixtureHost) Stop(context.Context, domain.Link) (core.Rollback, error) {
	h.stops++
	h.current = HostObservation{}
	return nil, nil
}
func spoofFixture(t *testing.T, outer string) domain.Link {
	t.Helper()
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	key[0] = 1
	link := domain.Link{
		ID: id, Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("10.244.62.207"), Peer: netip.MustParseAddr("10.244.62.198")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.245.62.1/32"), Peer: netip.MustParsePrefix("10.245.62.2/32")},
		Spoof: domain.SpoofOptions{Role: "creator", SourceFile: "/root/stl/spoof/sources.txt", ListenPort: 42001, PeerPort: 42002,
			BindIPv4: netip.MustParseAddr("10.244.62.207"), LocalPublicKey: base64.RawURLEncoding.EncodeToString(key),
			MaterialSHA256: strings.Repeat("a", 64), OuterProtocol: outer},
	}
	if outer == "icmp" {
		link.Encapsulation = domain.EncapNative
	}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	return link
}
func TestSpoofBackendOfflineEnsureAndExactOwnerRemove(t *testing.T) {
	for _, outer := range []string{"", "icmp"} {
		t.Run(outer, func(t *testing.T) {
			ctx := context.Background()
			link := spoofFixture(t, outer)
			host := &fixtureHost{}
			b, err := New(host)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			req := core.Request{Operation: core.OperationEnsure, Link: link}
			planned, err := b.Plan(ctx, req, observed)
			if err != nil {
				t.Fatal(err)
			}
			if planned.Empty() {
				t.Fatal("offline Link should still start original local helper")
			}
			claims := planned.Resources()
			if len(claims) != 7 {
				t.Fatalf("unexpected claim count %+v", claims)
			}
			if !slices.IsSortedFunc(claims, func(a, c domain.ResourceClaim) int { return strings.Compare(a.Canonical(), c.Canonical()) }) {
				t.Fatal("expected canonical resource ordering for Engine resource collision checks")
			}
			if err = b.Validate(ctx, req, observed, planned); err != nil {
				t.Fatalf("offline preflight forbidden unexpectedly: %v", err)
			}
			if _, err = b.Apply(ctx, req, observed, planned); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Verify(ctx, req); err != nil {
				t.Fatalf("local helper verification unexpectedly demanded peer: %v", err)
			}
			if host.starts != 1 || host.preflights != 1 {
				t.Fatalf("host did not start once %+v", host)
			}
			observed, err = b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			planned, err = b.Plan(ctx, req, observed)
			if err != nil {
				t.Fatal(err)
			}
			if !planned.Empty() {
				t.Fatal("idempotent Ensure planned a duplicate start")
			}
			prior := link
			remove := core.Request{Operation: core.OperationRemove, Link: link, Prior: &prior, OwnedResources: claims}
			planned, err = b.Plan(ctx, remove, observed)
			if err != nil {
				t.Fatal(err)
			}
			if err = b.Validate(ctx, remove, observed, planned); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Apply(ctx, remove, observed, planned); err != nil {
				t.Fatal(err)
			}
			if _, err = b.Verify(ctx, remove); err != nil {
				t.Fatal(err)
			}
			if host.stops != 1 {
				t.Fatal("original local helper not stopped exactly once")
			}
		})
	}
}
func TestSpoofBackendRejectsForeignResourceAndUncommittedRemove(t *testing.T) {
	ctx := context.Background()
	link := spoofFixture(t, "icmp")
	for _, observed := range []HostObservation{
		{UnitExists: true, UnitOwned: false},
		{InterfaceExists: true, InterfaceOwned: false},
		{InterfaceExists: true, InterfaceOwned: true, UnitExists: true, UnitOwned: true, UnitActive: false},
	} {
		host := &fixtureHost{current: observed}
		b, _ := New(host)
		got, _ := b.Inspect(ctx, link)
		req := core.Request{Operation: core.OperationEnsure, Link: link}
		p, err := b.Plan(ctx, req, got)
		if err != nil {
			t.Fatal(err)
		}
		if b.Validate(ctx, req, got, p) == nil {
			t.Fatalf("foreign/orphan host resource was silently adopted: %+v", observed)
		}
		if host.preflights != 0 {
			t.Fatal("foreign resource reached preflight")
		}
	}
	h := &fixtureHost{}
	b, _ := New(h)
	obs, _ := b.Inspect(ctx, link)
	req := core.Request{Operation: core.OperationRemove, Link: link}
	p, _ := b.Plan(ctx, req, obs)
	if b.Validate(ctx, req, obs, p) == nil {
		t.Fatal("uncommitted Spoof retirement accepted")
	}
}
func TestSpoofOuterProtocolClaimsDoNotShareWrongPortNamespace(t *testing.T) {
	udp := spoofFixture(t, "")
	icmp := udp
	icmp.Encapsulation = domain.EncapNative
	icmp.Spoof.OuterProtocol = "icmp"
	a, err := expectedClaims(udp)
	if err != nil {
		t.Fatal(err)
	}
	b, err := expectedClaims(icmp)
	if err != nil {
		t.Fatal(err)
	}
	var udpPort, icmpID bool
	for _, c := range a {
		if c.Kind == domain.ResourceUDPListenPort {
			udpPort = true
		}
	}
	for _, c := range b {
		if c.Kind == domain.ResourceBackendID && strings.HasPrefix(c.Key, "spoof/icmp-receive-id/") {
			icmpID = true
		}
		if c.Kind == domain.ResourceUDPListenPort {
			t.Fatal("ICMP profile erroneously claims ordinary UDP receive port")
		}
	}
	if !udpPort || !icmpID {
		t.Fatal("missing independent profile resource claims")
	}
}

// A reverse proxy/NAT router advertises one port but the original Link
// actually binds another. Engine claims/locks must track real listeners,
// including local alternate binds, not external paired destinations.
func TestSpoofClaimUsesLocalPostDNATPortNotAdvertisedPort(t *testing.T) {
	link := spoofFixture(t, "auto")
	link.Spoof.BindIPv4 = netip.MustParseAddr("10.10.22.3")
	link.Spoof.BindPort = 49117
	link.Spoof.BindAlternates = "10.10.22.3:49118"
	link.Spoof.LocalAlternates = "203.0.113.23:48118"
	link.Underlay.Local = netip.MustParseAddr("203.0.113.22")
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	claims, err := expectedClaims(link)
	if err != nil {
		t.Fatal(err)
	}
	has := func(kind, key string) bool {
		return slices.Contains(claims, domain.ResourceClaim{Kind: kind, Key: key})
	}
	for _, real := range []string{"49117", "49118"} {
		if !has(domain.ResourceUDPListenPort, real) ||
			!has(domain.ResourceBackendID, "spoof/icmp-receive-id/"+real) ||
			!has(domain.ResourceBackendID, "spoof/raw-receive-id/"+real) {
			t.Fatalf("real NAT receiver port %s omitted from collision/ownership claims: %+v", real, claims)
		}
	}
	for _, external := range []string{"42001", "48118"} {
		if has(domain.ResourceUDPListenPort, external) ||
			has(domain.ResourceBackendID, "spoof/icmp-receive-id/"+external) ||
			has(domain.ResourceBackendID, "spoof/raw-receive-id/"+external) {
			t.Fatalf("advertised-but-unbound port %s falsely reserved: %+v", external, claims)
		}
	}
}
