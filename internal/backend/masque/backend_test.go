package masque

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func testLink() domain.Link {
	return domain.Link{
		ID:      "lnk_123456789abcdef00123456789abcdef",
		Backend: domain.BackendMASQUE, Encapsulation: domain.EncapTLS,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("2a10:ed40:9:e::2"),
			Peer:  netip.MustParseAddr("2a01:4f8:1c1b:20f8::1"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.252.99.2/32"),
			Peer:  netip.MustParsePrefix("10.252.99.1/32"),
		},
		MASQUE: domain.MASQUEOptions{Role: "dial", TCPPort: 443, TLSServerName: "masque.example.com", MaterialSHA256: strings.Repeat("a", 64)},
	}
}

type fakeHost struct {
	value     HostObservation
	ready     bool
	starts    int
	stops     int
	existing  bool
	failStart bool
}

func (f *fakeHost) Inspect(_ context.Context, link domain.Link) (HostObservation, error) {
	return f.value, nil
}
func (f *fakeHost) Preflight(_ context.Context, _ domain.Link, _ bool) error {
	if !f.ready {
		return errors.New("test credentials missing")
	}
	return nil
}
func (f *fakeHost) Start(_ context.Context, link domain.Link) (core.Rollback, error) {
	f.starts++
	f.value = HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true, InterfaceExists: true, InterfaceOwned: true,
		InterfaceIndex: 11, LocalAddress: link.Addresses.Local, PeerRoute: true, RuntimeReady: true}
	undo := func(context.Context) error { f.value = HostObservation{}; return nil }
	if f.failStart {
		return undo, errors.New("failed after service start")
	}
	return undo, nil
}
func (f *fakeHost) Stop(_ context.Context, link domain.Link) (core.Rollback, error) {
	f.stops++
	f.value = HostObservation{}
	return func(context.Context) error {
		f.value = HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true, InterfaceExists: true, InterfaceOwned: true,
			InterfaceIndex: 12, LocalAddress: link.Addresses.Local, PeerRoute: true, RuntimeReady: true}
		return nil
	}, nil
}

func TestMASQUEBackendUsesCanonicalEngineContracts(t *testing.T) {
	host := &fakeHost{ready: true}
	b, err := New(host)
	if err != nil {
		t.Fatal(err)
	}
	link := testLink()
	ctx := context.Background()
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	firstReq := core.Request{Operation: core.OperationEnsure, Link: link}
	p, err := b.Plan(ctx, firstReq, obs)
	if err != nil || p.Empty() {
		t.Fatalf("first Ensure should create only this Link: %v", err)
	}
	if err := b.Validate(ctx, firstReq, obs, p); err != nil {
		t.Fatal(err)
	}
	undo, err := b.Apply(ctx, firstReq, obs, p)
	if err != nil || undo == nil {
		t.Fatalf("missing mutation undo: %v", err)
	}
	if _, err := b.Verify(ctx, firstReq); err != nil {
		t.Fatal(err)
	}
	if host.starts != 1 {
		t.Fatalf("start count=%d", host.starts)
	}

	obs, _ = b.Inspect(ctx, link)
	claims := slices.Clone(p.Resources())
	slices.SortFunc(claims, func(a, b domain.ResourceClaim) int { return strings.Compare(a.Canonical(), b.Canonical()) })
	prior := link
	again := core.Request{Operation: core.OperationEnsure, Link: link, Prior: &prior, OwnedResources: claims}
	p2, err := b.Plan(ctx, again, obs)
	if err != nil || !p2.Empty() {
		t.Fatalf("re-ensure should be idempotent: %v", err)
	}
	if err := b.Validate(ctx, again, obs, p2); err != nil {
		t.Fatal(err)
	}
	rem := core.Request{Operation: core.OperationRemove, Link: link, Prior: &prior, OwnedResources: claims}
	p3, err := b.Plan(ctx, rem, obs)
	if err != nil || p3.Empty() {
		t.Fatalf("remove requires owned stop: %v", err)
	}
	if err := b.Validate(ctx, rem, obs, p3); err != nil {
		t.Fatal(err)
	}
	compensate, err := b.Apply(ctx, rem, obs, p3)
	if err != nil || compensate == nil {
		t.Fatalf("remove lacks compensation: %v", err)
	}
	if _, err := b.Verify(ctx, rem); err != nil {
		t.Fatal(err)
	}
	if host.stops != 1 {
		t.Fatal("selected host was not stopped")
	}
}

func TestMASQUENeverAdoptsForeignOrOldResources(t *testing.T) {
	link := testLink()
	host := &fakeHost{ready: true, value: HostObservation{UnitExists: true, UnitOwned: false, UnitActive: true, InterfaceExists: true}}
	b, _ := New(host)
	obs, _ := b.Inspect(context.Background(), link)
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	p, _ := b.Plan(context.Background(), req, obs)
	if err := b.Validate(context.Background(), req, obs, p); err == nil {
		t.Fatal("adopted foreign unit")
	}
	host.value = HostObservation{UnitExists: true, UnitOwned: true, UnitActive: true, InterfaceExists: true, InterfaceOwned: true,
		LocalAddress: link.Addresses.Local, PeerRoute: true, RuntimeReady: true}
	obs, _ = b.Inspect(context.Background(), link)
	prior := link
	req = core.Request{Operation: core.OperationRemove, Link: link, Prior: &prior}
	p, _ = b.Plan(context.Background(), req, obs)
	if err := b.Validate(context.Background(), req, obs, p); err == nil {
		t.Fatal("removed without committed owner resource claims")
	}
}

func TestMASQUEInvalidPhysicalRouteAndPortFailClosed(t *testing.T) {
	tcases := []func(*domain.Link){
		func(l *domain.Link) { l.MASQUE.Role = "other" },
		func(l *domain.Link) { l.Encapsulation = domain.EncapUDP },
		func(l *domain.Link) { l.MASQUE.TCPPort = 0 },
		func(l *domain.Link) { l.Underlay.Peer = netip.MustParseAddr("127.0.0.1") },
		func(l *domain.Link) { l.Underlay.Local = netip.MustParseAddr("10.0.0.1") },
		func(l *domain.Link) { l.Addresses.Peer = netip.MustParsePrefix("127.0.0.1/32") },
		func(l *domain.Link) { l.Addresses.Peer = netip.MustParsePrefix("10.252.99.2/32") },
		func(l *domain.Link) { l.Addresses.Peer = netip.MustParsePrefix("10.252.99.1/24") },
	}
	for i, mutate := range tcases {
		link := testLink()
		mutate(&link)
		if err := validateLink(link); err == nil {
			t.Errorf("accepted invalid MASQUE Link case %d", i)
		}
	}
}

func TestMASQUELinkClaimPortScope(t *testing.T) {
	l := testLink()
	dial, _ := expectedClaims(l)
	for _, c := range dial {
		if c.Kind == domain.ResourceTCPListenPort {
			t.Fatal("dial must not reserve a local TCP listener")
		}
	}
	l.MASQUE.Role = "listen"
	listener, _ := expectedClaims(l)
	found := false
	for _, c := range listener {
		if c.Kind == domain.ResourceTCPListenPort && c.Key == "443" {
			found = true
		}
	}
	if !found {
		t.Fatal("listen must reserve global TCP port")
	}
}
