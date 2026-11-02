package l2tpv3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pairing"
)

func testLink() domain.Link {
	return domain.Link{
		ID:      "lnk_1234567890abcdef1234567890abcdef",
		Backend: domain.BackendL2TPv3, Encapsulation: domain.EncapNative,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.1"), Peer: netip.MustParseAddr("198.51.100.2")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.253.115.1/30"), Peer: netip.MustParsePrefix("10.253.115.2/30")},
	}
}
func TestIdentityPairingAndValidation(t *testing.T) {
	l := testLink()
	id, err := identityFor(l)
	if err != nil {
		t.Fatal(err)
	}
	other := pairing.Invert(l)
	peer, err := identityFor(other)
	if err != nil {
		t.Fatal(err)
	}
	if id.name != peer.name || id.tunnel != peer.peerTunnel || id.peerTunnel != peer.tunnel ||
		id.session != peer.peerSession || id.peerSession != peer.session || id.mac != peer.peerMAC || id.peerMAC != peer.mac {
		t.Fatalf("L2TP ids and MAC are not correctly reciprocal: %+v %+v", id, peer)
	}
	if len(id.name) > 15 || id.tunnel == id.session || id.peerTunnel == id.peerSession {
		t.Fatal("L2TP invalid identifiers")
	}
	if _, err := Overhead(l); err != nil {
		t.Fatal(err)
	}
	offer, err := pairing.NewQuickOffer(l, nil)
	if err != nil {
		t.Fatal(err)
	}
	url, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	copied, err := pairing.DecodeSetupLink(url)
	if err != nil {
		t.Fatal(err)
	}
	if copied.ReceiverLink() != other {
		t.Fatalf("L2TP pairing receiver differed: %#v vs %#v", copied.ReceiverLink(), other)
	}
	bad := l
	bad.Encapsulation = domain.EncapUDP
	if bad.Validate() == nil {
		t.Fatal("UDP L2TPv3 mistakenly accepted as Direct-IP")
	}
	bad = l
	bad.Addresses.Peer = netip.MustParsePrefix("10.253.116.2/30")
	if bad.Validate() == nil {
		t.Fatal("L2TPv3 disjoint peer prefix accepted")
	}
	bad = l
	bad.Addresses.Local = netip.MustParsePrefix("10.253.115.1/32")
	bad.Addresses.Peer = netip.MustParsePrefix("10.253.115.2/32")
	if bad.Validate() == nil {
		t.Fatal("L2TPv3 /32 Ethernet unicast unusable peer accepted")
	}
}

type fakeKernel struct {
	link     domain.Link
	id       identity
	tunnels  []tunnel
	sessions []session
	ifc      *iface
	addr     []netip.Prefix
	neigh    []neighbor
	fail     string
	calls    []string
}

func newFakeKernel(t *testing.T, l domain.Link) *fakeKernel {
	t.Helper()
	id, e := identityFor(l)
	if e != nil {
		t.Fatal(e)
	}
	return &fakeKernel{link: l, id: id}
}
func (h *fakeKernel) Run(_ context.Context, binary string, args ...string) (linux.CommandResult, error) {
	joined := strings.Join(args, " ")
	h.calls = append(h.calls, joined)
	if h.fail != "" && strings.Contains(joined, h.fail) {
		return linux.CommandResult{}, errors.New("injected command failure")
	}
	encode := func(v any) (linux.CommandResult, error) {
		b, _ := json.Marshal(v)
		return linux.CommandResult{Stdout: b}, nil
	}
	switch {
	case joined == "-json l2tp show tunnel":
		return encode(h.tunnels)
	case joined == "-json l2tp show session":
		return encode(h.sessions)
	case joined == "-json link show":
		if h.ifc == nil {
			return encode([]iface{})
		}
		return encode([]iface{*h.ifc})
	case strings.HasPrefix(joined, "-json address show dev "):
		if h.ifc == nil {
			return linux.CommandResult{}, errors.New("interface missing")
		}
		row := map[string]any{"ifindex": h.ifc.IfIndex, "ifname": h.ifc.IfName, "addr_info": []map[string]any{}}
		list := []map[string]any{}
		for _, a := range h.addr {
			list = append(list, map[string]any{"family": "inet", "local": a.Addr().String(), "prefixlen": a.Bits()})
		}
		row["addr_info"] = list
		return encode([]any{row})
	case strings.HasPrefix(joined, "-json neigh show dev "):
		return encode(h.neigh)
	case strings.HasPrefix(joined, "-statistics -json link show dev "):
		return encode([]map[string]any{{"ifindex": h.ifc.IfIndex, "ifname": h.ifc.IfName, "stats64": map[string]any{
			"rx": map[string]any{"packets": uint64(5), "bytes": uint64(1024), "errors": uint64(0)},
			"tx": map[string]any{"packets": uint64(7), "bytes": uint64(2048), "errors": uint64(0)},
		}}})
	case strings.HasPrefix(joined, "l2tp add tunnel "):
		h.tunnels = append(h.tunnels, tunnel{TunnelID: h.id.tunnel, PeerTunnel: h.id.peerTunnel, Encap: "IP", Local: h.link.Underlay.Local.String(), Peer: h.link.Underlay.Peer.String()})
		return linux.CommandResult{}, nil
	case strings.HasPrefix(joined, "l2tp add session "):
		h.sessions = append(h.sessions, session{TunnelID: h.id.tunnel, PeerTunnelID: h.id.peerTunnel, SessionID: h.id.session, PeerSessionID: h.id.peerSession, Interface: h.id.name})
		h.ifc = &iface{IfIndex: 123, IfName: h.id.name, Address: "de:ad:be:ef:00:00", Flags: []string{"BROADCAST"}}
		return linux.CommandResult{}, nil
	case strings.HasPrefix(joined, "l2tp del session "):
		if h.ifc == nil {
			return linux.CommandResult{}, errors.New("no session")
		}
		h.sessions = nil
		h.ifc = nil
		h.addr = nil
		h.neigh = nil
		return linux.CommandResult{}, nil
	case strings.HasPrefix(joined, "l2tp del tunnel "):
		if len(h.sessions) != 0 {
			return linux.CommandResult{}, errors.New("session still attached")
		}
		h.tunnels = nil
		return linux.CommandResult{}, nil
	case strings.HasPrefix(joined, "neigh replace "):
		h.neigh = []neighbor{{Dst: h.link.Addresses.Peer.Addr().String(), LLAddr: h.id.peerMAC, State: json.RawMessage(`["PERMANENT"]`)}}
		return linux.CommandResult{}, nil
	default:
		return linux.CommandResult{}, fmt.Errorf("unexpected kernel command %q", joined)
	}
}

type fakeRoutes struct{ source netip.Addr }

func (r fakeRoutes) Resolve(_ context.Context, _ netip.Addr) (linux.Route, error) {
	return linux.Route{Source: r.source, Device: "eth0"}, nil
}

type fakeFirewall struct{ active bool }

func (f *fakeFirewall) HasInbound(_ context.Context, _ domain.LinkID, _ linux.InboundFirewallRule) (bool, error) {
	return f.active, nil
}
func (f *fakeFirewall) HasOwnedInbound(_ context.Context, _ domain.LinkID, _ bool) (bool, error) {
	return f.active, nil
}
func (f *fakeFirewall) EnsureInboundLocked(_ context.Context, _ domain.LinkID, _ linux.InboundFirewallRule) (func(context.Context) error, bool, error) {
	old := f.active
	f.active = true
	return func(_ context.Context) error { f.active = old; return nil }, !old, nil
}
func (f *fakeFirewall) RemoveInboundLocked(_ context.Context, _ domain.LinkID, _ linux.InboundFirewallRule) (bool, error) {
	had := f.active
	f.active = false
	return had, nil
}

type fakeCollisions struct{ conflicts []linux.ObservedResource }

func (c fakeCollisions) Inspect(_ context.Context, _ []domain.ResourceClaim) ([]linux.ObservedResource, error) {
	return c.conflicts, nil
}
func testBackend(t *testing.T, l domain.Link, k *fakeKernel, fw *fakeFirewall, collision fakeCollisions) *Backend {
	t.Helper()
	b, err := New(Options{Runner: k, Routes: fakeRoutes{source: l.Underlay.Local}, Firewall: fw, Collisions: collision,
		SetAlias: func(_ context.Context, ix int, v string) error {
			if k.ifc == nil || ix != k.ifc.IfIndex {
				return fmt.Errorf("wrong alias index")
			}
			k.ifc.IfAlias = v
			return nil
		},
		SetMAC: func(_ context.Context, ix int, v string) error {
			if k.ifc == nil || ix != k.ifc.IfIndex {
				return fmt.Errorf("wrong MAC index")
			}
			k.ifc.Address = v
			return nil
		},
		AddAddress: func(_ context.Context, ix int, p netip.Prefix) error {
			if k.ifc == nil || ix != k.ifc.IfIndex {
				return fmt.Errorf("wrong address index")
			}
			k.addr = []netip.Prefix{p}
			return nil
		},
		SetUp: func(_ context.Context, ix int) error {
			if k.ifc == nil || ix != k.ifc.IfIndex {
				return fmt.Errorf("wrong up index")
			}
			k.ifc.Flags = append(k.ifc.Flags, "UP")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func exercise(t *testing.T, b *Backend, req core.Request) (core.Plan, core.Rollback, error) {
	t.Helper()
	ctx := context.Background()
	obs, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return nil, nil, err
	}
	p, err := b.Plan(ctx, req, obs)
	if err != nil {
		return nil, nil, err
	}
	if err = b.Validate(ctx, req, obs, p); err != nil {
		return p, nil, err
	}
	cb, err := b.Apply(ctx, req, obs, p)
	if err != nil {
		return p, cb, err
	}
	_, err = b.Verify(ctx, req)
	return p, cb, err
}
func TestBackendLifecycleAndOwnership(t *testing.T) {
	l := testLink()
	k := newFakeKernel(t, l)
	fw := &fakeFirewall{}
	b := testBackend(t, l, k, fw, fakeCollisions{})
	p, _, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
	if err != nil {
		t.Fatal(err)
	}
	if p.Empty() || len(p.Resources()) < 5 {
		t.Fatal("new Link has no exact resources")
	}
	if !fw.active || k.ifc == nil || k.ifc.IfAlias != "stl:"+string(l.ID) || !reflect.DeepEqual(k.addr, []netip.Prefix{l.Addresses.Local}) {
		t.Fatal("L2TP creation missing expected state")
	}
	ds, err := b.DiagnosticState(context.Background(), l)
	if err != nil || ds.RXPackets != 5 || ds.TXBytes != 2048 {
		t.Fatalf("incorrect read-only state: %+v %v", ds, err)
	}
	p2, _, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Prior: &l, Link: l, OwnedResources: p.Resources()})
	if err != nil || !p2.Empty() {
		t.Fatalf("idempotent Ensure changed backend: p=%#v err=%v", p2, err)
	}
	p3, _, err := exercise(t, b, core.Request{Operation: core.OperationRemove, Prior: &l, Link: l, OwnedResources: p.Resources()})
	if err != nil || p3.Empty() {
		t.Fatalf("Remove failed: %v", err)
	}
	if fw.active || k.ifc != nil || len(k.tunnels) != 0 || len(k.sessions) != 0 {
		t.Fatal("Remove leaked kernel or firewall resources")
	}
}
func TestForeignAndNoOwnershipCannotBeAdopted(t *testing.T) {
	l := testLink()
	k := newFakeKernel(t, l)
	k.ifc = &iface{IfIndex: 222, IfName: k.id.name, Address: k.id.mac}
	fw := &fakeFirewall{}
	b := testBackend(t, l, k, fw, fakeCollisions{})
	_, _, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
	if err == nil {
		t.Fatal("foreign interface name adopted")
	}
	if k.ifc == nil || k.ifc.IfIndex != 222 || len(k.tunnels) != 0 {
		t.Fatal("foreign resource mutated")
	}
	k.ifc = nil
	b = testBackend(t, l, k, fw, fakeCollisions{conflicts: []linux.ObservedResource{{Owner: "", Claim: domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: l.Addresses.Local.Masked().String()}}}})
	_, _, err = exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
	if err == nil || len(k.tunnels) != 0 {
		t.Fatal("overlapping address/route collision not rejected")
	}
}
func TestFailedCreateRollsBackExactResources(t *testing.T) {
	l := testLink()
	k := newFakeKernel(t, l)
	fw := &fakeFirewall{}
	b := testBackend(t, l, k, fw, fakeCollisions{})
	k.fail = "neigh replace"
	_, undo, err := exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: l})
	if err == nil || undo == nil {
		t.Fatalf("expected partial failure with undo, got %v", err)
	}
	k.fail = ""
	if err = undo(context.Background()); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if k.ifc != nil || len(k.tunnels) != 0 || len(k.sessions) != 0 || fw.active {
		t.Fatal("rollback leaked own resources")
	}
}
func TestPeerIdentityResourceConflict(t *testing.T) {
	a := testLink()
	id, err := identityFor(a)
	if err != nil {
		t.Fatal(err)
	}
	if id.tunnel == id.session || id.peerTunnel == id.peerSession {
		t.Fatal("same resource IDs")
	}
	// Simulate a different Link occupying the 32-bit host-wide tunnel ID:
	k := newFakeKernel(t, a)
	k.tunnels = []tunnel{{TunnelID: id.tunnel, PeerTunnel: id.peerTunnel, Encap: "IP", Local: a.Underlay.Local.String(), Peer: a.Underlay.Peer.String()}}
	b := testBackend(t, a, k, &fakeFirewall{}, fakeCollisions{})
	_, _, err = exercise(t, b, core.Request{Operation: core.OperationEnsure, Link: a})
	if err == nil {
		t.Fatal("existing uncommitted tunnel adopted")
	}
	if !slices.Equal(k.tunnels, []tunnel{{TunnelID: id.tunnel, PeerTunnel: id.peerTunnel, Encap: "IP", Local: a.Underlay.Local.String(), Peer: a.Underlay.Peer.String()}}) {
		t.Fatal("foreign tunnel unexpectedly modified")
	}
}
func TestDifferentLinkIDsStable(t *testing.T) {
	one := testLink()
	two := one
	two.ID = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	a, e := identityFor(one)
	if e != nil {
		t.Fatal(e)
	}
	b, e := identityFor(two)
	if e != nil {
		t.Fatal(e)
	}
	if a.tunnel == b.tunnel || a.session == b.session || a.mac == b.mac {
		t.Fatal("distinct Link ID identities unexpectedly collide")
	}
	if got := strconv.Itoa(len(one.Addresses.Peer.Addr().String())); got == "" {
		t.Fatal("unexpected empty peer")
	}
}
