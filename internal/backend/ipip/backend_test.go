package ipip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

var testID = domain.LinkID("lnk_11111111111111111111111111111111")

func testLink() domain.Link {
	return domain.Link{
		ID:          testID,
		DisplayName: "ipip-test",
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("198.51.100.20"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.80.20.0/31"), Peer: netip.MustParsePrefix("10.80.20.1/31"),
		},
		Backend: domain.BackendIPIP, Encapsulation: domain.EncapNative,
	}
}

type fakeRunner struct {
	link                 domain.Link
	name                 string
	state                observedLink
	extra                []observedLink
	mappings             []fouMapping
	commands             []string
	addressIndexOverride int
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	r.commands = append(r.commands, strings.Join(append([]string{name}, args...), " "))
	joined := strings.Join(args, " ")
	switch {
	case joined == "-details -json link show type ipip":
		rows := make([]linkJSON, 0, 1+len(r.extra))
		for _, state := range append([]observedLink{r.state}, r.extra...) {
			if state.Exists {
				rows = append(rows, rowFromState(state))
			}
		}
		raw, _ := json.Marshal(rows)
		return linux.CommandResult{Stdout: raw}, nil
	case joined == "-json fou show":
		rows := make([]map[string]any, 0, len(r.mappings))
		for _, mapping := range r.mappings {
			row := map[string]any{
				"port": mapping.Port, "family": "inet", "local": mapping.Local.String(),
				"peer": mapping.Peer.String(), "peer_port": mapping.PeerPort, "dev": mapping.Device,
			}
			if mapping.Encapsulation == domain.EncapGUE {
				row["gue"] = nil
			} else {
				row["ipproto"] = mapping.IPProto
			}
			rows = append(rows, row)
		}
		raw, _ := json.Marshal(rows)
		return linux.CommandResult{Stdout: raw}, nil
	case strings.HasPrefix(joined, "-json address show dev "):
		if !r.state.Exists {
			return linux.CommandResult{}, errors.New("interface not found")
		}
		items := make([]string, 0, len(r.state.IPv4Addresses))
		for _, prefix := range r.state.IPv4Addresses {
			items = append(items, fmt.Sprintf(`{"family":"inet","local":%q,"prefixlen":%d}`, prefix.Addr().String(), prefix.Bits()))
		}
		index := r.state.IfIndex
		if r.addressIndexOverride != 0 {
			index = r.addressIndexOverride
		}
		raw := fmt.Sprintf(`[{"ifindex":%d,"ifname":%q,"addr_info":[%s]}]`, index, r.state.Name, strings.Join(items, ","))
		return linux.CommandResult{Stdout: []byte(raw)}, nil
	case strings.HasPrefix(joined, "link add "):
		if r.state.Exists {
			return linux.CommandResult{}, errors.New("name already exists")
		}
		port, _ := UDPPort(r.link)
		r.state = observedLink{
			Exists: true, IfIndex: 77, Name: r.name, Local: r.link.Underlay.Local, Peer: r.link.Underlay.Peer,
			Encapsulation: r.link.Encapsulation, UDPPort: port,
		}
		return linux.CommandResult{}, nil
	case strings.HasPrefix(joined, "fou add port "):
		mapping, _ := desiredFOUMapping(r.link, linux.Route{Peer: r.link.Underlay.Peer, Source: r.link.Underlay.Local, Device: "eth0"})
		for _, existing := range r.mappings {
			if existing.Port == mapping.Port {
				return linux.CommandResult{}, errors.New("port already exists")
			}
		}
		r.mappings = append(r.mappings, mapping)
		return linux.CommandResult{}, nil
	case strings.HasPrefix(joined, "fou del port "):
		port, _ := UDPPort(r.link)
		r.mappings = slices.DeleteFunc(r.mappings, func(m fouMapping) bool { return m.Port == port })
		return linux.CommandResult{}, nil
	default:
		return linux.CommandResult{}, fmt.Errorf("unexpected command: %s", joined)
	}
}

func rowFromState(s observedLink) linkJSON {
	var row linkJSON
	row.IfIndex, row.IfName, row.IfAlias = s.IfIndex, s.Name, s.Alias
	if row.IfAlias == "" && s.Owner != "" {
		row.IfAlias, _ = linux.OwnerTag(s.Owner)
	}
	if s.Up {
		row.Flags = []string{"POINTOPOINT", "NOARP", "UP"}
	} else {
		row.Flags = []string{"POINTOPOINT", "NOARP"}
	}
	row.LinkInfo.InfoKind = "ipip"
	row.LinkInfo.InfoData.Local, row.LinkInfo.InfoData.Remote = s.Local.String(), s.Peer.String()
	if s.Encapsulation == domain.EncapFOU || s.Encapsulation == domain.EncapGUE {
		row.LinkInfo.InfoData.Encap = &encapJSON{Type: string(s.Encapsulation), Sport: s.UDPPort, Dport: s.UDPPort}
	}
	return row
}

type fakeRoute struct{ route linux.Route }

func (r fakeRoute) Resolve(context.Context, netip.Addr) (linux.Route, error) { return r.route, nil }

type fakeFirewall struct {
	present    bool
	failEnsure bool
	lastRule   linux.InboundFirewallRule
}

func (f *fakeFirewall) HasInbound(_ context.Context, _ domain.LinkID, rule linux.InboundFirewallRule) (bool, error) {
	f.lastRule = rule
	return f.present, nil
}
func (f *fakeFirewall) HasOwnedInbound(context.Context, domain.LinkID, bool) (bool, error) {
	return f.present, nil
}
func (f *fakeFirewall) EnsureInboundLocked(_ context.Context, _ domain.LinkID, rule linux.InboundFirewallRule) (func(context.Context) error, bool, error) {
	f.lastRule = rule
	if f.failEnsure {
		return nil, false, errors.New("firewall add failed")
	}
	was := f.present
	f.present = true
	return func(context.Context) error { f.present = was; return nil }, !was, nil
}
func (f *fakeFirewall) RemoveInboundLocked(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error) {
	was := f.present
	f.present = false
	return was, nil
}

type fakeCollisions struct{ items []linux.ObservedResource }

func (c fakeCollisions) Inspect(context.Context, []domain.ResourceClaim) ([]linux.ObservedResource, error) {
	return c.items, nil
}

func newTestBackend(t *testing.T, runner *fakeRunner, firewall *fakeFirewall, collisions fakeCollisions) *Backend {
	t.Helper()
	link := runner.link
	b, err := New(Options{
		Runner:   runner,
		Routes:   fakeRoute{linux.Route{Peer: link.Underlay.Peer, Source: link.Underlay.Local, Device: "eth0"}},
		Firewall: firewall, Collisions: collisions,
		LookupIndex: func(string) (int, error) { return 77, nil },
		SetAlias: func(_ context.Context, index int, alias string) error {
			if index != 77 {
				return fmt.Errorf("wrong index %d", index)
			}
			owner, ok := linux.ParseOwnerTag(alias)
			if !ok {
				return errors.New("bad owner alias")
			}
			runner.state.Owner, runner.state.Alias = owner, alias
			return nil
		},
		AddAddress: func(_ context.Context, index int, prefix netip.Prefix) error {
			if index != 77 {
				return fmt.Errorf("wrong index %d", index)
			}
			runner.state.IPv4Addresses = []netip.Prefix{prefix}
			return nil
		},
		SetUp: func(_ context.Context, index int) error {
			if index != 77 {
				return fmt.Errorf("wrong index %d", index)
			}
			runner.state.Up = true
			return nil
		},
		DeleteLink: func(_ context.Context, index int) error {
			if index != 77 {
				return fmt.Errorf("wrong index %d", index)
			}
			runner.state = observedLink{}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIPIPUDPPortIsStableSymmetricAndCollisionVisible(t *testing.T) {
	link := testLink()
	link.Encapsulation = domain.EncapFOU
	port, err := UDPPort(link)
	if err != nil || int(port) < ipipUDPPortBase || int(port) >= ipipUDPPortBase+ipipUDPPortSpan {
		t.Fatalf("derived port out of range: %d %v", port, err)
	}
	inverse := link
	inverse.Underlay.Local, inverse.Underlay.Peer = link.Underlay.Peer, link.Underlay.Local
	inverse.Addresses.Local, inverse.Addresses.Peer = link.Addresses.Peer, link.Addresses.Local
	peerPort, err := UDPPort(inverse)
	if err != nil || peerPort != port {
		t.Fatalf("peer did not derive same port: %d %d %v", port, peerPort, err)
	}
	other := link
	other.ID = "lnk_22221111111111111111111111111111"
	otherPort, err := UDPPort(other)
	if err != nil || otherPort == port {
		t.Fatalf("representative independent Link did not get distinct port: %d %d %v", port, otherPort, err)
	}
	claims := commonCollisionClaims(link, "x")
	if !slices.ContainsFunc(claims, func(c domain.ResourceClaim) bool {
		return c.Kind == domain.ResourceUDPListenPort && c.Key == strconv.Itoa(int(port))
	}) {
		t.Fatalf("derived UDP port is not collision-claimed: %#v", claims)
	}
}

func TestNativeIPIPLifecycleIsIdempotentOwnedAndUsesProtocol4(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner, firewall := &fakeRunner{link: link, name: name}, &fakeFirewall{}
	b := newTestBackend(t, runner, firewall, fakeCollisions{})
	ctx := context.Background()
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, err := b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Empty() {
		t.Fatal("absent IPIP Link produced empty create plan")
	}
	if err := b.Validate(ctx, req, obs, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Apply(ctx, req, obs, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(ctx, req); err != nil {
		t.Fatal(err)
	}
	if firewall.lastRule.Protocol != ipipProtocol || firewall.lastRule.DestinationPort != 0 {
		t.Fatalf("native firewall rule wrong: %+v", firewall.lastRule)
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "ip link add "+name+" type ipip local 192.0.2.10 remote 198.51.100.20 mode ipip") || strings.Contains(joined, " encap ") {
		t.Fatalf("unexpected Native IPIP argv:\n%s", joined)
	}
	if got, err := Overhead(link); err != nil || got != 20 {
		t.Fatalf("native overhead=%d err=%v want=20", got, err)
	}
	resources := candidate.Resources()
	if !slices.ContainsFunc(resources, func(c domain.ResourceClaim) bool {
		return c.Kind == domain.ResourceBackendID && strings.Contains(c.Key, "ipip/native/")
	}) {
		t.Fatalf("IPIP backend identity missing from resources: %#v", resources)
	}

	obs, _ = b.Inspect(ctx, link)
	second, err := b.Plan(ctx, core.Request{Operation: core.OperationEnsure, Prior: &link, Link: link, OwnedResources: resources}, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, core.Request{Operation: core.OperationEnsure, Prior: &link, Link: link, OwnedResources: resources}, obs, second); err != nil {
		t.Fatal(err)
	}
	if !second.Empty() {
		t.Fatal("exact IPIP reapply was not idempotent")
	}

	remove := core.Request{Operation: core.OperationRemove, Prior: &link, Link: link, OwnedResources: resources}
	removePlan, err := b.Plan(ctx, remove, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, remove, obs, removePlan); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Apply(ctx, remove, obs, removePlan); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Verify(ctx, remove); err != nil {
		t.Fatal(err)
	}
	if runner.state.Exists || firewall.present {
		t.Fatal("owned IPIP state remained after remove")
	}
}

func TestIPIPFOUAndGUELifecycleUsesDerivedOwnedPort(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapFOU, domain.EncapGUE} {
		t.Run(string(encap), func(t *testing.T) {
			link := testLink()
			link.Encapsulation = encap
			port, _ := UDPPort(link)
			name, _ := InterfaceName(link.ID)
			runner, firewall := &fakeRunner{link: link, name: name}, &fakeFirewall{}
			b := newTestBackend(t, runner, firewall, fakeCollisions{})
			ctx := context.Background()
			req := core.Request{Operation: core.OperationEnsure, Link: link}
			obs, err := b.Inspect(ctx, link)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Validate(ctx, req, obs, candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Apply(ctx, req, obs, candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Verify(ctx, req); err != nil {
				t.Fatal(err)
			}
			if firewall.lastRule.Protocol != 17 || firewall.lastRule.DestinationPort != port {
				t.Fatalf("UDP firewall rule wrong: %+v want port %d", firewall.lastRule, port)
			}
			if len(runner.mappings) != 1 || runner.mappings[0].Port != port || runner.mappings[0].PeerPort != port || runner.mappings[0].Encapsulation != encap {
				t.Fatalf("unexpected receive mapping: %#v", runner.mappings)
			}
			if encap == domain.EncapFOU && runner.mappings[0].IPProto != ipipProtocol {
				t.Fatalf("FOU protocol=%d want %d", runner.mappings[0].IPProto, ipipProtocol)
			}
			joined := strings.Join(runner.commands, "\n")
			portText := strconv.Itoa(int(port))
			kind := "gue"
			if encap == domain.EncapFOU {
				kind = "ipproto 4"
			}
			if !strings.Contains(joined, "ip fou add port "+portText+" "+kind+" local 192.0.2.10 peer 198.51.100.20 peer_port "+portText+" dev eth0") {
				t.Fatalf("missing exact receive mapping command:\n%s", joined)
			}
			if !strings.Contains(joined, "encap "+string(encap)+" encap-sport "+portText+" encap-dport "+portText) {
				t.Fatalf("missing symmetric IPIP UDP encapsulation ports:\n%s", joined)
			}
			wantOverhead := 28
			if encap == domain.EncapGUE {
				wantOverhead = 32
			}
			if got, err := Overhead(link); err != nil || got != wantOverhead {
				t.Fatalf("%s overhead=%d err=%v want=%d", encap, got, err, wantOverhead)
			}

			resources := candidate.Resources()
			obs, _ = b.Inspect(ctx, link)
			secondReq := core.Request{Operation: core.OperationEnsure, Prior: &link, Link: link, OwnedResources: resources}
			second, err := b.Plan(ctx, secondReq, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Validate(ctx, secondReq, obs, second); err != nil {
				t.Fatal(err)
			}
			if !second.Empty() {
				t.Fatal("exact UDP-encapsulated IPIP reapply was not idempotent")
			}

			remove := core.Request{Operation: core.OperationRemove, Prior: &link, Link: link, OwnedResources: resources}
			removePlan, err := b.Plan(ctx, remove, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Validate(ctx, remove, obs, removePlan); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Apply(ctx, remove, obs, removePlan); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Verify(ctx, remove); err != nil {
				t.Fatal(err)
			}
			if len(runner.mappings) != 0 || runner.state.Exists || firewall.present {
				t.Fatal("IPIP FOU/GUE owned state remained after remove")
			}
		})
	}
}

func TestIPIPRejectsDuplicateIdentityAndForeignReceivePort(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name, extra: []observedLink{{
		Exists: true, IfIndex: 89, Name: "other", Local: link.Underlay.Local, Peer: link.Underlay.Peer, Encapsulation: domain.EncapNative,
	}}}
	b := newTestBackend(t, runner, &fakeFirewall{}, fakeCollisions{})
	ctx := context.Background()
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, _ := b.Inspect(ctx, link)
	candidate, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, candidate); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("duplicate Native IPIP identity accepted: %v", err)
	}

	link.Encapsulation = domain.EncapFOU
	runner.link, runner.extra = link, nil
	port, _ := UDPPort(link)
	runner.mappings = []fouMapping{{
		Port: port, Encapsulation: domain.EncapGUE, Local: link.Underlay.Local,
		Peer: link.Underlay.Peer, PeerPort: port, Device: "eth0",
	}}
	obs, err = b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Plan(ctx, core.Request{Operation: core.OperationEnsure, Link: link}, obs); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("foreign derived receive-port mapping accepted: %v", err)
	}
}

func TestIPIPApplyFailureRollsBackOnlyProvablyOwnedState(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name}
	firewall := &fakeFirewall{failEnsure: true}
	b := newTestBackend(t, runner, firewall, fakeCollisions{})
	ctx := context.Background()
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, _ := b.Inspect(ctx, link)
	candidate, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, candidate); err != nil {
		t.Fatal(err)
	}
	undo, err := b.Apply(ctx, req, obs, candidate)
	if err == nil || undo == nil {
		t.Fatalf("firewall failure did not return rollback: %v", err)
	}
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.state.Exists {
		t.Fatal("provably owned created IPIP interface survived rollback")
	}

	// Re-run and add independent address state after the failed operation.
	runner.state = observedLink{}
	obs, _ = b.Inspect(ctx, link)
	candidate, _ = b.Plan(ctx, req, obs)
	undo, err = b.Apply(ctx, req, obs, candidate)
	if err == nil || undo == nil {
		t.Fatalf("second firewall failure did not return rollback: %v", err)
	}
	runner.state.IPv4Addresses = append(runner.state.IPv4Addresses, netip.MustParsePrefix("10.99.0.1/32"))
	if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
		t.Fatalf("rollback did not fail closed after address drift: %v", err)
	}
	if !runner.state.Exists {
		t.Fatal("changed IPIP state was destructively removed")
	}
}

func TestIPIPLookupFailurePreservesUnindexedCreatedInterface(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name}
	b, err := New(Options{
		Runner:   runner,
		Routes:   fakeRoute{linux.Route{Peer: link.Underlay.Peer, Source: link.Underlay.Local, Device: "eth0"}},
		Firewall: &fakeFirewall{}, Collisions: fakeCollisions{},
		LookupIndex: func(string) (int, error) { return 0, errors.New("lookup failed") },
		SetAlias: func(context.Context, int, string) error {
			t.Fatal("alias must not run without resolved ifindex")
			return nil
		},
		DeleteLink: func(_ context.Context, index int) error {
			t.Fatalf("unindexed interface must not be destructively deleted by ifindex %d", index)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, _ := b.Inspect(ctx, link)
	candidate, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, candidate); err != nil {
		t.Fatal(err)
	}
	undo, err := b.Apply(ctx, req, obs, candidate)
	if err == nil || undo == nil {
		t.Fatalf("lookup failure did not return rollback: %v", err)
	}
	if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
		t.Fatalf("unindexed rollback did not fail closed: %v", err)
	}
	if !runner.state.Exists {
		t.Fatal("unindexed created interface was destructively removed")
	}
}

func TestParseIPIPKernelStateRejectsAmbiguousIdentity(t *testing.T) {
	raw := []byte(`[
		{"ifindex":1,"ifname":"tunl0","flags":[],"linkinfo":{"info_kind":"ipip","info_data":{"remote":"any","local":"any"}}},
		{"ifindex":5,"ifname":"sti111111111111","flags":["UP"],"linkinfo":{"info_kind":"ipip","info_data":{"remote":"198.51.100.20","local":"192.0.2.10","encap":{"type":"fou","sport":50000,"dport":50000}}}}
	]`)
	links, err := parseIPIPLinks(raw)
	if err != nil || len(links) != 1 || links[0].Encapsulation != domain.EncapFOU || links[0].UDPPort != 50000 {
		t.Fatalf("valid IPIP observation not parsed safely: %#v %v", links, err)
	}
	bad := []byte(`[{"ifindex":5,"ifname":"x","flags":[],"linkinfo":{"info_kind":"ipip","info_data":{"remote":"198.51.100.20","local":"192.0.2.10","encap":{"type":"fou","sport":50000,"dport":50001}}}}]`)
	if _, err := parseIPIPLinks(bad); err == nil {
		t.Fatal("asymmetric inspected UDP ports were accepted")
	}
}
