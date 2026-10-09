package gre

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
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
		DisplayName: "gre-test",
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("198.51.100.20"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.80.20.0/31"), Peer: netip.MustParsePrefix("10.80.20.1/31"),
		},
		Backend: domain.BackendGRE, Encapsulation: domain.EncapNative,
		GRE: domain.GREOptions{
			KeyEnabled: true, Key: 0, TTL: 64, TOS: 0x10,
			DisablePMTUD: true, Checksum: true, Sequence: true,
		},
	}
}

type fakeRunner struct {
	link     domain.Link
	name     string
	state    observedLink
	extra    []observedLink
	mappings []fouMapping
	commands []string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	r.commands = append(r.commands, strings.Join(append([]string{name}, args...), " "))
	joined := strings.Join(args, " ")
	switch {
	case joined == "-details -json link show type gre":
		rows := make([]linkJSON, 0, 1+len(r.extra))
		for _, state := range append([]observedLink{r.state}, r.extra...) {
			if !state.Exists {
				continue
			}
			rows = append(rows, rowFromState(state))
		}
		raw, _ := json.Marshal(rows)
		return linux.CommandResult{Stdout: raw}, nil
	case joined == "-json fou show":
		rows := make([]map[string]any, 0, len(r.mappings))
		for _, mapping := range r.mappings {
			row := map[string]any{
				"port": mapping.Port, "family": "inet",
				"local": mapping.Local.String(), "peer": mapping.Peer.String(),
				"peer_port": mapping.PeerPort, "dev": mapping.Device,
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
		raw := fmt.Sprintf(`[{"ifname":%q,"addr_info":[%s]}]`, r.state.Name, strings.Join(items, ","))
		return linux.CommandResult{Stdout: []byte(raw)}, nil
	case strings.HasPrefix(joined, "link add "):
		if r.state.Exists {
			return linux.CommandResult{}, errors.New("name already exists")
		}
		r.state = observedLink{
			Exists: true, IfIndex: 77, Name: r.name,
			Local: r.link.Underlay.Local, Peer: r.link.Underlay.Peer,
			KeyEnabled: r.link.GRE.KeyEnabled, Key: r.link.GRE.Key,
			TTL: r.link.GRE.TTL, TOS: r.link.GRE.TOS, PMTUD: !r.link.GRE.DisablePMTUD,
			Checksum: r.link.GRE.Checksum, Sequence: r.link.GRE.Sequence,
			Encapsulation: r.link.Encapsulation, UDPPort: r.link.GRE.UDPPort,
		}
		return linux.CommandResult{}, nil
	case strings.HasPrefix(joined, "address add "):
		r.state.IPv4Addresses = []netip.Prefix{r.link.Addresses.Local}
		return linux.CommandResult{}, nil
	case joined == "link set dev "+r.name+" up":
		r.state.Up = true
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
		port := r.link.GRE.UDPPort
		r.mappings = slices.DeleteFunc(r.mappings, func(m fouMapping) bool { return m.Port == port })
		return linux.CommandResult{}, nil
	default:
		return linux.CommandResult{}, fmt.Errorf("unexpected command: %s", joined)
	}
}

func rowFromState(s observedLink) linkJSON {
	var row linkJSON
	row.IfIndex, row.IfName = s.IfIndex, s.Name
	if s.Owner != "" {
		row.IfAlias, _ = linux.OwnerTag(s.Owner)
	}
	if s.Up {
		row.Flags = []string{"POINTOPOINT", "NOARP", "UP"}
	} else {
		row.Flags = []string{"POINTOPOINT", "NOARP"}
	}
	row.LinkInfo.InfoKind = "gre"
	row.LinkInfo.InfoData.Local, row.LinkInfo.InfoData.Remote = s.Local.String(), s.Peer.String()
	row.LinkInfo.InfoData.TTL = s.TTL
	if s.TOS != 0 {
		row.LinkInfo.InfoData.TOS = fmt.Sprintf("0x%02x", s.TOS)
	}
	pmtud := s.PMTUD
	row.LinkInfo.InfoData.PMTUD = &pmtud
	if s.KeyEnabled {
		key := netip.AddrFrom4([4]byte{byte(s.Key >> 24), byte(s.Key >> 16), byte(s.Key >> 8), byte(s.Key)})
		row.LinkInfo.InfoData.IKey, row.LinkInfo.InfoData.OKey = key.String(), key.String()
	}
	row.LinkInfo.InfoData.ICsum, row.LinkInfo.InfoData.OCsum = s.Checksum, s.Checksum
	row.LinkInfo.InfoData.ISeq, row.LinkInfo.InfoData.OSeq = s.Sequence, s.Sequence
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
}

func (f *fakeFirewall) HasInbound(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error) {
	return f.present, nil
}
func (f *fakeFirewall) HasOwnedInbound(context.Context, domain.LinkID, bool) (bool, error) {
	return f.present, nil
}
func (f *fakeFirewall) EnsureInbound(context.Context, domain.LinkID, linux.InboundFirewallRule) (func(context.Context) error, bool, error) {
	if f.failEnsure {
		return nil, false, errors.New("firewall add failed")
	}
	was := f.present
	f.present = true
	return func(context.Context) error { f.present = was; return nil }, !was, nil
}
func (f *fakeFirewall) RemoveInbound(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error) {
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
			runner.state.Owner = owner
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

func TestNativeGRELifecycleIsIdempotentAndOwned(t *testing.T) {
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
		t.Fatal("absent GRE Link produced empty create plan")
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

	obs, err = b.Inspect(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, second); err != nil {
		t.Fatal(err)
	}
	if !second.Empty() {
		t.Fatal("exact reapply was not idempotent")
	}

	createCommand := ""
	for _, command := range runner.commands {
		if strings.Contains(command, " link add ") {
			createCommand = command
			break
		}
	}
	for _, fragment := range []string{"key 0", "ttl 64", "tos 0x10", "nopmtudisc", "icsum ocsum", "iseq oseq"} {
		if !strings.Contains(createCommand, fragment) {
			t.Fatalf("create argv missing %q: %q", fragment, createCommand)
		}
	}
	resources := candidate.Resources()
	if !slices.ContainsFunc(resources, func(c domain.ResourceClaim) bool {
		return c.Kind == domain.ResourceBackendID && strings.Contains(c.Key, "key=0")
	}) {
		t.Fatalf("keyed GRE identity missing from resources: %#v", resources)
	}

	remove := core.Request{Operation: core.OperationRemove, Prior: &link, Link: link, OwnedResources: resources}
	obs, _ = b.Inspect(ctx, link)
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
		t.Fatal("owned GRE state remained after remove")
	}
}

func TestNativeGREApplyFailureRollsBackCreatedInterface(t *testing.T) {
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
		t.Fatal("created GRE interface survived rollback")
	}
}

func TestNativeGRERejectsForeignOwnershipAndDuplicateTuple(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	foreign := observedLink{Exists: true, IfIndex: 88, Name: name, Owner: domain.LinkID("lnk_22222222222222222222222222222222"), Up: true, Local: link.Underlay.Local, Peer: link.Underlay.Peer, KeyEnabled: true, Key: 0, TTL: 64, TOS: 0x10, PMTUD: false, Checksum: true, Sequence: true, IPv4Addresses: []netip.Prefix{link.Addresses.Local}}
	runner := &fakeRunner{link: link, name: name, state: foreign}
	b := newTestBackend(t, runner, &fakeFirewall{present: true}, fakeCollisions{})
	ctx := context.Background()
	req := core.Request{Operation: core.OperationEnsure, Link: link}
	obs, _ := b.Inspect(ctx, link)
	candidate, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, candidate); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("foreign owner accepted: %v", err)
	}

	runner.state = observedLink{}
	runner.extra = []observedLink{{Exists: true, IfIndex: 89, Name: "other", Local: link.Underlay.Local, Peer: link.Underlay.Peer, KeyEnabled: true, Key: 0, PMTUD: true}}
	obs, _ = b.Inspect(ctx, link)
	candidate, err = b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, candidate); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("duplicate GRE tuple accepted: %v", err)
	}

	runner.extra[0].Key = 1
	obs, _ = b.Inspect(ctx, link)
	candidate, err = b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, candidate); err != nil {
		t.Fatalf("distinct GRE key was incorrectly rejected: %v", err)
	}
}

func TestParseKernelGREJSONPreservesExplicitZeroKey(t *testing.T) {
	raw := []byte(`[{"ifindex":5,"ifname":"g0","flags":["POINTOPOINT","NOARP"],"linkinfo":{"info_kind":"gre","info_data":{"remote":"198.51.100.1","local":"192.0.2.1","ttl":0,"pmtudisc":true,"ikey":"0.0.0.0","okey":"0.0.0.0"}}}]`)
	links, err := parseGRELinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || !links[0].KeyEnabled || links[0].Key != 0 {
		t.Fatalf("kernel key-zero identity lost: %#v", links)
	}
	link := testLink()
	link.GRE = domain.GREOptions{KeyEnabled: true, Key: 0}
	if got, err := Overhead(link); err != nil || got != 28 {
		t.Fatalf("keyed GRE overhead=%d err=%v, want 28", got, err)
	}
}

func TestFOUAndGUELifecycleUseOwnedSymmetricUDPMapping(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapFOU, domain.EncapGUE} {
		t.Run(string(encap), func(t *testing.T) {
			link := testLink()
			link.Encapsulation = encap
			link.GRE.UDPPort = 5555
			name, _ := InterfaceName(link.ID)
			runner := &fakeRunner{link: link, name: name}
			// A Native GRE with the same endpoints/key remains distinguishable.
			runner.extra = []observedLink{{
				Exists: true, IfIndex: 90, Name: "native-peer", Local: link.Underlay.Local, Peer: link.Underlay.Peer,
				KeyEnabled: link.GRE.KeyEnabled, Key: link.GRE.Key, PMTUD: true, Encapsulation: domain.EncapNative,
			}}
			firewall := &fakeFirewall{}
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
			if len(runner.mappings) != 1 || runner.mappings[0].Port != 5555 || runner.mappings[0].Encapsulation != encap {
				t.Fatalf("unexpected receive mapping: %#v", runner.mappings)
			}

			resources := candidate.Resources()
			req.OwnedResources = resources
			obs, _ = b.Inspect(ctx, link)
			second, err := b.Plan(ctx, req, obs)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Validate(ctx, req, obs, second); err != nil {
				t.Fatal(err)
			}
			if !second.Empty() {
				t.Fatal("exact UDP-encapsulated GRE reapply was not idempotent")
			}

			joined := strings.Join(runner.commands, "\n")
			kind := "gue"
			if encap == domain.EncapFOU {
				kind = "ipproto 47"
			}
			if !strings.Contains(joined, "ip fou add port 5555 "+kind+" local 192.0.2.10 peer 198.51.100.20 peer_port 5555 dev eth0") {
				t.Fatalf("missing exact receive mapping command:\n%s", joined)
			}
			if !strings.Contains(joined, "encap "+string(encap)+" encap-sport 5555 encap-dport 5555") {
				t.Fatalf("missing fixed GRE UDP encapsulation ports:\n%s", joined)
			}
			wantOverhead := 44
			if encap == domain.EncapGUE {
				wantOverhead = 48
			}
			if got, err := Overhead(link); err != nil || got != wantOverhead {
				t.Fatalf("%s overhead=%d err=%v want=%d", encap, got, err, wantOverhead)
			}

			remove := core.Request{Operation: core.OperationRemove, Prior: &link, Link: link, OwnedResources: resources}
			obs, _ = b.Inspect(ctx, link)
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
				t.Fatal("FOU/GUE owned state remained after remove")
			}
		})
	}
}

func TestFOURejectsForeignReceivePortMapping(t *testing.T) {
	link := testLink()
	link.Encapsulation, link.GRE.UDPPort = domain.EncapFOU, 5555
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name, mappings: []fouMapping{{
		Port: 5555, Encapsulation: domain.EncapGUE, Local: link.Underlay.Local,
		Peer: link.Underlay.Peer, PeerPort: 5555, Device: "eth0",
	}}}
	b := newTestBackend(t, runner, &fakeFirewall{}, fakeCollisions{})
	obs, err := b.Inspect(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Plan(context.Background(), core.Request{Operation: core.OperationEnsure, Link: link}, obs)
	if stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("foreign receive-port mapping accepted: %v", err)
	}
}
