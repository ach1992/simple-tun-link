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
	"github.com/ach1992/simple-tun-link/internal/state"
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
			Checksum: true, Sequence: true,
		},
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
	row.IfIndex, row.IfName, row.IfAlias = s.IfIndex, s.Name, s.Alias
	if row.IfAlias == "" && s.Owner != "" {
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
func (f *fakeFirewall) EnsureInboundLocked(context.Context, domain.LinkID, linux.InboundFirewallRule) (func(context.Context) error, bool, error) {
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
			runner.state.Owner = owner
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
	for _, fragment := range []string{"key 0", "ttl 64", "tos 0x10", "icsum ocsum", "iseq oseq"} {
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

	// Linux GRE receive lookup also collides when encapsulation/UDP port
	// differ but underlay endpoints and GRE key identity are identical.
	runner.extra[0].Encapsulation = domain.EncapFOU
	runner.extra[0].UDPPort = 33061
	obs, _ = b.Inspect(ctx, link)
	candidate, err = b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(ctx, req, obs, candidate); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("cross-encap duplicate receive identity accepted: %v", err)
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

func TestGRELegacyRemoveSerializesCrossEncapsulationEnsure(t *testing.T) {
	legacy := testLink()
	name, err := InterfaceName(legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	observedState := observedLink{
		Exists: true, IfIndex: 77, Name: name, Owner: legacy.ID,
		Local: legacy.Underlay.Local, Peer: legacy.Underlay.Peer,
		KeyEnabled: legacy.GRE.KeyEnabled, Key: legacy.GRE.Key,
		TTL: legacy.GRE.TTL, TOS: legacy.GRE.TOS,
		PMTUD:    !legacy.GRE.DisablePMTUD,
		Checksum: legacy.GRE.Checksum, Sequence: legacy.GRE.Sequence,
		Encapsulation: legacy.Encapsulation, Up: true,
		IPv4Addresses: []netip.Prefix{legacy.Addresses.Local},
	}
	runner := &fakeRunner{link: legacy, name: name, state: observedState}
	b := newTestBackend(t, runner, &fakeFirewall{present: true}, fakeCollisions{})
	ctx := context.Background()
	req := core.Request{Operation: core.OperationRemove, Prior: &legacy, Link: legacy}
	obs, err := b.Inspect(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := b.Plan(ctx, req, obs)
	if err != nil {
		t.Fatal(err)
	}
	fwClaim, err := linux.InboundFirewallClaim(legacy.ID, candidate.(plan).firewallRule)
	if err != nil {
		t.Fatal(err)
	}
	// Exact persisted claims from before the gre/rx claim was introduced.
	legacyOwned := slices.DeleteFunc(desiredResources(legacy, name, fwClaim), func(c domain.ResourceClaim) bool {
		return c == greReceiveClaim(legacy)
	})
	shared := greReceiveClaim(legacy)
	if slices.Contains(legacyOwned, shared) || !slices.Contains(candidate.Resources(), shared) {
		t.Fatal("legacy ownership unexpectedly includes gre/rx or Remove failed to lock gre/rx")
	}
	req.OwnedResources = legacyOwned
	if err := b.Validate(ctx, req, obs, candidate); err != nil {
		t.Fatalf("valid legacy-owned Remove was rejected: %v", err)
	}
	// A lock-only claim must not grant destructive ownership.
	forged := req
	forged.OwnedResources = nil
	if err := b.Validate(ctx, forged, obs, candidate); err == nil {
		t.Fatal("new synchronization claim bypassed legacy ownership checks")
	}

	competitor := legacy
	competitor.ID = domain.LinkID("lnk_22222222222222222222222222222222")
	competitor.Encapsulation = domain.EncapFOU
	competitor.GRE.UDPPort = 33061
	competitor.Addresses = domain.LinkAddresses{
		Local: netip.MustParsePrefix("10.80.21.0/31"),
		Peer:  netip.MustParsePrefix("10.80.21.1/31"),
	}
	competitorName, err := InterfaceName(competitor.ID)
	if err != nil {
		t.Fatal(err)
	}
	competitorClaims := desiredResources(competitor, competitorName, fwClaim)
	if !slices.Contains(competitorClaims, shared) {
		t.Fatal("competing cross-encapsulation Ensure did not claim the common receive lock")
	}
	// Match Engine's resourceLockClaims(prior.OwnedResources, plan.Resources())
	// with a legacy record: the two operations must contend in real file locks.
	manager := state.NewLockManager(t.TempDir())
	removeLocks := append(append([]domain.ResourceClaim(nil), legacyOwned...), candidate.Resources()...)
	release, err := manager.Acquire(ctx, removeLocks)
	if err != nil {
		t.Fatal(err)
	}
	// The file-lock implementation only observes a canceled context when
	// an actual claim blocks. This discriminates shared-lock contention
	// without introducing timing or a sleeping/stress test.
	waitCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = manager.Acquire(waitCtx, competitorClaims)
	if !errors.Is(err, context.Canceled) {
		_ = release()
		t.Fatalf("FOU Ensure did not wait for legacy GRE Remove: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	release, err = manager.Acquire(ctx, competitorClaims)
	if err != nil {
		t.Fatalf("competing FOU Ensure cannot resume after Remove releases locks: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestGREReceiveClaimCrossEncapsulationLocking(t *testing.T) {
	link := testLink()
	link.GRE = domain.GREOptions{}
	fou := link
	fou.Encapsulation = domain.EncapFOU
	fou.GRE.UDPPort = 33061
	firewall := domain.ResourceClaim{Kind: domain.ResourceFirewall, Key: "test"}
	receive := domain.ResourceClaim{Kind: domain.ResourceBackendID,
		Key: greReceiveIdentity(link.Underlay.Local, link.Underlay.Peer, false, 0)}
	if !slices.Contains(desiredResources(link, "stl-native", firewall), receive) ||
		!slices.Contains(desiredResources(fou, "stl-fou", firewall), receive) {
		t.Fatal("same underlay/unkeyed GRE receives do not share a serialization/conflict claim")
	}
	fou.GRE.KeyEnabled, fou.GRE.Key = true, 33061
	if slices.Contains(desiredResources(fou, "stl-fou", firewall), receive) {
		t.Fatal("distinct keyed GRE receive identity collides with unkeyed Native")
	}
}

func TestParseGREIPRouteEmptyPlaceholders(t *testing.T) {
	// iproute2 6.15 emits {} for non-GRE interfaces when no GRE module/link
	// has been created yet. This must not prevent the first Native ensure.
	valid := `{"ifindex":5,"ifname":"g0","flags":["POINTOPOINT","NOARP"],"linkinfo":{"info_kind":"gre","info_data":{"remote":"198.51.100.1","local":"192.0.2.1","ttl":0,"pmtudisc":true}}}`
	rows, err := parseGRELinks([]byte("[{}, { }, " + valid + ", {}]"))
	if err != nil {
		t.Fatalf("empty iproute2 placeholders must not block GRE inspection: %v", err)
	}
	if len(rows) != 1 || rows[0].Name != "g0" || rows[0].IfIndex != 5 {
		t.Fatalf("GRE parser lost genuine identity after placeholders: %#v", rows)
	}
	if empty, err := parseGRELinks([]byte("[{}, {}]")); err != nil || len(empty) != 0 {
		t.Fatalf("only placeholders should produce empty, valid observation: %#v, %v", empty, err)
	}
	for _, raw := range []string{
		`[{}, {"ifname":"unrecognized"}]`,
		`[{}, {"ifindex":1,"ifname":"foreign","linkinfo":{"info_kind":"veth"}}]`,
		`[{}, null]`,
		`[{}, 17]`,
	} {
		if _, err := parseGRELinks([]byte(raw)); err == nil {
			t.Fatalf("must reject nonempty/malformed GRE observation: %s", raw)
		}
	}
}

func TestGREInspectionRejectsMalformedRootAndWildcardFallback(t *testing.T) {
	// A genuine kernel gre0 fallback is the only wildcard interface omitted.
	fallback := `{"ifindex":8,"ifname":"gre0","flags":["NOARP"],"linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any","ttl":0}}}`
	parsed, err := parseGRELinks([]byte("[{}, " + fallback + ", {}]"))
	if err != nil || len(parsed) != 0 {
		t.Fatalf("valid gre0 fallback and empty iproute2 placeholders must be skipped: %#v %v", parsed, err)
	}
	if links, err := parseGRELinks([]byte("[]")); err != nil || len(links) != 0 {
		t.Fatalf("empty JSON array must remain valid: %#v %v", links, err)
	}
	for name, raw := range map[string]string{
		"top-level null":         "null",
		"whitespace null":        " \n null \n",
		"empty input":            " \n ",
		"nonarray root":          `{"ifname":"gre0"}`,
		"wrong fallback kind":    `[{"ifindex":8,"ifname":"gre0","linkinfo":{"info_kind":"veth","info_data":{"local":"any","remote":"any"}}}]`,
		"missing fallback index": `[{"ifname":"gre0","linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any"}}}]`,
		"foreign wildcard name":  `[{"ifindex":8,"ifname":"foreign","linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any"}}}]`,
		"one wildcard address":   `[{"ifindex":8,"ifname":"gre0","linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"198.51.100.20"}}}]`,
		"owned wildcard alias":   `[{"ifindex":8,"ifname":"gre0","ifalias":"foreign-tag","linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any"}}}]`,
		"keyed wildcard":         `[{"ifindex":8,"ifname":"gre0","linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any","ikey":"0.0.0.7","okey":"0.0.0.7"}}}]`,
		"encapsulated wildcard":  `[{"ifindex":8,"ifname":"gre0","linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any","encap":{"type":"fou","sport":33061,"dport":33061}}}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseGRELinks([]byte(raw)); err == nil {
				t.Fatalf("malformed GRE observation silently treated as absence: %#v", got)
			}
		})
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
			// Same underlay peers are supported across encapsulations only when
			// Linux GRE receive identity differs (a distinct keyed value here).
			runner.extra = []observedLink{{
				Exists: true, IfIndex: 90, Name: "native-peer", Local: link.Underlay.Local, Peer: link.Underlay.Peer,
				KeyEnabled: true, Key: 1, PMTUD: true, Encapsulation: domain.EncapNative,
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

func TestNativeGRELookupFailurePreservesUnindexedCreatedInterface(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name}
	firewall := &fakeFirewall{}
	b, err := New(Options{
		Runner:   runner,
		Routes:   fakeRoute{linux.Route{Peer: link.Underlay.Peer, Source: link.Underlay.Local, Device: "eth0"}},
		Firewall: firewall, Collisions: fakeCollisions{},
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

func TestNativeGRECreationIdentityDriftPreservesReplacement(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	foreignOwner := domain.LinkID("lnk_33333333333333333333333333333333")

	for _, tc := range []struct {
		name     string
		lookup   func(*fakeRunner) (int, error)
		setAlias func(*fakeRunner, int, string) error
	}{
		{
			name: "replacement_before_ownership_mark",
			lookup: func(r *fakeRunner) (int, error) {
				r.state.IfIndex = 88
				r.state.Owner = foreignOwner
				return 77, nil
			},
			setAlias: func(*fakeRunner, int, string) error {
				t.Fatal("ownership must not be written after pre-alias identity drift")
				return nil
			},
		},
		{
			name:   "ownership_changed_before_address_setup",
			lookup: func(*fakeRunner) (int, error) { return 77, nil },
			setAlias: func(r *fakeRunner, index int, _ string) error {
				if index != 77 {
					return fmt.Errorf("wrong index %d", index)
				}
				// Model an external writer replacing/changing ownership immediately
				// after the identity-bound ownership mutation completed.
				r.state.Owner = foreignOwner
				return nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{link: link, name: name}
			firewall := &fakeFirewall{}
			b, err := New(Options{
				Runner:   runner,
				Routes:   fakeRoute{linux.Route{Peer: link.Underlay.Peer, Source: link.Underlay.Local, Device: "eth0"}},
				Firewall: firewall, Collisions: fakeCollisions{},
				LookupIndex: func(string) (int, error) { return tc.lookup(runner) },
				SetAlias:    func(_ context.Context, index int, alias string) error { return tc.setAlias(runner, index, alias) },
				AddAddress: func(context.Context, int, netip.Prefix) error {
					t.Fatal("address mutation must not run after identity drift")
					return nil
				},
				SetUp: func(context.Context, int) error {
					t.Fatal("link-up mutation must not run after identity drift")
					return nil
				},
				DeleteLink: func(_ context.Context, index int) error {
					t.Fatalf("ambiguous replacement must not be deleted by ifindex %d", index)
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
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
			undo, err := b.Apply(ctx, req, obs, candidate)
			if err == nil || undo == nil {
				t.Fatalf("identity drift was not surfaced: %v", err)
			}
			if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
				t.Fatalf("ambiguous rollback did not fail closed: %v", err)
			}
			if !runner.state.Exists || runner.state.Owner != foreignOwner {
				t.Fatalf("foreign replacement was mutated during failed rollback: %#v", runner.state)
			}
		})
	}
}

func TestNativeGRERollbackRevalidatesOwnershipBeforeDelete(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name}
	firewall := &fakeFirewall{failEnsure: true}
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
	undo, err := b.Apply(ctx, req, obs, candidate)
	if err == nil || undo == nil {
		t.Fatalf("expected post-create firewall failure: %v", err)
	}

	foreignOwner := domain.LinkID("lnk_44444444444444444444444444444444")
	runner.state.Owner = foreignOwner
	if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
		t.Fatalf("rollback accepted changed ownership: %v", err)
	}
	if !runner.state.Exists || runner.state.Owner != foreignOwner {
		t.Fatalf("rollback deleted or changed foreign-owned interface: %#v", runner.state)
	}
}

func TestNativeGRERollbackBeforeAddressAssignmentDeletesOnlyUntouchedCreatedState(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name}
	firewall := &fakeFirewall{}
	b := newTestBackend(t, runner, firewall, fakeCollisions{})
	b.addAddress = func(context.Context, int, netip.Prefix) error {
		return errors.New("address add failed")
	}

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
	undo, err := b.Apply(ctx, req, obs, candidate)
	if err == nil || undo == nil {
		t.Fatalf("address failure did not return rollback: %v", err)
	}
	if err := undo(context.Background()); err != nil {
		t.Fatalf("rollback of untouched pre-address state failed: %v", err)
	}
	if runner.state.Exists {
		t.Fatal("created GRE interface survived safe pre-address rollback")
	}
}

func TestNativeGRERollbackPreservesUnexpectedAdditionalAddress(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name}
	firewall := &fakeFirewall{failEnsure: true}
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
	undo, err := b.Apply(ctx, req, obs, candidate)
	if err == nil || undo == nil {
		t.Fatalf("expected post-create firewall failure: %v", err)
	}

	external := netip.MustParsePrefix("10.80.21.10/32")
	runner.state.IPv4Addresses = append(runner.state.IPv4Addresses, external)
	if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
		t.Fatalf("rollback accepted independently changed address state: %v", err)
	}
	if !runner.state.Exists || !slices.Contains(runner.state.IPv4Addresses, external) {
		t.Fatalf("rollback destroyed independently added address/state: %#v", runner.state)
	}
}

func attemptGRECreate(t *testing.T, b *Backend, link domain.Link) (core.Rollback, error) {
	t.Helper()
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
	return b.Apply(ctx, req, obs, candidate)
}

func TestNativeGREAmbiguousMutationRollbackOnlyDeletesUnmodifiedState(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*Backend, *fakeRunner)
		preserve bool
	}{
		{
			name: "failed_address_with_exact_intended_address",
			mutate: func(b *Backend, r *fakeRunner) {
				b.addAddress = func(_ context.Context, _ int, prefix netip.Prefix) error {
					r.state.IPv4Addresses = []netip.Prefix{prefix}
					return errors.New("address request failed after ambiguous mutation")
				}
			},
			preserve: true,
		},
		{
			name: "failed_address_without_mutation",
			mutate: func(b *Backend, _ *fakeRunner) {
				b.addAddress = func(context.Context, int, netip.Prefix) error {
					return errors.New("address request failed before mutation")
				}
			},
		},
		{
			name: "failed_up_with_interface_activated",
			mutate: func(b *Backend, r *fakeRunner) {
				b.setUp = func(context.Context, int) error {
					r.state.Up = true
					return errors.New("link-up failed after ambiguous mutation")
				}
			},
			preserve: true,
		},
		{
			name: "failed_up_without_mutation",
			mutate: func(b *Backend, _ *fakeRunner) {
				b.setUp = func(context.Context, int) error {
					return errors.New("link-up failed before mutation")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := testLink()
			name, _ := InterfaceName(link.ID)
			runner := &fakeRunner{link: link, name: name}
			b := newTestBackend(t, runner, &fakeFirewall{}, fakeCollisions{})
			tc.mutate(b, runner)
			undo, err := attemptGRECreate(t, b, link)
			if err == nil || undo == nil {
				t.Fatalf("ambiguous mutation must return a rollback: %v", err)
			}
			rollbackErr := undo(context.Background())
			if tc.preserve {
				if rollbackErr == nil || !strings.Contains(rollbackErr.Error(), "preserving") {
					t.Fatalf("ambiguous mutation was not preserved: %v", rollbackErr)
				}
				if !runner.state.Exists {
					t.Fatal("independently modified interface was destroyed")
				}
				if strings.Contains(tc.name, "address") && !slices.Contains(runner.state.IPv4Addresses, link.Addresses.Local) {
					t.Fatal("exact independently observable address was lost")
				}
				if strings.Contains(tc.name, "up") && !runner.state.Up {
					t.Fatal("ambiguous activated state was lost")
				}
			} else if rollbackErr != nil || runner.state.Exists {
				t.Fatalf("safe unmodified state was not rolled back: err=%v state=%#v", rollbackErr, runner.state)
			}
		})
	}
}

func TestNativeGRERawAliasBeforeOwnershipIsNotOverwrittenOrDeleted(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	owner, _ := linux.OwnerTag(link.ID)
	for _, rawAlias := range []string{"external-alias", " " + owner} {
		t.Run(rawAlias, func(t *testing.T) {
			runner := &fakeRunner{link: link, name: name}
			b := newTestBackend(t, runner, &fakeFirewall{}, fakeCollisions{})
			b.lookupIndex = func(string) (int, error) {
				runner.state.Alias = rawAlias
				return 77, nil
			}
			b.setAlias = func(context.Context, int, string) error {
				t.Fatal("must not overwrite an independently added alias")
				return nil
			}
			b.deleteLink = func(context.Context, int) error {
				t.Fatal("must not delete interface with independently added alias")
				return nil
			}
			undo, err := attemptGRECreate(t, b, link)
			if err == nil || undo == nil {
				t.Fatalf("raw alias drift not rejected: %v", err)
			}
			if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
				t.Fatalf("raw alias drift allowed rollback: %v", err)
			}
			if !runner.state.Exists || runner.state.Alias != rawAlias {
				t.Fatalf("independently supplied raw alias was changed: %#v", runner.state)
			}
		})
	}
}

func TestNativeGRERollbackPreservesChangedRawAlias(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	owner, _ := linux.OwnerTag(link.ID)
	runner := &fakeRunner{link: link, name: name}
	b := newTestBackend(t, runner, &fakeFirewall{failEnsure: true}, fakeCollisions{})
	undo, err := attemptGRECreate(t, b, link)
	if err == nil || undo == nil {
		t.Fatalf("expected later firewall failure: %v", err)
	}
	runner.state.Alias = " " + owner
	if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
		t.Fatalf("noncanonical owner alias was accepted: %v", err)
	}
	if !runner.state.Exists || runner.state.Alias != " "+owner {
		t.Fatalf("changed alias was destroyed: %#v", runner.state)
	}
}

func TestNativeGREAddressObservationRejectsNameReuseAcrossIfindexes(t *testing.T) {
	link := testLink()
	name, _ := InterfaceName(link.ID)
	runner := &fakeRunner{link: link, name: name, addressIndexOverride: 88}
	b := newTestBackend(t, runner, &fakeFirewall{}, fakeCollisions{})
	b.setAlias = func(context.Context, int, string) error {
		t.Fatal("address observation is not consistent; must not mark ownership")
		return nil
	}
	b.deleteLink = func(context.Context, int) error {
		t.Fatal("composite observations must not permit destructive rollback")
		return nil
	}
	undo, err := attemptGRECreate(t, b, link)
	if err == nil || undo == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("name reused by another ifindex was not rejected: %v", err)
	}
	if err := undo(context.Background()); err == nil || !strings.Contains(err.Error(), "preserving") {
		t.Fatalf("mismatched ifindex allowed rollback: %v", err)
	}
	if !runner.state.Exists || runner.state.IfIndex != 77 || runner.state.Owner != "" {
		t.Fatalf("mismatched observation modified or destroyed interface: %#v", runner.state)
	}
}
