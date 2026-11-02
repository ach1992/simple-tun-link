package l2tpv3

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type RouteResolver interface {
	Resolve(context.Context, netip.Addr) (linux.Route, error)
}
type Firewall interface {
	HasInbound(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error)
	HasOwnedInbound(context.Context, domain.LinkID, bool) (bool, error)
	FindOwnedInbound(context.Context, domain.LinkID, bool) (linux.InboundFirewallRule, bool, error)
	EnsureInboundLocked(context.Context, domain.LinkID, linux.InboundFirewallRule) (func(context.Context) error, bool, error)
	RemoveInboundLocked(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error)
}
type CollisionInspector interface {
	Inspect(context.Context, []domain.ResourceClaim) ([]linux.ObservedResource, error)
}
type Options struct {
	Runner      linux.Runner
	Routes      RouteResolver
	Firewall    Firewall
	Collisions  CollisionInspector
	IPBinary    string
	SetAlias    func(context.Context, int, string) error
	SetMAC      func(context.Context, int, string) error
	AddAddress  func(context.Context, int, netip.Prefix) error
	SetUp       func(context.Context, int) error
	AddNeighbor func(context.Context, int, netip.Addr, string) error
	ModuleProbe func(context.Context, string) bool
}
type Backend struct {
	runner      linux.Runner
	routes      RouteResolver
	firewall    Firewall
	collisions  CollisionInspector
	ip          string
	setAlias    func(context.Context, int, string) error
	setMAC      func(context.Context, int, string) error
	addAddress  func(context.Context, int, netip.Prefix) error
	setUp       func(context.Context, int) error
	addNeighbor func(context.Context, int, netip.Addr, string) error
	moduleProbe func(context.Context, string) bool
}

func New(opts Options) (*Backend, error) {
	if opts.Runner == nil || opts.Routes == nil || opts.Firewall == nil || opts.Collisions == nil {
		return nil, fmt.Errorf("L2TPv3 requires runner, routes, firewall and collision inspector")
	}
	ip := opts.IPBinary
	if ip == "" {
		ip = "ip"
	}
	setAlias := opts.SetAlias
	if setAlias == nil {
		setAlias = linux.SetLinkAliasByIndex
	}
	setMAC := opts.SetMAC
	if setMAC == nil {
		setMAC = linux.SetLinkMACByIndex
	}
	addAddress := opts.AddAddress
	if addAddress == nil {
		addAddress = linux.AddIPv4AddressByIndex
	}
	setUp := opts.SetUp
	if setUp == nil {
		setUp = linux.SetLinkUpByIndex
	}
	addNeighbor := opts.AddNeighbor
	if addNeighbor == nil {
		addNeighbor = linux.AddPermanentIPv4NeighborByIndex
	}
	moduleProbe := opts.ModuleProbe
	if moduleProbe == nil {
		moduleProbe = (linux.KernelModuleProbe{Runner: opts.Runner}).AvailableButNotLoaded
	}
	return &Backend{runner: opts.Runner, routes: opts.Routes, firewall: opts.Firewall, collisions: opts.Collisions, ip: ip, setAlias: setAlias, setMAC: setMAC, addAddress: addAddress, setUp: setUp, addNeighbor: addNeighbor, moduleProbe: moduleProbe}, nil
}
func (*Backend) Kind() domain.Backend { return domain.BackendL2TPv3 }

type observation struct {
	id             identity
	tunnels        []tunnel
	sessions       []session
	tunnel         *tunnel
	session        *session
	iface          *iface
	addresses      []netip.Prefix
	foreignAddress bool
	neighbors      []neighbor
}

func (o observation) ObservedResources() []domain.ResourceClaim {
	if o.iface == nil {
		return nil
	}
	claims := []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: o.iface.IfName}}
	for _, addr := range o.addresses {
		claims = append(claims, domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: addr.Addr().String()},
			domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: addr.Masked().String()})
	}
	return claims
}
func (o observation) present() bool { return o.iface != nil || o.tunnel != nil || o.session != nil }

// L2TPVerifiedOwnedIndex is the read-only identity witness used by Engine
// before a committed Remove and after its compensating kernel restoration.
// An alias or interface name alone is never sufficient to authorize MTU writes.
func (o observation) L2TPVerifiedOwnedIndex(l domain.Link) int {
	if !o.matches(l) || !o.interfaceOwned(l) || !onlyManagedNeighbor(o, l) ||
		!noForeignL2TPSessions(o) {
		return 0
	}
	return o.iface.IfIndex
}
func (o observation) matches(l domain.Link) bool {
	if o.tunnel == nil || o.session == nil || o.iface == nil {
		return false
	}
	s, i, id := o.session, o.iface, o.id
	if !o.tunnelMatches(l) || s.TunnelID != id.tunnel || s.SessionID != id.session ||
		s.PeerTunnelID != id.peerTunnel || s.PeerSessionID != id.peerSession || s.Interface != id.name ||
		i.IfName != id.name || i.IfIndex <= 0 || !slices.Contains(i.Flags, "UP") ||
		!strings.EqualFold(i.Address, id.mac) {
		return false
	}
	wantAlias, err := linux.OwnerTag(l.ID)
	if err != nil || i.IfAlias != wantAlias {
		return false
	}
	if o.foreignAddress || len(o.addresses) != 1 || o.addresses[0] != l.Addresses.Local {
		return false
	}
	for _, n := range o.neighbors {
		if n.Dst == l.Addresses.Peer.Addr().String() {
			return strings.EqualFold(n.LLAddr, id.peerMAC) && neighborPermanent(n)
		}
	}
	return false
}
func (o observation) tunnelMatches(l domain.Link) bool {
	if o.tunnel == nil {
		return false
	}
	t, id := o.tunnel, o.id
	return t.TunnelID == id.tunnel && t.PeerTunnel == id.peerTunnel && t.Encap == "IP" &&
		t.Local == l.Underlay.Local.String() && t.Peer == l.Underlay.Peer.String()
}
func (o observation) sessionMatches() bool {
	if o.session == nil {
		return false
	}
	s, id := o.session, o.id
	return s.TunnelID == id.tunnel && s.SessionID == id.session &&
		s.PeerTunnelID == id.peerTunnel && s.PeerSessionID == id.peerSession && s.Interface == id.name
}
func (o observation) interfaceOwned(l domain.Link) bool {
	if o.iface == nil {
		return false
	}
	owner, ok := linux.ParseOwnerTag(o.iface.IfAlias)
	return ok && owner == l.ID && o.iface.IfIndex > 0 && o.iface.IfName == o.id.name
}

func (b *Backend) Inspect(ctx context.Context, link domain.Link) (core.Observation, error) {
	if err := validLink(link); err != nil {
		return nil, err
	}
	id, err := identityFor(link)
	if err != nil {
		return nil, err
	}
	tRes, err := b.runner.Run(ctx, b.ip, "-json", "l2tp", "show", "tunnel")
	if err != nil {
		if b.moduleProbe(ctx, "l2tp_ip") || b.moduleProbe(ctx, "l2tp_eth") {
			return nil, core.KernelModuleNotLoaded("l2tp_ip/l2tp_eth")
		}
		return nil, fmt.Errorf("inspect L2TPv3 tunnels: %w", err)
	}
	tunnels, err := parseJSON[tunnel](tRes.Stdout, "tunnel")
	if err != nil {
		return nil, err
	}
	for _, discovered := range tunnels {
		if !discovered.valid() && discovered.TunnelID == id.tunnel {
			return nil, fmt.Errorf("L2TPv3 tunnel inventory has invalid matching host identity")
		}
	}
	sRes, err := b.runner.Run(ctx, b.ip, "-json", "l2tp", "show", "session")
	if err != nil {
		return nil, fmt.Errorf("inspect L2TPv3 sessions: %w", err)
	}
	sessions, err := parseJSON[session](sRes.Stdout, "session")
	if err != nil {
		return nil, err
	}
	lRes, err := b.runner.Run(ctx, b.ip, "-json", "link", "show")
	if err != nil {
		return nil, fmt.Errorf("inspect L2TPv3 link inventory: %w", err)
	}
	interfaces, err := parseJSON[iface](lRes.Stdout, "link")
	if err != nil {
		return nil, err
	}
	o := observation{id: id, tunnels: tunnels, sessions: sessions}
	for i := range tunnels {
		if tunnels[i].TunnelID != id.tunnel {
			continue
		}
		if o.tunnel != nil {
			return nil, fmt.Errorf("duplicate local L2TP tunnel ID in inventory")
		}
		o.tunnel = &o.tunnels[i]
	}
	for i := range sessions {
		if sessions[i].TunnelID == id.tunnel && sessions[i].SessionID == id.session {
			if o.session != nil {
				return nil, fmt.Errorf("duplicate local L2TP session ID in inventory")
			}
			o.session = &o.sessions[i]
		}
	}
	for i := range interfaces {
		if interfaces[i].IfName != id.name {
			continue
		}
		if o.iface != nil {
			return nil, fmt.Errorf("duplicate L2TP interface name")
		}
		iCopy := interfaces[i]
		o.iface = &iCopy
	}
	if o.iface != nil {
		addr, err := b.runner.Run(ctx, b.ip, "-json", "address", "show", "dev", id.name)
		if err != nil {
			return nil, fmt.Errorf("inspect L2TPv3 Link IPv4 address: %w", err)
		}
		rows, err := parseJSON[ifaceAddr](addr.Stdout, "IPv4 address")
		if err != nil {
			return nil, err
		}
		if len(rows) != 1 || rows[0].IfIndex != o.iface.IfIndex || rows[0].IfName != id.name {
			return nil, fmt.Errorf("L2TPv3 interface identity changed while reading addresses")
		}
		for _, item := range rows[0].AddrInfo {
			switch item.Family {
			case "inet":
				ip, err := netip.ParseAddr(item.Local)
				if err != nil || !ip.Is4() || item.PrefixLen < 0 || item.PrefixLen > 32 {
					return nil, fmt.Errorf("malformed L2TPv3 IPv4 address inventory")
				}
				o.addresses = append(o.addresses, netip.PrefixFrom(ip, item.PrefixLen))
			case "inet6":
				// An ordinary kernel-generated link-local address is allowed.
				// Every other IPv6 address blocks deletion of this interface.
				if !autoKernelLinkLocal(item.Local, item.PrefixLen, item.Scope, item.Protocol, o.iface.Address) {
					o.foreignAddress = true
				}
			default:
				o.foreignAddress = true
			}
		}
		nRes, err := b.runner.Run(ctx, b.ip, "-json", "neigh", "show", "dev", id.name)
		if err != nil {
			return nil, fmt.Errorf("inspect L2TPv3 neighbor inventory: %w", err)
		}
		o.neighbors, err = parseNeighbors(nRes.Stdout)
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

// Modern Linux exposes "kernel_ll" for automatically created IPv6
// link-local addresses. On older kernels which omit that protocol, permit
// only the precise EUI-64 link-local of the current Ethernet MAC.
// A foreign/global/manually assigned IPv6 address must not be destroyed.
func autoKernelLinkLocal(text string, bits int, scope, protocol, ethernetMAC string) bool {
	ip, err := netip.ParseAddr(text)
	if err != nil || !ip.Is6() || !ip.IsLinkLocalUnicast() || bits != 64 || scope != "link" {
		return false
	}
	if protocol == "kernel_ll" {
		return true
	}
	if protocol != "" {
		return false
	}
	mac, err := net.ParseMAC(ethernetMAC)
	if err != nil || len(mac) != 6 {
		return false
	}
	var eui [16]byte
	eui[0], eui[1] = 0xfe, 0x80
	eui[8], eui[9], eui[10] = mac[0]^2, mac[1], mac[2]
	eui[11], eui[12] = 0xff, 0xfe
	eui[13], eui[14], eui[15] = mac[3], mac[4], mac[5]
	return ip == netip.AddrFrom16(eui)
}

type plan struct {
	id                             identity
	link                           domain.Link
	route                          linux.Route
	firewallRule                   linux.InboundFirewallRule
	resources                      []domain.ResourceClaim
	create, remove, firewallChange bool
}

func (p plan) Empty() bool { return !p.create && !p.remove && !p.firewallChange }
func (p plan) Resources() []domain.ResourceClaim {
	return append([]domain.ResourceClaim(nil), p.resources...)
}
func (b *Backend) Plan(ctx context.Context, req core.Request, observed core.Observation) (core.Plan, error) {
	o, ok := observed.(observation)
	if !ok {
		return nil, fmt.Errorf("unexpected L2TPv3 observation")
	}
	if err := validLink(req.Link); err != nil {
		return nil, err
	}
	id, err := identityFor(req.Link)
	if err != nil {
		return nil, err
	}
	var route linux.Route
	var rule linux.InboundFirewallRule
	var has bool
	if req.Operation == core.OperationRemove {
		// A committed Link can lose the parent route or remote peer. Recover
		// only its original exactly owned IP115 firewall rule without asking
		// today's underlay router for a new interface identity.
		rule, has, err = linux.RecoverOwnedInboundForRemoval(
			ctx, b.firewall, req.Link.ID, req.Link.Underlay.Local,
			req.Link.Underlay.Peer, protocol, 0)
		if err != nil {
			return nil, fmt.Errorf("recover L2TPv3 original firewall ownership: %w", err)
		}
		if has {
			route.Device = rule.InputInterface
		}
	} else {
		route, err = linux.ResolveConfiguredUnderlay(ctx, b.routes, b.runner, req.Link.Underlay.Local, req.Link.Underlay.Peer)
		if err != nil || route.Source != req.Link.Underlay.Local {
			return nil, stlerr.LocalUnderlayUnverified("l2tpv3_plan", string(req.Link.ID), string(req.Link.Backend), err)
		}
		rule = linux.InboundFirewallRule{
			Local: req.Link.Underlay.Local, Peer: req.Link.Underlay.Peer,
			InputInterface: route.Device, Protocol: protocol,
		}
		has, err = b.firewall.HasInbound(ctx, req.Link.ID, rule)
		if err != nil {
			return nil, err
		}
		owned, err := b.firewall.HasOwnedInbound(ctx, req.Link.ID, false)
		if err != nil {
			return nil, err
		}
		if owned && !has {
			return nil, stlerr.New(stlerr.CodeConflict, "l2tpv3_plan", string(req.Link.ID), "l2tpv3", "a different owned IP115 firewall rule requires explicit reconciliation")
		}
	}
	p := plan{id: id, link: req.Link, route: route, firewallRule: rule}
	switch req.Operation {
	case core.OperationEnsure:
		claim, err := linux.InboundFirewallClaim(req.Link.ID, rule)
		if err != nil {
			return nil, err
		}
		p.resources = ownedClaims(req.Link, id, claim)
		p.create = !o.matches(req.Link)
		p.firewallChange = !has
	case core.OperationRemove:
		p.remove = o.present()
		p.firewallChange = has
	default:
		return nil, fmt.Errorf("unsupported L2TPv3 operation %q", req.Operation)
	}
	return p, nil
}
func (b *Backend) Validate(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) error {
	o, ok := observed.(observation)
	if !ok {
		return fmt.Errorf("unexpected L2TPv3 observation")
	}
	p, ok := candidate.(plan)
	if !ok {
		return fmt.Errorf("unexpected L2TPv3 plan")
	}
	if req.Operation == core.OperationEnsure {
		fresh, err := linux.ResolveConfiguredUnderlay(ctx, b.routes, b.runner, req.Link.Underlay.Local, req.Link.Underlay.Peer)
		if err != nil {
			return fmt.Errorf("cannot recheck L2TPv3 local underlay: %w", err)
		}
		if fresh.Device != p.route.Device || fresh.Source != req.Link.Underlay.Local {
			return fmt.Errorf("L2TPv3 underlay route/source changed")
		}
	}
	if req.Prior != nil {
		before, after := *req.Prior, req.Link
		before.MTU = domain.MTUPolicy{}
		after.MTU = domain.MTUPolicy{}
		if before != after {
			return stlerr.New(stlerr.CodeConflict, "l2tpv3_validate", string(req.Link.ID), "l2tpv3", "L2TPv3 configuration changes require Remove then Create; no implicit in-place recreation")
		}
	}
	// Kernel tunnel IDs are host-wide. Explicitly inspect all namespace-local
	// tunnels/sessions, including UDP L2TP and foreign sessions.
	for _, t := range o.tunnels {
		if t.TunnelID == p.id.tunnel && (!o.tunnelMatches(req.Link) || o.iface == nil || !o.interfaceOwned(req.Link) || req.Prior == nil) {
			return stlerr.New(stlerr.CodeConflict, "l2tpv3_validate", string(req.Link.ID), "l2tpv3", "L2TPv3 tunnel ID is occupied or not durably owned by this Link")
		}
	}
	for _, s := range o.sessions {
		// Linux L2TPv3 session IDs can be looked up across tunnels. Avoid
		// ambiguous cross-tunnel collisions as well as foreign sessions
		// grafted into our tunnel.
		if (s.TunnelID == p.id.tunnel && (s.SessionID != p.id.session || !o.sessionMatches() || req.Prior == nil)) ||
			(s.TunnelID != p.id.tunnel && s.SessionID == p.id.session) {
			return stlerr.New(stlerr.CodeConflict, "l2tpv3_validate", string(req.Link.ID), "l2tpv3", "L2TPv3 tunnel contains a foreign/ambiguous session")
		}
	}
	switch req.Operation {
	case core.OperationEnsure:
		if req.Prior == nil && o.present() {
			return stlerr.New(stlerr.CodeConflict, "l2tpv3_ensure", string(req.Link.ID), "l2tpv3", "uncommitted/foreign L2TPv3 state is not adoptable")
		}
		if o.present() && !o.matches(req.Link) {
			return stlerr.New(stlerr.CodeConflict, "l2tpv3_ensure", string(req.Link.ID), "l2tpv3", "partial or mismatched L2TPv3 resources require exact reconciliation")
		}
		if o.iface == nil && o.present() {
			return stlerr.New(stlerr.CodeConflict, "l2tpv3_ensure", string(req.Link.ID), "l2tpv3", "ambiguous partial L2TPv3 resources")
		}
		if o.iface != nil && !o.matches(req.Link) {
			return fmt.Errorf("L2TPv3 interface identity is not exact")
		}
		check := mtuResource(req.Link, p.id)
		conflicts, err := b.collisions.Inspect(ctx, check)
		if err != nil {
			return fmt.Errorf("inspect L2TPv3 host collisions: %w", err)
		}
		for _, collision := range conflicts {
			if req.Prior == nil || collision.Owner != req.Link.ID {
				return stlerr.New(stlerr.CodeConflict, "l2tpv3_ensure", string(req.Link.ID), "l2tpv3", "L2TPv3 interface/IP/subnet conflicts with another host resource")
			}
		}
	case core.OperationRemove:
		if o.present() && (!o.matches(req.Link) || !o.interfaceOwned(req.Link) || !onlyManagedNeighbor(o, req.Link)) {
			return stlerr.New(stlerr.CodeConflict, "l2tpv3_remove", string(req.Link.ID), "l2tpv3", "cannot delete L2TPv3 interface containing unowned neighbor or mismatched kernel state")
		}
		for _, claim := range []domain.ResourceClaim{
			{Kind: domain.ResourceInterface, Key: p.id.name},
			{Kind: domain.ResourceBackendID, Key: "l2tpv3/tunnel/" + fmt.Sprint(p.id.tunnel)},
			{Kind: domain.ResourceBackendID, Key: fmt.Sprintf("l2tpv3/session/%d", p.id.session)},
		} {
			if o.present() {
				if err := linux.RequireOwned(req.Link.ID, claim, req.OwnedResources); err != nil {
					return err
				}
			}
		}
		if p.firewallChange {
			claim, err := linux.InboundFirewallClaim(req.Link.ID, p.firewallRule)
			if err != nil {
				return err
			}
			if err = linux.RequireOwned(req.Link.ID, claim, req.OwnedResources); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported L2TPv3 operation")
	}
	return nil
}
func (b *Backend) Verify(ctx context.Context, req core.Request) (core.Observation, error) {
	result, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return nil, err
	}
	o := result.(observation)
	owned, err := b.firewall.HasOwnedInbound(ctx, req.Link.ID, false)
	if err != nil {
		return nil, err
	}
	var has bool
	if req.Operation == core.OperationEnsure {
		route, err := linux.ResolveConfiguredUnderlay(ctx, b.routes, b.runner, req.Link.Underlay.Local, req.Link.Underlay.Peer)
		if err != nil {
			return nil, err
		}
		rule := linux.InboundFirewallRule{
			Local: req.Link.Underlay.Local, Peer: req.Link.Underlay.Peer,
			InputInterface: route.Device, Protocol: protocol,
		}
		has, err = b.firewall.HasInbound(ctx, req.Link.ID, rule)
		if err != nil {
			return nil, err
		}
	}
	switch req.Operation {
	case core.OperationEnsure:
		if !o.matches(req.Link) || !has || !owned {
			return nil, fmt.Errorf("L2TPv3 Link exact kernel/firewall verification failed")
		}
	case core.OperationRemove:
		if o.present() || owned {
			return nil, fmt.Errorf("L2TPv3 Link resources remain after removal")
		}
	default:
		return nil, fmt.Errorf("unsupported L2TPv3 verification operation")
	}
	return o, nil
}

var _ core.Backend = (*Backend)(nil)
