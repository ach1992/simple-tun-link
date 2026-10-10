package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	EnsureInboundLocked(context.Context, domain.LinkID, linux.InboundFirewallRule) (func(context.Context) error, bool, error)
	RemoveInboundLocked(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error)
}
type CollisionInspector interface {
	Inspect(context.Context, []domain.ResourceClaim) ([]linux.ObservedResource, error)
}

type Options struct {
	Runner             linux.FileRunner
	Routes             RouteResolver
	Firewall           Firewall
	Collisions         CollisionInspector
	Keys               *KeyStore
	IPBinary, WGBinary string
	SetAlias           func(context.Context, int, string) error
	AddAddress         func(context.Context, int, netip.Prefix) error
	SetUp              func(context.Context, int) error
	DeleteLink         func(context.Context, int) error
	LookupIndex        func(string) (int, error)
}

type Backend struct {
	runner             linux.FileRunner
	routes             RouteResolver
	firewall           Firewall
	collisions         CollisionInspector
	keys               *KeyStore
	ipBinary, wgBinary string
	setAlias           func(context.Context, int, string) error
	addAddress         func(context.Context, int, netip.Prefix) error
	setUp              func(context.Context, int) error
	deleteLink         func(context.Context, int) error
	lookupIndex        func(string) (int, error)
}

func New(opts Options) (*Backend, error) {
	if opts.Runner == nil || opts.Routes == nil || opts.Firewall == nil || opts.Collisions == nil || opts.Keys == nil {
		return nil, fmt.Errorf("WireGuard requires runner, route, firewall, collision and private-key storage")
	}
	b := &Backend{runner: opts.Runner, routes: opts.Routes, firewall: opts.Firewall, collisions: opts.Collisions, keys: opts.Keys, ipBinary: opts.IPBinary, wgBinary: opts.WGBinary,
		setAlias: opts.SetAlias, addAddress: opts.AddAddress, setUp: opts.SetUp, deleteLink: opts.DeleteLink, lookupIndex: opts.LookupIndex}
	if b.ipBinary == "" {
		b.ipBinary = "ip"
	}
	if b.wgBinary == "" {
		b.wgBinary = "wg"
	}
	if b.setAlias == nil {
		b.setAlias = linux.SetLinkAliasByIndex
	}
	if b.addAddress == nil {
		b.addAddress = linux.AddIPv4AddressByIndex
	}
	if b.setUp == nil {
		b.setUp = linux.SetLinkUpByIndex
	}
	if b.deleteLink == nil {
		b.deleteLink = linux.DeleteLinkByIndex
	}
	if b.lookupIndex == nil {
		b.lookupIndex = func(name string) (int, error) {
			v, e := net.InterfaceByName(name)
			if e != nil {
				return 0, e
			}
			return v.Index, nil
		}
	}
	return b, nil
}

func (*Backend) Kind() domain.Backend { return domain.BackendWireGuard }

type observation struct {
	Target observedLink
	Links  []observedLink
}

func (o observation) ObservedResources() []domain.ResourceClaim {
	if !o.Target.Exists {
		return nil
	}
	out := []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: o.Target.Name}}
	for _, addr := range o.Target.IPv4Addresses {
		out = append(out, domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: addr.Addr().String()}, domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: addr.Masked().String()})
	}
	if o.Target.ListenPort != 0 {
		out = append(out, domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(o.Target.ListenPort))})
	}
	return out
}

type plan struct {
	link                            domain.Link
	name                            string
	route                           linux.Route
	firewallRule                    linux.InboundFirewallRule
	resources                       []domain.ResourceClaim
	interfaceChange, firewallChange bool
}

func (p plan) Empty() bool { return !p.interfaceChange && !p.firewallChange }
func (p plan) Resources() []domain.ResourceClaim {
	return append([]domain.ResourceClaim(nil), p.resources...)
}

func (b *Backend) Inspect(ctx context.Context, link domain.Link) (core.Observation, error) {
	name, err := InterfaceName(link.ID)
	if err != nil {
		return nil, err
	}
	result, err := b.runner.Run(ctx, b.ipBinary, "-details", "-json", "link", "show", "type", "wireguard")
	if err != nil {
		return nil, fmt.Errorf("cannot inspect WireGuard link identities: %w", err)
	}
	links, err := parseLinks(result.Stdout)
	if err != nil {
		return nil, err
	}
	obs := observation{Links: links}
	for i := range links {
		if links[i].Name != name {
			continue
		}
		a, err := b.runner.Run(ctx, b.ipBinary, "-json", "address", "show", "dev", name)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect WireGuard addresses: %w", err)
		}
		links[i].IPv4Addresses, err = parseAddresses(a.Stdout, name, links[i].IfIndex)
		if err != nil {
			return nil, err
		}
		if err = b.inspectPublicWG(ctx, &links[i]); err != nil {
			return nil, err
		}
		obs.Target = links[i]
		obs.Links[i] = links[i]
		break
	}
	return obs, nil
}

// Inspect only public WireGuard settings; never call `wg show ... dump` or
// `wg show ... private-key` (which disclose secret material).
func (b *Backend) inspectPublicWG(ctx context.Context, o *observedLink) error {
	get := func(field string) ([]byte, error) {
		result, err := b.runner.Run(ctx, b.wgBinary, "show", o.Name, field)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect WireGuard %s", field)
		}
		return result.Stdout, nil
	}
	key, err := get("public-key")
	if err != nil {
		return err
	}
	o.PublicKey, err = parseObservedPublicKey(key)
	if err != nil {
		return err
	}
	port, err := get("listen-port")
	if err != nil {
		return err
	}
	portText := strings.TrimSpace(string(port))
	if portText != "" && portText != "off" {
		n, e := strconv.ParseUint(portText, 10, 16)
		if e != nil {
			return fmt.Errorf("invalid WireGuard listening port")
		}
		o.ListenPort = uint16(n)
	}
	peers, err := get("peers")
	if err != nil {
		return err
	}
	o.Peers = strings.Fields(string(peers))
	allowed, err := get("allowed-ips")
	if err != nil {
		return err
	}
	keepalive, err := get("persistent-keepalive")
	if err != nil {
		return err
	}
	endpoints, err := get("endpoints")
	if err != nil {
		return err
	}
	if len(o.Peers) > 1 {
		return nil
	}
	if len(o.Peers) == 0 {
		if strings.TrimSpace(string(allowed)) != "" || strings.TrimSpace(string(keepalive)) != "" || strings.TrimSpace(string(endpoints)) != "" {
			return fmt.Errorf("WireGuard peer metadata is inconsistent")
		}
		return nil
	}
	o.AllowedIPs, err = parsePeerAttribute(allowed, o.Peers[0])
	if err != nil {
		return err
	}
	keep, err := parsePeerAttribute(keepalive, o.Peers[0])
	if err != nil {
		return err
	}
	if keep != "" && keep != "off" {
		n, e := strconv.ParseUint(keep, 10, 16)
		if e != nil {
			return fmt.Errorf("invalid WireGuard keepalive")
		}
		o.Keepalive = uint16(n)
	}
	o.Endpoint, err = parsePeerAttribute(endpoints, o.Peers[0])
	return err
}

// wireguard-tools prints exactly "(none)" for a new interface without a
// private key. Normalize that one sentinel at the read boundary, but fail
// closed for empty, malformed, noncanonical, or all-zero public keys.
func parseObservedPublicKey(raw []byte) (string, error) {
	text := strings.TrimSpace(string(raw))
	if text == "(none)" {
		return "", nil
	}
	if len(text) != 44 {
		return "", fmt.Errorf("unexpected WireGuard public-key observation")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != text {
		return "", fmt.Errorf("invalid WireGuard public-key observation")
	}
	nonzero := false
	for _, b := range decoded {
		if b != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		return "", fmt.Errorf("invalid all-zero WireGuard public-key observation")
	}
	return text, nil
}

func (b *Backend) Plan(ctx context.Context, req core.Request, observed core.Observation) (core.Plan, error) {
	obs, ok := observed.(observation)
	if !ok {
		return nil, fmt.Errorf("unexpected WireGuard observation")
	}
	if err := validateLink(req.Link); err != nil {
		return nil, err
	}
	name, _ := InterfaceName(req.Link.ID)
	route, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve WireGuard underlay: %w", err)
	}
	if route.Source != req.Link.Underlay.Local {
		return nil, fmt.Errorf("WireGuard local underlay does not match selected route source")
	}
	rule := linux.InboundFirewallRule{Peer: req.Link.Underlay.Peer, Local: req.Link.Underlay.Local, InputInterface: route.Device, Protocol: 17, DestinationPort: req.Link.WireGuard.ListenPort}
	firewallPresent, err := b.firewall.HasInbound(ctx, req.Link.ID, rule)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect WireGuard firewall rule: %w", err)
	}
	anyOwned, err := b.firewall.HasOwnedInbound(ctx, req.Link.ID, false)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect WireGuard firewall ownership: %w", err)
	}
	if !firewallPresent && anyOwned {
		return nil, stlerr.New(stlerr.CodeConflict, "wireguard_plan", string(req.Link.ID), "wireguard", "owned firewall rule differs from current underlay; reconcile before changing")
	}
	p := plan{link: req.Link, name: name, route: route, firewallRule: rule}
	switch req.Operation {
	case core.OperationEnsure:
		key, err := b.keys.Load(req.Link.ID)
		if err != nil {
			return nil, fmt.Errorf("WireGuard Link private key is unavailable or unsafe: %w", err)
		}
		pub, err := key.PublicKey()
		if err != nil || pub != req.Link.WireGuard.LocalPublicKey {
			return nil, stlerr.New(stlerr.CodeConflict, "wireguard_plan", string(req.Link.ID), "wireguard", "private key does not match desired local public identity")
		}
		firewallClaim, err := linux.InboundFirewallClaim(req.Link.ID, rule)
		if err != nil {
			return nil, err
		}
		p.resources = desiredResources(req.Link, name, firewallClaim)
		p.interfaceChange = !obs.Target.matches(req.Link, name)
		p.firewallChange = !firewallPresent
	case core.OperationRemove:
		// Lock the UDP socket even for historical records without its claim.
		p.resources = []domain.ResourceClaim{{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(req.Link.WireGuard.ListenPort))}}
		p.interfaceChange = obs.Target.Exists && obs.Target.Owner == req.Link.ID
		p.firewallChange = firewallPresent
	default:
		return nil, fmt.Errorf("unsupported WireGuard operation")
	}
	return p, nil
}

func (b *Backend) Validate(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) error {
	obs, ok := observed.(observation)
	if !ok {
		return fmt.Errorf("unexpected WireGuard observation")
	}
	p, ok := candidate.(plan)
	if !ok {
		return fmt.Errorf("unexpected WireGuard plan")
	}
	if err := validateLink(req.Link); err != nil {
		return err
	}
	route, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
	if err != nil {
		return err
	}
	if route.Source != req.Link.Underlay.Local || route.Device != p.route.Device {
		return fmt.Errorf("WireGuard underlay route changed during planning")
	}
	if obs.Target.Exists {
		if obs.Target.Owner != req.Link.ID {
			return stlerr.New(stlerr.CodeConflict, "wireguard_validate", string(req.Link.ID), "wireguard", "WireGuard interface name belongs to another owner")
		}
		claim := domain.ResourceClaim{Kind: domain.ResourceInterface, Key: p.name}
		if err := linux.RequireOwned(req.Link.ID, claim, req.OwnedResources); err != nil {
			return err
		}
		if !obs.Target.matches(req.Link, p.name) {
			return stlerr.New(stlerr.CodeConflict, "wireguard_validate", string(req.Link.ID), "wireguard", "owned WireGuard interface differs from desired configuration; manual reconciliation required")
		}
	}
	if p.firewallChange && req.Operation == core.OperationRemove || (!p.firewallChange && req.Operation == core.OperationEnsure) {
		claim, err := linux.InboundFirewallClaim(req.Link.ID, p.firewallRule)
		if err != nil {
			return err
		}
		if err := linux.RequireOwned(req.Link.ID, claim, req.OwnedResources); err != nil {
			return err
		}
	}
	if req.Operation == core.OperationRemove {
		// Engine holds the canonical Link and resource locks here. Remove's
		// rollback must be capable of recreating an owned interface after
		// a later Verify/commit failure. Do not start any destructive work
		// when the required private key has drifted or is missing.
		if p.interfaceChange {
			if err := b.requireRecreationCredential(req.Link); err != nil {
				return err
			}
		}
		return b.rejectForeignReplacement(ctx, req.Link.ID, p.name)
	}
	// Common host inspection supports only interface/address/subnet/UDP;
	// firewall claims and WG public identity have dedicated inspectors.
	var claims []domain.ResourceClaim
	if !obs.Target.Exists {
		for _, claim := range p.resources {
			switch claim.Kind {
			case domain.ResourceInterface, domain.ResourceLinkAddress, domain.ResourceLinkSubnet, domain.ResourceUDPListenPort:
				claims = append(claims, claim)
			}
		}
	}
	conflicts, err := b.collisions.Inspect(ctx, claims)
	if err != nil {
		return fmt.Errorf("cannot inspect WireGuard resource collisions: %w", err)
	}
	for _, c := range conflicts {
		if c.Owner != req.Link.ID {
			return stlerr.New(stlerr.CodeConflict, "wireguard_validate", string(req.Link.ID), "wireguard", "WireGuard host resource conflicts with existing state")
		}
	}
	if err := b.rejectForeignReplacement(ctx, req.Link.ID, p.name); err != nil {
		return err
	}
	if err := b.rejectWireGuardSocketAndKeyCollision(ctx, req.Link); err != nil {
		return err
	}
	return nil
}

// requireRecreationCredential verifies the same protected local key which
// createOwnedInterface needs for Remove compensation. Keep the preflight
// private-key-free in errors and avoid generic `wg show` secret inspection.
// Apply repeats this check immediately before its first destructive action:
// the protected file might have changed after the Engine's Validate call.
func (b *Backend) requireRecreationCredential(link domain.Link) error {
	fd, err := b.keys.OpenForWireGuard(link.ID, link.WireGuard.LocalPublicKey)
	if err != nil {
		return stlerr.Wrap(stlerr.CodeConflict, "wireguard_remove", string(link.ID), string(link.Backend),
			"protected WireGuard credential needed for safe removal rollback is unavailable or invalid", err)
	}
	if err := fd.Close(); err != nil {
		return fmt.Errorf("close verified WireGuard rollback credential: %w", err)
	}
	return nil
}

func (b *Backend) rejectForeignReplacement(ctx context.Context, id domain.LinkID, name string) error {
	conflicts, err := b.collisions.Inspect(ctx, []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: name}})
	if err != nil {
		return err
	}
	for _, c := range conflicts {
		if c.Owner != id {
			return stlerr.New(stlerr.CodeConflict, "wireguard_validate", string(id), "wireguard", "interface name is occupied by unowned/foreign state")
		}
	}
	return nil
}

// Kernel WireGuard sockets may not appear as ordinary userspace UDP listeners.
// Check ALL WireGuard interfaces separately, in addition to the common host
// collision inspector (which catches FOU/GUE and userspace listeners).
func (b *Backend) rejectWireGuardSocketAndKeyCollision(ctx context.Context, link domain.Link) error {
	name, _ := InterfaceName(link.ID)
	for _, entry := range []struct{ field, want string }{{"listen-port", strconv.Itoa(int(link.WireGuard.ListenPort))}, {"public-key", link.WireGuard.LocalPublicKey}} {
		out, err := b.runner.Run(ctx, b.wgBinary, "show", "all", entry.field)
		if err != nil {
			return fmt.Errorf("cannot inspect WireGuard global %s", entry.field)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out.Stdout)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return fmt.Errorf("invalid WireGuard global %s observation", entry.field)
			}
			if fields[0] != name && fields[1] == entry.want {
				return stlerr.New(stlerr.CodeConflict, "wireguard_validate", string(link.ID), "wireguard", "WireGuard listener or local public key already used by another interface")
			}
		}
	}
	return nil
}

func (b *Backend) Verify(ctx context.Context, req core.Request) (core.Observation, error) {
	current, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return nil, err
	}
	obs := current.(observation)
	owned, err := b.firewall.HasOwnedInbound(ctx, req.Link.ID, false)
	if err != nil {
		return nil, err
	}
	name, _ := InterfaceName(req.Link.ID)
	switch req.Operation {
	case core.OperationEnsure:
		route, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
		if err != nil {
			return nil, err
		}
		rule := linux.InboundFirewallRule{Peer: req.Link.Underlay.Peer, Local: req.Link.Underlay.Local, InputInterface: route.Device, Protocol: 17, DestinationPort: req.Link.WireGuard.ListenPort}
		exact, err := b.firewall.HasInbound(ctx, req.Link.ID, rule)
		if err != nil {
			return nil, err
		}
		if !obs.Target.matches(req.Link, name) || !exact || !owned {
			return nil, fmt.Errorf("WireGuard interface/firewall verification failed")
		}
	case core.OperationRemove:
		if obs.Target.Exists && obs.Target.Owner == req.Link.ID {
			return nil, fmt.Errorf("owned WireGuard interface still exists")
		}
		if owned {
			return nil, fmt.Errorf("owned WireGuard firewall rule still exists")
		}
	default:
		return nil, fmt.Errorf("unsupported WireGuard verification operation")
	}
	return current, nil
}
