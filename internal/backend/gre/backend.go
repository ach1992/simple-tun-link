package gre

import (
	"context"
	"fmt"
	"net"
	"net/netip"

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
	EnsureInbound(context.Context, domain.LinkID, linux.InboundFirewallRule) (func(context.Context) error, bool, error)
	RemoveInbound(context.Context, domain.LinkID, linux.InboundFirewallRule) (bool, error)
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
	DeleteLink  func(context.Context, int) error
	LookupIndex func(string) (int, error)
}

type Backend struct {
	runner      linux.Runner
	routes      RouteResolver
	firewall    Firewall
	collisions  CollisionInspector
	ipBinary    string
	setAlias    func(context.Context, int, string) error
	deleteLink  func(context.Context, int) error
	lookupIndex func(string) (int, error)
}

func New(opts Options) (*Backend, error) {
	if opts.Runner == nil || opts.Routes == nil || opts.Firewall == nil || opts.Collisions == nil {
		return nil, fmt.Errorf("GRE runner, route resolver, firewall, and collision inspector are required")
	}
	ip := opts.IPBinary
	if ip == "" {
		ip = "ip"
	}
	setAlias := opts.SetAlias
	if setAlias == nil {
		setAlias = linux.SetLinkAliasByIndex
	}
	deleteLink := opts.DeleteLink
	if deleteLink == nil {
		deleteLink = linux.DeleteLinkByIndex
	}
	lookupIndex := opts.LookupIndex
	if lookupIndex == nil {
		lookupIndex = func(name string) (int, error) {
			device, err := net.InterfaceByName(name)
			if err != nil {
				return 0, err
			}
			return device.Index, nil
		}
	}
	return &Backend{
		runner: opts.Runner, routes: opts.Routes, firewall: opts.Firewall,
		collisions: opts.Collisions, ipBinary: ip, setAlias: setAlias, deleteLink: deleteLink, lookupIndex: lookupIndex,
	}, nil
}

func (*Backend) Kind() domain.Backend { return domain.BackendGRE }

type observation struct {
	Target   observedLink
	Links    []observedLink
	Mappings []fouMapping
}

func (o observation) ObservedResources() []domain.ResourceClaim {
	if !o.Target.Exists {
		return nil
	}
	out := []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: o.Target.Name}}
	for _, prefix := range o.Target.IPv4Addresses {
		out = append(out,
			domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: prefix.Addr().String()},
			domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: prefix.Masked().String()},
		)
	}
	return out
}

type plan struct {
	link            domain.Link
	name            string
	route           linux.Route
	firewallRule    linux.InboundFirewallRule
	fouMapping      fouMapping
	fouManaged      bool
	fouPresent      bool
	resources       []domain.ResourceClaim
	interfaceChange bool
	firewallChange  bool
	fouChange       bool
}

func (p plan) Empty() bool { return !p.interfaceChange && !p.firewallChange && !p.fouChange }
func (p plan) Resources() []domain.ResourceClaim {
	return append([]domain.ResourceClaim(nil), p.resources...)
}

func (b *Backend) Inspect(ctx context.Context, link domain.Link) (core.Observation, error) {
	name, err := InterfaceName(link.ID)
	if err != nil {
		return nil, err
	}
	result, err := b.runner.Run(ctx, b.ipBinary, "-details", "-json", "link", "show", "type", "gre")
	if err != nil {
		return nil, fmt.Errorf("inspect GRE links: %w", err)
	}
	links, err := parseGRELinks(result.Stdout)
	if err != nil {
		return nil, err
	}
	obs := observation{Links: links}
	if link.Encapsulation == domain.EncapFOU || link.Encapsulation == domain.EncapGUE {
		obs.Mappings, err = b.inspectFOU(ctx)
		if err != nil {
			return nil, err
		}
	}
	for i := range links {
		if links[i].Name != name {
			continue
		}
		addrResult, err := b.runner.Run(ctx, b.ipBinary, "-json", "address", "show", "dev", name)
		if err != nil {
			return nil, fmt.Errorf("inspect GRE Link Addresses: %w", err)
		}
		links[i].IPv4Addresses, err = parseIPv4Addresses(addrResult.Stdout, name)
		if err != nil {
			return nil, err
		}
		obs.Target = links[i]
		obs.Links[i] = links[i]
		break
	}
	return obs, nil
}

func (b *Backend) Plan(ctx context.Context, req core.Request, observed core.Observation) (core.Plan, error) {
	obs, ok := observed.(observation)
	if !ok {
		return nil, fmt.Errorf("unexpected GRE observation type")
	}
	if err := validateLink(req.Link); err != nil {
		return nil, err
	}
	name, _ := InterfaceName(req.Link.ID)
	route, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
	if err != nil {
		return nil, fmt.Errorf("resolve GRE underlay route: %w", err)
	}
	if route.Source != req.Link.Underlay.Local {
		return nil, fmt.Errorf("selected local underlay does not match kernel route source")
	}
	protocol, destinationPort := uint8(greProtocol), uint16(0)
	if req.Link.Encapsulation == domain.EncapFOU || req.Link.Encapsulation == domain.EncapGUE {
		protocol, destinationPort = 17, req.Link.GRE.UDPPort
	}
	rule := linux.InboundFirewallRule{
		Peer: req.Link.Underlay.Peer, Local: req.Link.Underlay.Local,
		InputInterface: route.Device, Protocol: protocol, DestinationPort: destinationPort,
	}
	firewallPresent, err := b.firewall.HasInbound(ctx, req.Link.ID, rule)
	if err != nil {
		return nil, fmt.Errorf("inspect GRE firewall rule: %w", err)
	}
	anyOwnedFirewall, err := b.firewall.HasOwnedInbound(ctx, req.Link.ID, false)
	if err != nil {
		return nil, fmt.Errorf("inspect GRE firewall ownership: %w", err)
	}
	if !firewallPresent && anyOwnedFirewall {
		return nil, stlerr.New(stlerr.CodeConflict, "gre_plan", string(req.Link.ID), string(req.Link.Backend), "an owned GRE firewall rule exists for a different underlay route; reconciliation is required")
	}

	p := plan{link: req.Link, name: name, route: route, firewallRule: rule}
	if mapping, managed := desiredFOUMapping(req.Link, route); managed {
		exact, collision := mappingAtPort(obs.Mappings, mapping)
		if collision {
			return nil, stlerr.New(stlerr.CodeConflict, "gre_plan", string(req.Link.ID), string(req.Link.Backend), "GRE FOU/GUE receive port is occupied by a different mapping")
		}
		p.fouMapping, p.fouManaged, p.fouPresent = mapping, true, exact
	}
	switch req.Operation {
	case core.OperationEnsure:
		claim, err := linux.InboundFirewallClaim(req.Link.ID, rule)
		if err != nil {
			return nil, err
		}
		p.resources = desiredResources(req.Link, name, claim)
		p.interfaceChange = !obs.Target.matches(req.Link, name)
		p.firewallChange = !firewallPresent
		p.fouChange = p.fouManaged && !p.fouPresent
	case core.OperationRemove:
		p.interfaceChange = obs.Target.Exists && obs.Target.Owner == req.Link.ID
		p.firewallChange = firewallPresent
		p.fouChange = p.fouManaged && p.fouPresent
	default:
		return nil, fmt.Errorf("unsupported GRE operation %q", req.Operation)
	}
	return p, nil
}

func (b *Backend) Validate(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) error {
	obs, ok := observed.(observation)
	if !ok {
		return fmt.Errorf("unexpected GRE observation type")
	}
	p, ok := candidate.(plan)
	if !ok {
		return fmt.Errorf("unexpected GRE plan type")
	}
	if err := validateLink(req.Link); err != nil {
		return err
	}
	freshRoute, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
	if err != nil {
		return fmt.Errorf("recheck GRE underlay route: %w", err)
	}
	if freshRoute.Source != req.Link.Underlay.Local || freshRoute.Device != p.route.Device {
		return fmt.Errorf("underlay route changed after GRE planning")
	}
	if obs.Target.Exists && obs.Target.Owner != req.Link.ID {
		return stlerr.New(stlerr.CodeConflict, "gre_validate", string(req.Link.ID), string(req.Link.Backend), "GRE interface name is not owned by this Link")
	}
	if req.Operation == core.OperationEnsure && obs.Target.Exists && !obs.Target.matches(req.Link, p.name) {
		return stlerr.New(stlerr.CodeConflict, "gre_validate", string(req.Link.ID), string(req.Link.Backend), "owned GRE interface differs from requested configuration; explicit repair is required")
	}
	if req.Operation == core.OperationRemove {
		if obs.Target.Exists {
			claim := domain.ResourceClaim{Kind: domain.ResourceInterface, Key: p.name}
			if err := linux.RequireOwned(req.Link.ID, claim, req.OwnedResources); err != nil {
				return err
			}
			if !obs.Target.matches(req.Link, p.name) {
				return stlerr.New(stlerr.CodeConflict, "gre_remove", string(req.Link.ID), string(req.Link.Backend), "owned GRE interface no longer matches committed state; refusing destructive removal")
			}
		}
		if p.firewallChange {
			claim, err := linux.InboundFirewallClaim(req.Link.ID, p.firewallRule)
			if err != nil {
				return err
			}
			if err := linux.RequireOwned(req.Link.ID, claim, req.OwnedResources); err != nil {
				return err
			}
		}
		if p.fouChange {
			if err := linux.RequireOwned(req.Link.ID, fouResourceClaim(req.Link), req.OwnedResources); err != nil {
				return err
			}
		}
		return b.rejectForeignInterfaceReplacement(ctx, req.Link.ID, p.name)
	}

	if p.fouPresent {
		if err := linux.RequireOwned(req.Link.ID, fouResourceClaim(req.Link), req.OwnedResources); err != nil {
			return stlerr.New(stlerr.CodeConflict, "gre_validate", string(req.Link.ID), string(req.Link.Backend), "existing FOU/GUE receive mapping is not proven to belong to this Link")
		}
	}
	claims := commonCollisionClaims(req.Link, p.name)
	if p.fouPresent {
		claims = filterClaimKind(claims, domain.ResourceUDPListenPort)
	}
	conflicts, err := b.collisions.Inspect(ctx, claims)
	if err != nil {
		return fmt.Errorf("inspect GRE resource collisions: %w", err)
	}
	for _, conflict := range conflicts {
		if conflict.Owner != req.Link.ID {
			return stlerr.New(stlerr.CodeConflict, "gre_validate", string(req.Link.ID), string(req.Link.Backend), "GRE host resource conflicts with existing state")
		}
	}
	wantedID := backendIdentity(req.Link.Underlay.Local, req.Link.Underlay.Peer, req.Link.GRE.KeyEnabled, req.Link.GRE.Key, req.Link.Encapsulation, req.Link.GRE.UDPPort)
	for _, existing := range obs.Links {
		if existing.Name != p.name && existing.backendIdentity() == wantedID {
			return stlerr.New(stlerr.CodeConflict, "gre_validate", string(req.Link.ID), string(req.Link.Backend), "GRE underlay/key tuple is already in use")
		}
	}
	return nil
}

func (b *Backend) rejectForeignInterfaceReplacement(ctx context.Context, id domain.LinkID, name string) error {
	conflicts, err := b.collisions.Inspect(ctx, []domain.ResourceClaim{{Kind: domain.ResourceInterface, Key: name}})
	if err != nil {
		return err
	}
	for _, conflict := range conflicts {
		if conflict.Owner != "" && conflict.Owner == id {
			continue
		}
		return stlerr.New(stlerr.CodeConflict, "gre_remove", string(id), string(domain.BackendGRE), "GRE interface name is occupied by state not proven to belong to this Link")
	}
	return nil
}

func (b *Backend) Verify(ctx context.Context, req core.Request) (core.Observation, error) {
	observed, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return nil, err
	}
	obs := observed.(observation)
	ownedFirewall, err := b.firewall.HasOwnedInbound(ctx, req.Link.ID, false)
	if err != nil {
		return nil, err
	}
	switch req.Operation {
	case core.OperationEnsure:
		route, err := b.routes.Resolve(ctx, req.Link.Underlay.Peer)
		if err != nil {
			return nil, err
		}
		protocol, destinationPort := uint8(greProtocol), uint16(0)
		if req.Link.Encapsulation == domain.EncapFOU || req.Link.Encapsulation == domain.EncapGUE {
			protocol, destinationPort = 17, req.Link.GRE.UDPPort
		}
		rule := linux.InboundFirewallRule{Peer: req.Link.Underlay.Peer, Local: req.Link.Underlay.Local, InputInterface: route.Device, Protocol: protocol, DestinationPort: destinationPort}
		exactFirewall, err := b.firewall.HasInbound(ctx, req.Link.ID, rule)
		if err != nil {
			return nil, err
		}
		name, _ := InterfaceName(req.Link.ID)
		if !obs.Target.matches(req.Link, name) || !exactFirewall || !ownedFirewall {
			return nil, fmt.Errorf("GRE Link verification failed")
		}
		if mapping, managed := desiredFOUMapping(req.Link, route); managed {
			exact, collision := mappingAtPort(obs.Mappings, mapping)
			if !exact || collision {
				return nil, fmt.Errorf("GRE FOU/GUE receive mapping verification failed")
			}
		}
	case core.OperationRemove:
		if obs.Target.Exists && obs.Target.Owner == req.Link.ID {
			return nil, fmt.Errorf("owned GRE interface still exists")
		}
		if ownedFirewall {
			return nil, fmt.Errorf("owned GRE firewall rule still exists")
		}
		if req.Link.Encapsulation == domain.EncapFOU || req.Link.Encapsulation == domain.EncapGUE {
			for _, mapping := range obs.Mappings {
				if mapping.Port == req.Link.GRE.UDPPort {
					return nil, fmt.Errorf("GRE FOU/GUE receive port still exists after removal")
				}
			}
		}
	}
	return obs, nil
}

func filterClaimKind(claims []domain.ResourceClaim, kind string) []domain.ResourceClaim {
	out := make([]domain.ResourceClaim, 0, len(claims))
	for _, claim := range claims {
		if claim.Kind != kind {
			out = append(out, claim)
		}
	}
	return out
}
