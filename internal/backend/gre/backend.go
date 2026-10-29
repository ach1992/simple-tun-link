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
	AddAddress  func(context.Context, int, netip.Prefix) error
	SetUp       func(context.Context, int) error
	DeleteLink  func(context.Context, int) error
	LookupIndex func(string) (int, error)
	ModuleProbe func(context.Context, string) bool
}

type Backend struct {
	runner      linux.Runner
	routes      RouteResolver
	firewall    Firewall
	collisions  CollisionInspector
	ipBinary    string
	setAlias    func(context.Context, int, string) error
	addAddress  func(context.Context, int, netip.Prefix) error
	setUp       func(context.Context, int) error
	deleteLink  func(context.Context, int) error
	lookupIndex func(string) (int, error)
	moduleProbe func(context.Context, string) bool
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
	addAddress := opts.AddAddress
	if addAddress == nil {
		addAddress = linux.AddIPv4AddressByIndex
	}
	setUp := opts.SetUp
	if setUp == nil {
		setUp = linux.SetLinkUpByIndex
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
	moduleProbe := opts.ModuleProbe
	if moduleProbe == nil {
		moduleProbe = (linux.KernelModuleProbe{Runner: opts.Runner}).AvailableButNotLoaded
	}
	return &Backend{
		moduleProbe: moduleProbe,
		runner:      opts.Runner, routes: opts.Routes, firewall: opts.Firewall,
		collisions: opts.Collisions, ipBinary: ip, setAlias: setAlias, addAddress: addAddress, setUp: setUp,
		deleteLink: deleteLink, lookupIndex: lookupIndex,
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
		if b.moduleProbe(ctx, "ip_gre") {
			return nil, core.KernelModuleNotLoaded("ip_gre")
		}
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
		links[i].IPv4Addresses, err = parseIPv4Addresses(addrResult.Stdout, name, links[i].IfIndex)
		if err != nil {
			return nil, err
		}
		obs.Target = links[i]
		obs.Links[i] = links[i]
		break
	}
	return obs, nil
}

// These reasons are authored, credential-free operator categories, not
// interpretations of arbitrary kernel output or a remote Setup Link.
func grePlanningIssue(link domain.Link, code stlerr.Code, reason, next, detail string, cause error) *stlerr.Error {
	issue := stlerr.Wrap(code, "gre_plan", string(link.ID), string(domain.BackendGRE), detail, cause)
	issue.ReasonCode, issue.NextStep = reason, next
	return issue
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
		return nil, grePlanningIssue(req.Link, stlerr.CodePlan, "gre_underlay_route_unverified",
			"On the receiver, check the route to the sender public IPv4 with ip -4 route get PEER_IP. Verify local underlay routing first; no tunnel was applied.",
			"cannot verify the kernel route to GRE peer", err)
	}
	if route.Source != req.Link.Underlay.Local {
		return nil, grePlanningIssue(req.Link, stlerr.CodePlan, "gre_underlay_source_mismatch",
			"The kernel-selected outgoing source IPv4 differs from the local underlay IPv4 expected by this Setup Link. Inspect ip -4 route get PEER_IP on this receiver and correct the endpoint/route before re-importing.",
			"selected GRE underlay source does not match the kernel route", nil)
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
		return nil, grePlanningIssue(req.Link, stlerr.CodeInspect, "gre_firewall_readback_unverified",
			"STL could not confirm its exact GRE ingress firewall rule. Inspect firewall service/readback availability and STL ownership without changing other rules; no tunnel was applied.",
			"cannot verify GRE ingress firewall rule", err)
	}
	anyOwnedFirewall, err := b.firewall.HasOwnedInbound(ctx, req.Link.ID, false)
	if err != nil {
		return nil, grePlanningIssue(req.Link, stlerr.CodeInspect, "gre_firewall_ownership_unverified",
			"STL could not verify existing GRE firewall ownership. Inspect STL Link status and firewall service availability read-only; do not adopt or flush another owner's rules.",
			"cannot verify GRE firewall ownership", err)
	}
	if !firewallPresent && anyOwnedFirewall {
		return nil, grePlanningIssue(req.Link, stlerr.CodeConflict, "gre_firewall_route_drift",
			"An earlier STL-owned firewall rule targets a different route. Inspect this Link and its route in STL before retrying; never replace the rule blindly.",
			"existing owned GRE firewall does not match this underlay route", nil)
	}

	p := plan{link: req.Link, name: name, route: route, firewallRule: rule}
	if mapping, managed := desiredFOUMapping(req.Link, route); managed {
		exact, collision := mappingAtPort(obs.Mappings, mapping)
		if collision {
			return nil, grePlanningIssue(req.Link, stlerr.CodeConflict, "gre_receive_port_occupied",
				"The selected GRE FOU/GUE UDP receive port is already mapped differently. Select a non-conflicting port or reconcile the exact owned mapping in STL.",
				"GRE FOU/GUE receive port is already occupied", nil)
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
		// Earlier persisted GRE Links did not record the shared receive claim.
		// Lock it for Remove as well, so a concurrent cross-encapsulation
		// Ensure cannot race our deletion. This is a synchronization claim,
		// NOT proof of ownership; Validate still checks Prior.OwnedResources.
		p.resources = []domain.ResourceClaim{greReceiveClaim(req.Link)}
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
	wantedReceive := greReceiveIdentity(req.Link.Underlay.Local, req.Link.Underlay.Peer, req.Link.GRE.KeyEnabled, req.Link.GRE.Key)
	for _, existing := range obs.Links {
		if existing.Name != p.name && existing.receiveIdentity() == wantedReceive {
			return stlerr.New(stlerr.CodeConflict, "gre_validate", string(req.Link.ID), string(req.Link.Backend), "GRE underlay/key receive identity is already in use across encapsulations")
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
