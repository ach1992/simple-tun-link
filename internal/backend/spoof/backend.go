// Package spoof integrates the authenticated Direct TUN carrier with the
// canonical STL Engine. Runtime reachability is not an Ensure prerequisite.
package spoof

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type HostObservation struct {
	UnitExists, UnitOwned, UnitActive                        bool
	InterfaceExists, InterfaceOwned, AddressReady, PeerRoute bool
	RuntimeReady                                             bool // local managed helper + TUN only; never remote connectivity
	FirewallExists                                           bool // exact original Link-owned INPUT rule(s) are installed
	FirewallReady                                            bool // all requested Link-owned rules present and exact, not actual external reachability
	HelperPID                                                int  // exact verified systemd MainPID
}
type Host interface {
	Inspect(context.Context, domain.Link) (HostObservation, error)
	Preflight(context.Context, domain.Link, bool) error
	Start(context.Context, domain.Link) (core.Rollback, error)
	Stop(context.Context, domain.Link) (core.Rollback, error)
}
type Backend struct{ host Host }

func New(host Host) (*Backend, error) {
	if host == nil {
		return nil, errors.New("Spoof host required")
	}
	return &Backend{host: host}, nil
}
func (*Backend) Kind() domain.Backend { return domain.BackendSpoof }

type observation struct {
	link domain.Link
	host HostObservation
}

func (o observation) ObservedResources() []domain.ResourceClaim {
	var result []domain.ResourceClaim
	if o.host.UnitExists {
		result = append(result, domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "spoof/unit/" + string(o.link.ID)})
	}
	if o.link.Spoof.ManageIngress && o.host.FirewallExists {
		result = append(result, domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "spoof/ingress/" + string(o.link.ID)})
	}
	if o.host.InterfaceExists {
		name, _ := carrier.TunnelName(o.link.ID)
		result = append(result, domain.ResourceClaim{Kind: domain.ResourceInterface, Key: name})
		if o.host.AddressReady {
			result = append(result, domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: o.link.Addresses.Local.Addr().String()})
		}
	}
	return result
}

type plan struct {
	link        domain.Link
	resources   []domain.ResourceClaim
	start, stop bool
}

func (p plan) Empty() bool                       { return !p.start && !p.stop }
func (p plan) Resources() []domain.ResourceClaim { return slices.Clone(p.resources) }
func expectedClaims(link domain.Link) ([]domain.ResourceClaim, error) {
	name, err := carrier.TunnelName(link.ID)
	if err != nil {
		return nil, err
	}
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: name},
		{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
		{Kind: domain.ResourceRoute, Key: "spoof/peer/" + link.Addresses.Peer.String()},
		{Kind: domain.ResourceBackendID, Key: "spoof/unit/" + string(link.ID)},
		{Kind: domain.ResourceBackendID, Key: "spoof/material/" + string(link.ID) + "/" + link.Spoof.MaterialSHA256},
	}
	if link.Spoof.ManageIngress {
		claims = append(claims, domain.ResourceClaim{Kind: domain.ResourceBackendID,
			Key: "spoof/ingress/" + string(link.ID)})
	}
	profile := link.Spoof.OuterProtocol
	primary := netip.AddrPortFrom(link.Underlay.Local, link.Spoof.ListenPort)
	otherEndpoints, err := domain.ParseSpoofAlternates(link.Spoof.LocalAlternates, primary)
	if err != nil {
		return nil, err
	}
	allEndpoints := append([]netip.AddrPort{primary}, otherEndpoints...)
	for _, ep := range allEndpoints {
		port := strconv.Itoa(int(ep.Port()))
		if profile == "" || profile == "udp" || profile == "auto" {
			claims = append(claims, domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: port})
		}
		if profile == "icmp" || profile == "auto" {
			claims = append(claims, domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "spoof/icmp-receive-id/" + port})
		}
		if profile != "" && profile != "udp" && profile != "icmp" {
			claims = append(claims, domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "spoof/raw-receive-id/" + port})
		}
	}
	for _, claim := range claims {
		if err := claim.Validate(); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(claims, func(a, b domain.ResourceClaim) int {
		if a.Canonical() < b.Canonical() {
			return -1
		}
		if a.Canonical() > b.Canonical() {
			return 1
		}
		return 0
	})
	claims = slices.CompactFunc(claims, func(a, b domain.ResourceClaim) bool { return a.Canonical() == b.Canonical() })
	return claims, nil
}
func ValidateTopology(link domain.Link) error {
	if link.Backend != domain.BackendSpoof {
		return errors.New("not a Spoof Link")
	}
	return link.Validate()
}

// DiagnosticState is a read-only exact-owner observation. Peer liveness is
// separately attested by a PID-bound, fresh helper status report.
func (b *Backend) DiagnosticState(ctx context.Context, link domain.Link) (HostObservation, error) {
	if err := ValidateTopology(link); err != nil {
		return HostObservation{}, err
	}
	return b.host.Inspect(ctx, link)
}

func (b *Backend) Inspect(ctx context.Context, link domain.Link) (core.Observation, error) {
	if err := ValidateTopology(link); err != nil {
		return nil, err
	}
	h, err := b.host.Inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	return observation{link: link, host: h}, nil
}
func (b *Backend) Plan(_ context.Context, req core.Request, observed core.Observation) (core.Plan, error) {
	o, ok := observed.(observation)
	if !ok || o.link != req.Link {
		return nil, errors.New("Spoof observed Link changed")
	}
	claims, err := expectedClaims(req.Link)
	if err != nil {
		return nil, err
	}
	p := plan{link: req.Link, resources: claims}
	switch req.Operation {
	case core.OperationEnsure:
		p.start = !o.host.RuntimeReady || req.Link.Spoof.ManageIngress && !o.host.FirewallReady
	case core.OperationRemove:
		p.stop = o.host.UnitExists || o.host.InterfaceExists || req.Link.Spoof.ManageIngress && o.host.FirewallExists
	default:
		return nil, errors.New("unsupported Spoof operation")
	}
	return p, nil
}
func sameTopologyExceptBinding(a, b domain.Link) bool {
	if a.Backend != domain.BackendSpoof || b.Backend != domain.BackendSpoof {
		return false
	}
	// The Engine's authenticated enrollment may update ONLY peer public key.
	a.Spoof.PeerPublicKey = ""
	b.Spoof.PeerPublicKey = ""
	return a == b
}
func exactOwned(req core.Request, expected []domain.ResourceClaim) bool {
	return req.Prior != nil && sameTopologyExceptBinding(*req.Prior, req.Link) && slices.Equal(req.OwnedResources, expected)
}
func (b *Backend) Validate(ctx context.Context, req core.Request, observed core.Observation, proposed core.Plan) error {
	o, ok := observed.(observation)
	p, pok := proposed.(plan)
	if !ok || !pok || o.link != req.Link || p.link != req.Link {
		return errors.New("Spoof stale plan")
	}
	expected, err := expectedClaims(req.Link)
	if err != nil || !slices.Equal(expected, p.resources) {
		return errors.New("Spoof resource claims differ")
	}
	h := o.host
	if h.UnitExists && !h.UnitOwned || h.InterfaceExists && !h.InterfaceOwned {
		return errors.New("Spoof original unit/TUN ownership unverified")
	}
	if h.InterfaceExists && !h.UnitActive {
		return errors.New("Spoof orphan interface needs owner-scoped recovery")
	}
	if h.RuntimeReady && (!h.UnitActive || !h.InterfaceExists || !h.AddressReady || !h.PeerRoute) {
		return errors.New("Spoof local runtime readiness inconsistent")
	}
	switch req.Operation {
	case core.OperationEnsure:
		if req.Prior != nil && !exactOwned(req, expected) {
			return errors.New("Spoof previous committed topology/claims changed")
		}
		if req.Prior == nil && (h.UnitExists || h.InterfaceExists || req.Link.Spoof.ManageIngress && h.FirewallExists) {
			return errors.New("Spoof cannot adopt pre-existing service/TUN as new Link")
		}
		if h.UnitActive && !h.RuntimeReady {
			return errors.New("Spoof active helper is not locally ready; investigate before repair")
		}
		if p.start != (!h.RuntimeReady || req.Link.Spoof.ManageIngress && !h.FirewallReady) {
			return errors.New("Spoof Ensure plan stale")
		}
		return b.host.Preflight(ctx, req.Link, false)
	case core.OperationRemove:
		if !exactOwned(req, expected) {
			return errors.New("Spoof Remove requires exact committed ownership")
		}
		if p.stop != (h.UnitExists || h.InterfaceExists || req.Link.Spoof.ManageIngress && h.FirewallExists) {
			return errors.New("Spoof Remove plan stale")
		}
		return b.host.Preflight(ctx, req.Link, true)
	default:
		return errors.New("Spoof operation invalid")
	}
}
func (b *Backend) Apply(ctx context.Context, req core.Request, _ core.Observation, candidate core.Plan) (core.Rollback, error) {
	p, ok := candidate.(plan)
	if !ok || p.link != req.Link || p.Empty() {
		return nil, errors.New("Spoof invalid apply")
	}
	switch req.Operation {
	case core.OperationEnsure:
		if p.start {
			return b.host.Start(ctx, req.Link)
		}
	case core.OperationRemove:
		if p.stop {
			return b.host.Stop(ctx, req.Link)
		}
	}
	return nil, fmt.Errorf("Spoof unexpected apply %s", req.Operation)
}
func (b *Backend) Verify(ctx context.Context, req core.Request) (core.Observation, error) {
	current, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return nil, err
	}
	h := current.(observation).host
	switch req.Operation {
	case core.OperationEnsure:
		if !h.RuntimeReady || !h.UnitOwned || !h.UnitActive || !h.InterfaceOwned || !h.AddressReady || !h.PeerRoute ||
			req.Link.Spoof.ManageIngress && !h.FirewallReady {
			return nil, errors.New("Spoof managed helper/TUN/route not locally ready (no remote path required)")
		}
	case core.OperationRemove:
		if h.UnitExists || h.InterfaceExists || h.UnitActive || req.Link.Spoof.ManageIngress && h.FirewallExists {
			return nil, errors.New("Spoof host resources still present")
		}
	default:
		return nil, errors.New("Spoof Verify invalid operation")
	}
	return current, ctx.Err()
}

var _ core.Backend = (*Backend)(nil)
