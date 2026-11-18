// Package masque adapts the authenticated CONNECT-IP datapath to the one STL
// Engine's transactional Backend contract. It is not a second Link Engine.
// The host adapter owns exact-name service/kernel inventory and credentials.
package masque

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type HostObservation struct {
	UnitExists      bool
	UnitOwned       bool
	UnitActive      bool
	InterfaceExists bool
	InterfaceOwned  bool
	InterfaceIndex  int
	LocalAddress    netip.Prefix
	PeerRoute       bool
	// RuntimeReady denotes an active original per-Link helper, exact
	// protected credential identity and the expected owned TUN/route.
	RuntimeReady bool
}

// Host is deliberately an injected, nonpublic lifecycle adapter. Production
// may start/stop only exact Link-owned services; the raw kernel/service names,
// existence and matching aliases do not authorize adoption of foreign state.
type Host interface {
	Inspect(context.Context, domain.Link) (HostObservation, error)
	Preflight(context.Context, domain.Link, bool) error
	Start(context.Context, domain.Link) (core.Rollback, error)
	Stop(context.Context, domain.Link) (core.Rollback, error)
}

type Backend struct{ host Host }

func New(host Host) (*Backend, error) {
	if host == nil {
		return nil, errors.New("MASQUE host adapter is required")
	}
	return &Backend{host: host}, nil
}

func (*Backend) Kind() domain.Backend { return domain.BackendMASQUE }

type observation struct {
	link domain.Link
	host HostObservation
}

func (o observation) ObservedResources() []domain.ResourceClaim {
	if !o.host.InterfaceExists && !o.host.UnitExists {
		return nil
	}
	var r []domain.ResourceClaim
	if o.host.InterfaceExists {
		name, _ := masque.AgentInterfaceName(o.link.ID)
		r = append(r, domain.ResourceClaim{Kind: domain.ResourceInterface, Key: name})
		if o.host.LocalAddress.IsValid() {
			r = append(r, domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: o.host.LocalAddress.Addr().String()})
		}
	}
	if o.host.UnitExists {
		r = append(r, domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: "masque/unit/" + string(o.link.ID)})
	}
	return r
}

type plan struct {
	link      domain.Link
	resources []domain.ResourceClaim
	start     bool
	stop      bool
}

func (p plan) Empty() bool                       { return !p.start && !p.stop }
func (p plan) Resources() []domain.ResourceClaim { return slices.Clone(p.resources) }

func expectedClaims(link domain.Link) ([]domain.ResourceClaim, error) {
	name, err := masque.AgentInterfaceName(link.ID)
	if err != nil {
		return nil, err
	}
	r := []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: name},
		{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
		{Kind: domain.ResourceRoute, Key: "masque/peer/" + link.Addresses.Peer.String()},
		{Kind: domain.ResourceBackendID, Key: "masque/unit/" + string(link.ID)},
		{Kind: domain.ResourceBackendID, Key: "masque/material/" + string(link.ID) + "/" + link.MASQUE.MaterialSHA256},
	}
	if link.MASQUE.Role == "listen" {
		r = append(r, domain.ResourceClaim{Kind: domain.ResourceTCPListenPort, Key: strconv.Itoa(int(link.MASQUE.TCPPort))})
	}
	for _, c := range r {
		if err := c.Validate(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func validateLink(link domain.Link) error {
	if link.Backend != domain.BackendMASQUE || link.Validate() != nil {
		return errors.New("invalid managed MASQUE Link")
	}
	for _, prefix := range []netip.Prefix{link.Addresses.Local, link.Addresses.Peer} {
		if err := composition.ValidateComposedPrivateIPv4Route(prefix); err != nil {
			return fmt.Errorf("MASQUE private route is invalid: %w", err)
		}
	}
	for _, ip := range []netip.Addr{link.Underlay.Local, link.Underlay.Peer} {
		if ip.Is4() && (link.Addresses.Local.Contains(ip) || link.Addresses.Peer.Contains(ip)) {
			return errors.New("MASQUE private route captures its physical TLS peer")
		}
	}
	return nil
}

func (b *Backend) Inspect(ctx context.Context, link domain.Link) (core.Observation, error) {
	if err := validateLink(link); err != nil {
		return nil, err
	}
	observed, err := b.host.Inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	return observation{link: link, host: observed}, nil
}

func (b *Backend) Plan(ctx context.Context, req core.Request, observed core.Observation) (core.Plan, error) {
	_ = ctx
	o, ok := observed.(observation)
	if !ok || o.link != req.Link {
		return nil, errors.New("MASQUE observed Link identity changed")
	}
	if err := validateLink(req.Link); err != nil {
		return nil, err
	}
	claims, err := expectedClaims(req.Link)
	if err != nil {
		return nil, err
	}
	p := plan{link: req.Link, resources: claims}
	switch req.Operation {
	case core.OperationEnsure:
		p.start = !o.host.RuntimeReady
	case core.OperationRemove:
		p.stop = o.host.UnitExists || o.host.InterfaceExists
	default:
		return nil, errors.New("unsupported MASQUE Link operation")
	}
	return p, nil
}

func exactCommittedClaims(req core.Request, expected []domain.ResourceClaim) bool {
	if req.Prior == nil || *req.Prior != req.Link {
		return false
	}
	copyExpected := slices.Clone(expected)
	slices.SortFunc(copyExpected, func(a, b domain.ResourceClaim) int {
		return strings.Compare(a.Canonical(), b.Canonical())
	})
	return slices.Equal(req.OwnedResources, copyExpected)
}

func (b *Backend) Validate(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) error {
	o, ok := observed.(observation)
	p, pok := candidate.(plan)
	if !ok || !pok || o.link != req.Link || p.link != req.Link {
		return errors.New("MASQUE stale host plan")
	}
	expected, err := expectedClaims(req.Link)
	if err != nil || !slices.Equal(p.resources, expected) {
		return errors.New("MASQUE resource claims differ from intended Link")
	}
	h := o.host
	if h.UnitExists && !h.UnitOwned {
		return errors.New("MASQUE service exists without original Link ownership")
	}
	if h.InterfaceExists && !h.InterfaceOwned {
		return errors.New("MASQUE interface is not an original Link-owned TUN")
	}
	if h.UnitActive && !h.UnitExists {
		return errors.New("MASQUE active service inventory inconsistent")
	}
	if h.RuntimeReady && (!h.UnitActive || !h.InterfaceExists || !h.PeerRoute || h.LocalAddress != req.Link.Addresses.Local) {
		return errors.New("MASQUE runtime readiness lacks the entire owned interface/route")
	}
	if h.InterfaceExists && (!h.UnitActive || !h.UnitOwned) {
		return errors.New("MASQUE orphan or unrelated TUN requires exact-owner recovery")
	}
	switch req.Operation {
	case core.OperationEnsure:
		if req.Prior != nil && !exactCommittedClaims(req, expected) {
			return errors.New("MASQUE committed owner claims changed")
		}
		if req.Prior == nil && (h.UnitExists || h.InterfaceExists) {
			return errors.New("MASQUE existing service/interface cannot be adopted as a new Link")
		}
		if h.UnitActive && !h.RuntimeReady {
			return errors.New("MASQUE partial active runtime requires reconciliation")
		}
		if h.RuntimeReady != !p.start {
			return errors.New("MASQUE start plan stale")
		}
		return b.host.Preflight(ctx, req.Link, false)
	case core.OperationRemove:
		if !exactCommittedClaims(req, expected) {
			return errors.New("MASQUE Remove needs exact committed Link resource ownership")
		}
		if p.stop != (h.UnitExists || h.InterfaceExists) {
			return errors.New("MASQUE stop plan stale")
		}
		if h.UnitExists {
			return b.host.Preflight(ctx, req.Link, true)
		}
		return nil
	default:
		return errors.New("unsupported MASQUE operation")
	}
}

func (b *Backend) Apply(ctx context.Context, req core.Request, observed core.Observation, candidate core.Plan) (core.Rollback, error) {
	o, ok := observed.(observation)
	p, pok := candidate.(plan)
	if !ok || !pok || o.link != req.Link || p.link != req.Link {
		return nil, errors.New("MASQUE stale Apply")
	}
	if p.Empty() {
		return nil, errors.New("MASQUE Apply invoked with empty plan")
	}
	if req.Operation == core.OperationEnsure && p.start {
		return b.host.Start(ctx, req.Link)
	}
	if req.Operation == core.OperationRemove && p.stop {
		return b.host.Stop(ctx, req.Link)
	}
	return nil, errors.New("invalid MASQUE lifecycle Apply")
}

func (b *Backend) Verify(ctx context.Context, req core.Request) (core.Observation, error) {
	o, err := b.Inspect(ctx, req.Link)
	if err != nil {
		return nil, err
	}
	h := o.(observation).host
	switch req.Operation {
	case core.OperationEnsure:
		if !h.RuntimeReady || !h.UnitOwned || !h.UnitActive || !h.InterfaceOwned ||
			!h.InterfaceExists || !h.PeerRoute || h.LocalAddress != req.Link.Addresses.Local {
			return nil, errors.New("MASQUE owned service/TUN/route not fully ready")
		}
	case core.OperationRemove:
		if h.UnitExists || h.InterfaceExists || h.UnitActive {
			return nil, errors.New("MASQUE stopped service/TUN still observed")
		}
	default:
		return nil, errors.New("invalid MASQUE verification operation")
	}
	return o, ctx.Err()
}

var _ core.Backend = (*Backend)(nil)

// MASQUEHostAbsent is a read-only proof for explicit owner-initiated crash
// recovery. A similarly named but foreign/ambiguous object is NOT absence.
// Never call Host.Stop here or change any systemd/network resource.
func (b *Backend) MASQUEHostAbsent(ctx context.Context, link domain.Link) (bool, error) {
	if b == nil || b.host == nil || validateLink(link) != nil {
		return false, errors.New("MASQUE recovery host identity invalid")
	}
	obs, err := b.host.Inspect(ctx, link)
	if err != nil {
		return false, err
	}
	return !obs.UnitExists && !obs.InterfaceExists && !obs.UnitActive, nil
}
