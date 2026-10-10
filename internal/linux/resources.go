package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// ObservedResource is a secret-free collision observation from the current host.
// Owner is populated only when ownership can be proven from an STL owner marker.
type ObservedResource struct {
	Claim  domain.ResourceClaim
	Owner  domain.LinkID
	Source string
}

// ResourceProbe handles one collision-sensitive resource kind whose Linux
// representation is backend/mechanism-specific. The common inspector refuses
// to silently skip claims for which no probe exists.
type ResourceProbe interface {
	InspectResource(context.Context, domain.ResourceClaim) ([]ObservedResource, error)
}

type ResourceProbeFunc func(context.Context, domain.ResourceClaim) ([]ObservedResource, error)

func (f ResourceProbeFunc) InspectResource(ctx context.Context, claim domain.ResourceClaim) ([]ObservedResource, error) {
	return f(ctx, claim)
}

type HostSnapshotter struct {
	Runner   Runner
	IPBinary string
	SSBinary string
}

type hostSnapshot struct {
	interfaces map[string]ObservedResource
	addresses  []ObservedResource
	routes     []ObservedResource
	udpPorts   map[uint16]ObservedResource
}

type ipLinkRow struct {
	IfName  string `json:"ifname"`
	IfAlias string `json:"ifalias"`
}

type ipAddressRow struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type ipRouteRow struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
}

func (s HostSnapshotter) Snapshot(ctx context.Context) (hostSnapshot, error) {
	if s.Runner == nil {
		return hostSnapshot{}, fmt.Errorf("host snapshot runner is required")
	}
	ipBinary := s.IPBinary
	if ipBinary == "" {
		ipBinary = "ip"
	}
	ssBinary := s.SSBinary
	if ssBinary == "" {
		ssBinary = "ss"
	}

	linksResult, err := s.Runner.Run(ctx, ipBinary, "-json", "link", "show")
	if err != nil {
		return hostSnapshot{}, fmt.Errorf("inspect links: %w", err)
	}
	var linkRows []ipLinkRow
	if err := json.Unmarshal(linksResult.Stdout, &linkRows); err != nil {
		return hostSnapshot{}, fmt.Errorf("parse link JSON: %w", err)
	}
	interfaces := make(map[string]ObservedResource, len(linkRows))
	ownersByInterface := make(map[string]domain.LinkID, len(linkRows))
	for _, row := range linkRows {
		if row.IfName == "" || strings.ContainsAny(row.IfName, "\r\n\x00") {
			return hostSnapshot{}, fmt.Errorf("link inspection returned an invalid interface name")
		}
		var owner domain.LinkID
		if parsed, ok := ParseOwnerTag(strings.TrimSpace(row.IfAlias)); ok {
			owner = parsed
			ownersByInterface[row.IfName] = parsed
		}
		claim := domain.ResourceClaim{Kind: domain.ResourceInterface, Key: row.IfName}
		interfaces[row.IfName] = ObservedResource{Claim: claim, Owner: owner, Source: "ip-link"}
	}

	addressesResult, err := s.Runner.Run(ctx, ipBinary, "-json", "address", "show")
	if err != nil {
		return hostSnapshot{}, fmt.Errorf("inspect addresses: %w", err)
	}
	var addressRows []ipAddressRow
	if err := json.Unmarshal(addressesResult.Stdout, &addressRows); err != nil {
		return hostSnapshot{}, fmt.Errorf("parse address JSON: %w", err)
	}
	var addresses []ObservedResource
	for _, row := range addressRows {
		owner := ownersByInterface[row.IfName]
		for _, info := range row.AddrInfo {
			addr, err := netip.ParseAddr(strings.TrimSpace(info.Local))
			if err != nil || info.PrefixLen < 0 || info.PrefixLen > addr.BitLen() {
				return hostSnapshot{}, fmt.Errorf("address inspection returned an invalid address")
			}
			prefix := netip.PrefixFrom(addr, info.PrefixLen).Masked()
			addresses = append(addresses,
				ObservedResource{Claim: domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: addr.String()}, Owner: owner, Source: "ip-address"},
				ObservedResource{Claim: domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: prefix.String()}, Owner: owner, Source: "ip-address"},
			)
		}
	}

	routesResult, err := s.Runner.Run(ctx, ipBinary, "-json", "route", "show", "table", "all")
	if err != nil {
		return hostSnapshot{}, fmt.Errorf("inspect routes: %w", err)
	}
	var routeRows []ipRouteRow
	if err := json.Unmarshal(routesResult.Stdout, &routeRows); err != nil {
		return hostSnapshot{}, fmt.Errorf("parse route JSON: %w", err)
	}
	var routes []ObservedResource
	for _, row := range routeRows {
		dst := strings.TrimSpace(row.Destination)
		if dst == "" || dst == "default" {
			continue
		}
		prefix, err := netip.ParsePrefix(dst)
		if err != nil {
			// iproute2 may represent a host route as a bare address
			// rather than with /32 or /128. Ignoring it can allocate
			// a Link subnet over another existing host route.
			addr, addrErr := netip.ParseAddr(dst)
			if addrErr != nil || addr.Zone() != "" {
				return hostSnapshot{}, fmt.Errorf("route inspection returned an invalid destination")
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefix = prefix.Masked()
		// An IPv4/IPv6 /0 is the default route even when iproute2
		// spells it as a prefix rather than the keyword 'default'.
		// Reserving /0 would incorrectly forbid every Link subnet.
		if prefix.Bits() == 0 {
			continue
		}
		routes = append(routes, ObservedResource{
			Claim:  domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: prefix.String()},
			Owner:  ownersByInterface[row.Device],
			Source: "ip-route",
		})
	}

	ssResult, err := s.Runner.Run(ctx, ssBinary, "-H", "-u", "-l", "-n")
	if err != nil {
		return hostSnapshot{}, fmt.Errorf("inspect UDP listeners: %w", err)
	}
	udpPorts, err := parseUDPListeners(string(ssResult.Stdout))
	if err != nil {
		return hostSnapshot{}, err
	}

	return hostSnapshot{interfaces: interfaces, addresses: addresses, routes: routes, udpPorts: udpPorts}, nil
}

func parseUDPListeners(text string) (map[uint16]ObservedResource, error) {
	ports := make(map[uint16]ObservedResource)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return nil, fmt.Errorf("parse UDP listener: unexpected ss row")
		}
		endpoint := fields[3]
		colon := strings.LastIndexByte(endpoint, ':')
		if colon < 0 || colon == len(endpoint)-1 {
			return nil, fmt.Errorf("parse UDP listener endpoint")
		}
		portText := strings.TrimSpace(endpoint[colon+1:])
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			if portText == "*" {
				continue
			}
			return nil, fmt.Errorf("parse UDP listener port")
		}
		claim := domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: strconv.FormatUint(port, 10)}
		ports[uint16(port)] = ObservedResource{Claim: claim, Source: "ss-udp"}
	}
	return ports, nil
}

// CollisionInspector checks every requested resource claim. Common host-level
// resources are inspected from one coherent snapshot; backend/mechanism-specific
// kinds require an explicit Extra probe and are never silently ignored.
type CollisionInspector struct {
	Snapshotter HostSnapshotter
	Extra       map[string]ResourceProbe
}

func (i CollisionInspector) Inspect(ctx context.Context, claims []domain.ResourceClaim) ([]ObservedResource, error) {
	snapshot, err := i.Snapshotter.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	var conflicts []ObservedResource
	for _, claim := range claims {
		if err := claim.Validate(); err != nil {
			return nil, err
		}
		observed, handled, err := snapshot.conflicts(claim)
		if err != nil {
			return nil, err
		}
		if !handled {
			probe := i.Extra[claim.Kind]
			if probe == nil {
				return nil, fmt.Errorf("no collision inspector registered for resource kind %q", claim.Kind)
			}
			observed, err = probe.InspectResource(ctx, claim)
			if err != nil {
				return nil, fmt.Errorf("inspect resource kind %q: %w", claim.Kind, err)
			}
		}
		conflicts = append(conflicts, observed...)
	}
	return conflicts, nil
}

func (s hostSnapshot) conflicts(claim domain.ResourceClaim) ([]ObservedResource, bool, error) {
	switch claim.Kind {
	case domain.ResourceInterface:
		if observed, ok := s.interfaces[claim.Key]; ok {
			return []ObservedResource{observed}, true, nil
		}
		return nil, true, nil
	case domain.ResourceUDPListenPort:
		port, err := strconv.ParseUint(claim.Key, 10, 16)
		if err != nil || port == 0 {
			return nil, true, fmt.Errorf("invalid UDP listen port claim")
		}
		if observed, ok := s.udpPorts[uint16(port)]; ok {
			return []ObservedResource{observed}, true, nil
		}
		return nil, true, nil
	case domain.ResourceLinkAddress, domain.ResourceLinkSubnet:
		candidates := append(append([]ObservedResource(nil), s.addresses...), s.routes...)
		var conflicts []ObservedResource
		for _, observed := range candidates {
			conflict, err := domain.ResourceClaimsConflict(claim, observed.Claim)
			if err != nil {
				return nil, true, err
			}
			if conflict {
				conflicts = append(conflicts, observed)
			}
		}
		return conflicts, true, nil
	default:
		return nil, false, nil
	}
}
