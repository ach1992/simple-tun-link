package ipip

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const ipipProtocol = 4

// The Link ID is already a shared random 128-bit identity on both peers.
// Deriving the UDP receive port from it keeps IPIP FOU/GUE pairing/state
// backend-neutral while still giving independent Links distinct resources in
// the common case. Any actual collision is detected and rejected explicitly.
const (
	ipipUDPPortBase = 49152
	ipipUDPPortSpan = 16384
)

type encapJSON struct {
	Type  string `json:"type"`
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`
}

type linkJSON struct {
	IfIndex  int      `json:"ifindex"`
	IfName   string   `json:"ifname"`
	IfAlias  string   `json:"ifalias"`
	Flags    []string `json:"flags"`
	LinkInfo struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			Remote string     `json:"remote"`
			Local  string     `json:"local"`
			Encap  *encapJSON `json:"encap"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

type addressJSON struct {
	IfIndex  int    `json:"ifindex"`
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type observedLink struct {
	Exists        bool
	IfIndex       int
	Name          string
	Alias         string
	Owner         domain.LinkID
	Up            bool
	Local         netip.Addr
	Peer          netip.Addr
	Encapsulation domain.Encapsulation
	UDPPort       uint16
	IPv4Addresses []netip.Prefix
}

func parseIPIPLinks(raw []byte) ([]observedLink, error) {
	var rows []linkJSON
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse IPIP link state: %w", err)
	}
	out := make([]observedLink, 0, len(rows))
	for _, row := range rows {
		// Linux exposes wildcard fallback devices through the same query. They
		// are not STL point-to-point Links and must never be claimed/deleted.
		if strings.TrimSpace(row.LinkInfo.InfoData.Local) == "any" || strings.TrimSpace(row.LinkInfo.InfoData.Remote) == "any" {
			continue
		}
		state, err := parseIPIPLink(row)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	return out, nil
}

func parseIPIPLink(row linkJSON) (observedLink, error) {
	if row.IfName == "" || row.LinkInfo.InfoKind != "ipip" || row.IfIndex <= 0 {
		return observedLink{}, fmt.Errorf("invalid IPIP link inspection row")
	}
	local, err := netip.ParseAddr(strings.TrimSpace(row.LinkInfo.InfoData.Local))
	if err != nil || !local.Is4() {
		return observedLink{}, fmt.Errorf("invalid inspected IPIP local underlay")
	}
	peer, err := netip.ParseAddr(strings.TrimSpace(row.LinkInfo.InfoData.Remote))
	if err != nil || !peer.Is4() {
		return observedLink{}, fmt.Errorf("invalid inspected IPIP peer underlay")
	}
	state := observedLink{
		Exists: true, IfIndex: row.IfIndex, Name: row.IfName, Alias: row.IfAlias,
		Local: local, Peer: peer, Encapsulation: domain.EncapNative,
	}
	if owner, ok := linux.ParseOwnerTag(row.IfAlias); ok {
		state.Owner = owner
	}
	state.Up = slices.Contains(row.Flags, "UP")
	if encap := row.LinkInfo.InfoData.Encap; encap != nil {
		switch encap.Type {
		case string(domain.EncapFOU):
			state.Encapsulation = domain.EncapFOU
		case string(domain.EncapGUE):
			state.Encapsulation = domain.EncapGUE
		default:
			return observedLink{}, fmt.Errorf("unsupported inspected IPIP UDP encapsulation")
		}
		if encap.Sport == 0 || encap.Sport != encap.Dport {
			return observedLink{}, fmt.Errorf("inspected IPIP UDP ports are not symmetric")
		}
		state.UDPPort = encap.Sport
	}
	return state, nil
}

func parseIPv4Addresses(raw []byte, name string, ifindex int) ([]netip.Prefix, error) {
	var rows []addressJSON
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse IPIP address state: %w", err)
	}
	if len(rows) != 1 || ifindex <= 0 || rows[0].IfIndex != ifindex || rows[0].IfName != name {
		return nil, fmt.Errorf("IPIP address observation identity changed; preserving current host state")
	}
	var out []netip.Prefix
	for _, row := range rows {
		for _, info := range row.AddrInfo {
			if info.Family != "inet" {
				continue
			}
			addr, err := netip.ParseAddr(info.Local)
			if err != nil || !addr.Is4() || info.PrefixLen < 0 || info.PrefixLen > 32 {
				return nil, fmt.Errorf("invalid inspected IPIP IPv4 address")
			}
			out = append(out, netip.PrefixFrom(addr, info.PrefixLen))
		}
	}
	return out, nil
}

func (g observedLink) matches(link domain.Link, name string) bool {
	if !g.Exists || g.Name != name || g.Owner != link.ID || !g.Up || g.Local != link.Underlay.Local || g.Peer != link.Underlay.Peer {
		return false
	}
	expectedAlias, err := linux.OwnerTag(link.ID)
	if err != nil || g.Alias != expectedAlias {
		return false
	}
	port, err := UDPPort(link)
	if err != nil || g.Encapsulation != link.Encapsulation || g.UDPPort != port {
		return false
	}
	return len(g.IPv4Addresses) == 1 && g.IPv4Addresses[0] == link.Addresses.Local
}

func (g observedLink) matchesConfigurationBeforeOwnership(link domain.Link, name string) bool {
	if !g.Exists || g.Name != name || g.Local != link.Underlay.Local || g.Peer != link.Underlay.Peer {
		return false
	}
	port, err := UDPPort(link)
	return err == nil && g.Encapsulation == link.Encapsulation && g.UDPPort == port
}

func (g observedLink) backendIdentity() string {
	if !g.Exists || !g.Local.IsValid() || !g.Peer.IsValid() {
		return ""
	}
	return backendIdentity(g.Local, g.Peer)
}

func validateLink(link domain.Link) error {
	if err := link.Validate(); err != nil {
		return err
	}
	if link.Backend != domain.BackendIPIP {
		return fmt.Errorf("IPIP backend received %q Link", link.Backend)
	}
	if !link.Underlay.Local.Is4() || !link.Underlay.Peer.Is4() {
		return stlerr.New(stlerr.CodeUnsupported, "ipip_plan", string(link.ID), string(link.Backend), "v0.1 IPIP requires IPv4 underlay endpoints")
	}
	switch link.Encapsulation {
	case domain.EncapNative, domain.EncapFOU, domain.EncapGUE:
	default:
		return stlerr.New(stlerr.CodeUnsupported, "ipip_plan", string(link.ID), string(link.Backend), "unsupported IPIP encapsulation")
	}
	return nil
}

func InterfaceName(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	// 3 byte prefix + 12 hex chars = Linux IFNAMSIZ-1 (15) characters.
	return "sti" + string(id)[4:16], nil
}

// UDPPort returns zero for Native and a deterministic high ephemeral port for
// FOU/GUE. Both peers carry the same Link ID, so the mapping is symmetric
// without adding backend-specific fields to the stable Link/pairing contract.
func UDPPort(link domain.Link) (uint16, error) {
	if err := link.ID.Validate(); err != nil {
		return 0, err
	}
	if link.Encapsulation == domain.EncapNative {
		return 0, nil
	}
	if link.Encapsulation != domain.EncapFOU && link.Encapsulation != domain.EncapGUE {
		return 0, stlerr.New(stlerr.CodeUnsupported, "ipip_port", string(link.ID), string(link.Backend), "unsupported IPIP encapsulation")
	}
	value, err := strconv.ParseUint(string(link.ID)[4:8], 16, 16)
	if err != nil {
		return 0, fmt.Errorf("derive IPIP UDP port: %w", err)
	}
	return uint16(ipipUDPPortBase + int(value)%ipipUDPPortSpan), nil
}

func Overhead(link domain.Link) (int, error) {
	if err := validateLink(link); err != nil {
		return 0, err
	}
	overhead := 20 // outer IPv4 header
	switch link.Encapsulation {
	case domain.EncapFOU:
		overhead += 8 // UDP
	case domain.EncapGUE:
		overhead += 12 // UDP + 4-byte GUE base header
	}
	return overhead, nil
}

func ipipTypeArgs(link domain.Link) ([]string, error) {
	args := []string{"type", "ipip", "local", link.Underlay.Local.String(), "remote", link.Underlay.Peer.String(), "mode", "ipip"}
	port, err := UDPPort(link)
	if err != nil {
		return nil, err
	}
	if port != 0 {
		p := strconv.Itoa(int(port))
		args = append(args, "encap", string(link.Encapsulation), "encap-sport", p, "encap-dport", p)
	}
	return args, nil
}

// Linux IPIP tunnel lookup does not uniquely distinguish the same local/remote
// IPv4 endpoint pair by FOU/GUE encapsulation or UDP port. Use one shared
// collision/lock identity across all three encapsulations; no second Link may
// race to claim the same kernel endpoint pair.
func backendIdentity(local, peer netip.Addr) string {
	return "ipip/underlay/" + local.String() + "/" + peer.String()
}

func desiredResources(link domain.Link, name string, firewall domain.ResourceClaim) []domain.ResourceClaim {
	return append(commonCollisionClaims(link, name),
		domain.ResourceClaim{Kind: domain.ResourceBackendID, Key: backendIdentity(link.Underlay.Local, link.Underlay.Peer)},
		firewall,
	)
}

func commonCollisionClaims(link domain.Link, name string) []domain.ResourceClaim {
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: name},
		{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
	}
	if port, _ := UDPPort(link); port != 0 {
		claims = append(claims, domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(port))})
	}
	return claims
}

func firewallProtocolAndPort(link domain.Link) (uint8, uint16, error) {
	if link.Encapsulation == domain.EncapNative {
		return ipipProtocol, 0, nil
	}
	port, err := UDPPort(link)
	if err != nil {
		return 0, 0, err
	}
	return 17, port, nil
}

func desiredBackendIdentity(link domain.Link) string {
	return backendIdentity(link.Underlay.Local, link.Underlay.Peer)
}
