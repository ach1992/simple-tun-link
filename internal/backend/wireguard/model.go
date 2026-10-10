package wireguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type observedLink struct {
	Exists               bool
	IfIndex              int
	Name, Alias          string
	Owner                domain.LinkID
	Up                   bool
	IPv4Addresses        []netip.Prefix
	PublicKey            string
	ListenPort           uint16
	Peers                []string
	AllowedIPs, Endpoint string
	Keepalive            uint16
}

type linkJSON struct {
	IfIndex  int      `json:"ifindex"`
	IfName   string   `json:"ifname"`
	IfAlias  string   `json:"ifalias"`
	Flags    []string `json:"flags"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
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

func parseLinks(raw []byte) ([]observedLink, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("WireGuard link inspection must be a JSON array")
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil, fmt.Errorf("invalid WireGuard link JSON")
	}
	out := make([]observedLink, 0, len(rows))
	for _, item := range rows {
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(item, &shape); err != nil || shape == nil {
			return nil, fmt.Errorf("invalid WireGuard link row")
		}
		if len(shape) == 0 { // iproute2 can print empty placeholders for an unloaded link kind.
			continue
		}
		var row linkJSON
		if err := json.Unmarshal(item, &row); err != nil || row.IfIndex <= 0 ||
			row.IfName == "" || row.LinkInfo.Kind != "wireguard" {
			return nil, fmt.Errorf("invalid WireGuard link identity")
		}
		o := observedLink{Exists: true, IfIndex: row.IfIndex, Name: row.IfName, Alias: row.IfAlias, Up: slices.Contains(row.Flags, "UP")}
		if owner, ok := linux.ParseOwnerTag(row.IfAlias); ok {
			o.Owner = owner
		}
		out = append(out, o)
	}
	return out, nil
}

func parseAddresses(raw []byte, name string, ifindex int) ([]netip.Prefix, error) {
	var rows []addressJSON
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) != 1 ||
		rows[0].IfName != name || rows[0].IfIndex != ifindex {
		return nil, fmt.Errorf("WireGuard address observation identity changed")
	}
	var out []netip.Prefix
	for _, a := range rows[0].AddrInfo {
		if a.Family != "inet" {
			continue
		}
		addr, err := netip.ParseAddr(a.Local)
		if err != nil || !addr.Is4() || a.PrefixLen < 0 || a.PrefixLen > 32 {
			return nil, fmt.Errorf("invalid WireGuard IPv4 address observation")
		}
		out = append(out, netip.PrefixFrom(addr, a.PrefixLen))
	}
	return out, nil
}

func parsePeerAttribute(raw []byte, peer string) (string, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "", nil
	}
	fields := strings.Split(text, "\n")
	if len(fields) != 1 {
		return "", fmt.Errorf("unexpected WireGuard peer count")
	}
	parts := strings.Fields(fields[0])
	if len(parts) != 2 || parts[0] != peer {
		return "", fmt.Errorf("WireGuard peer attribute identity mismatch")
	}
	return parts[1], nil
}

func (o observedLink) matches(link domain.Link, name string) bool {
	alias, err := linux.OwnerTag(link.ID)
	return err == nil && o.Exists && o.Name == name && o.Owner == link.ID && o.Alias == alias && o.Up &&
		len(o.IPv4Addresses) == 1 && o.IPv4Addresses[0] == link.Addresses.Local && o.configuredFor(link)
}

func (o observedLink) configuredFor(link domain.Link) bool {
	return o.PublicKey == link.WireGuard.LocalPublicKey && o.ListenPort == link.WireGuard.ListenPort &&
		len(o.Peers) == 1 && o.Peers[0] == link.WireGuard.PeerPublicKey &&
		o.AllowedIPs == netip.PrefixFrom(link.Addresses.Peer.Addr(), 32).String() &&
		o.Keepalive == link.WireGuard.LocalKeepalive
	// Endpoint is intentionally dynamic: authenticated WireGuard roaming can
	// update the observed peer endpoint after initial configuration.
}

func (o observedLink) emptyConfig() bool {
	return o.PublicKey == "" && o.ListenPort == 0 && len(o.Peers) == 0 && o.AllowedIPs == "" && o.Keepalive == 0
}

func validateLink(link domain.Link) error {
	if err := link.Validate(); err != nil {
		return err
	}
	if link.Backend != domain.BackendWireGuard || link.Encapsulation != domain.EncapUDP {
		return stlerr.New(stlerr.CodeUnsupported, "wireguard", string(link.ID), string(link.Backend), "WireGuard backend requires UDP")
	}
	if !link.Underlay.Local.Is4() || !link.Underlay.Peer.Is4() {
		return stlerr.New(stlerr.CodeUnsupported, "wireguard", string(link.ID), string(link.Backend), "v0.1 WireGuard requires IPv4 underlay")
	}
	if link.WireGuard.ListenPort == 0 || link.WireGuard.PeerPort == 0 {
		return stlerr.New(stlerr.CodeInvalid, "wireguard", string(link.ID), string(link.Backend), "WireGuard requires explicit local and peer UDP ports")
	}
	if err := link.WireGuard.Validate(); err != nil {
		return err
	}
	return nil
}

func InterfaceName(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return "stlwg" + string(id)[4:14], nil
}

func desiredResources(link domain.Link, name string, firewall domain.ResourceClaim) []domain.ResourceClaim {
	return []domain.ResourceClaim{
		{Kind: domain.ResourceInterface, Key: name},
		{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
		{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.WireGuard.ListenPort))},
		{Kind: domain.ResourceBackendID, Key: "wireguard/local-public/" + link.WireGuard.LocalPublicKey},
		firewall,
	}
}

func endpoint(link domain.Link) string {
	return net.JoinHostPort(link.Underlay.Peer.String(), strconv.Itoa(int(link.WireGuard.PeerPort)))
}
