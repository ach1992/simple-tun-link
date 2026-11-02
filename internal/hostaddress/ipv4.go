package hostaddress

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

func validInterface(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

// Endpoint records an address actually configured on this host.
// It is NOT a promise that packets can reach a remote tunnel peer.
type Endpoint struct {
	Address   netip.Addr
	Interface string
}

// Parse consumes local iproute2 address inventory only.
// No route to a remote peer, online probe or host mutation is involved.
func Parse(raw []byte) ([]Endpoint, error) {
	var rows []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
		return nil, fmt.Errorf("cannot parse complete local IPv4 address inventory")
	}
	found := map[Endpoint]bool{}
	for _, row := range rows {
		for _, item := range row.Addresses {
			if item.Family != "inet" {
				if item.Family == "" && item.Local != "" {
					return nil, fmt.Errorf("local IPv4 family is unverified")
				}
				continue
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(item.Local))
			if err != nil {
				return nil, fmt.Errorf("local IPv4 address inventory contains an invalid address")
			}
			if !ip.Is4() {
				continue
			}
			if !ValidIPv4(ip) {
				continue
			}
			if !validInterface(row.Name) {
				return nil, fmt.Errorf("local IPv4 address inventory contains an invalid interface")
			}
			ep := Endpoint{Address: ip, Interface: row.Name}
			if found[ep] {
				return nil, fmt.Errorf("duplicate local IPv4/interface inventory entry")
			}
			found[ep] = true
		}
	}
	endpoints := make([]Endpoint, 0, len(found))
	for ep := range found {
		endpoints = append(endpoints, ep)
	}
	slices.SortFunc(endpoints, func(a, b Endpoint) int {
		if c := a.Address.Compare(b.Address); c != 0 {
			return c
		}
		return strings.Compare(a.Interface, b.Interface)
	})
	return endpoints, nil
}

func ValidIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	octets := ip.As4()
	// Kernel route destinations and addresses are not implicitly concrete
	// when they belong to 0/8 or 240/4 reserved blocks.
	return octets[0] != 0 && octets[0] < 240
}

func Unique(endpoints []Endpoint, local netip.Addr, device string) (Endpoint, error) {
	if !ValidIPv4(local) {
		return Endpoint{}, fmt.Errorf("select a usable IPv4 address actually assigned on this host")
	}
	var matches []Endpoint
	for _, ep := range endpoints {
		if ep.Address == local && (device == "" || ep.Interface == device) {
			matches = append(matches, ep)
		}
	}
	if len(matches) != 1 {
		return Endpoint{}, fmt.Errorf("local IPv4/interface must identify exactly one assigned host address; inspect ip -json address show and choose a unique local endpoint")
	}
	return matches[0], nil
}
