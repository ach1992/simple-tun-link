package hostaddress

import (
	"encoding/json"
	"errors"
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
	// ip -json address show emits one object per interface, including an
	// explicit addr_info array (possibly empty). A missing/null field is
	// incomplete evidence, not evidence that an address is absent.
	var rows []struct {
		Name      string `json:"ifname"`
		Addresses *[]struct {
			Family string `json:"family"`
			Local  string `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
		return nil, fmt.Errorf("cannot parse complete local IPv4 address inventory")
	}
	interfaces := make(map[string]bool, len(rows))
	for _, row := range rows {
		if !validInterface(row.Name) || row.Addresses == nil || interfaces[row.Name] {
			return nil, fmt.Errorf("local IPv4 address inventory contains an incomplete interface record")
		}
		interfaces[row.Name] = true
		for _, item := range *row.Addresses {
			if (item.Family != "inet" && item.Family != "inet6") || item.Local == "" {
				return nil, fmt.Errorf("local IPv4 address inventory contains an incomplete address record")
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(item.Local))
			if err != nil || (item.Family == "inet" && !ip.Is4()) ||
				(item.Family == "inet6" && !ip.Is6()) {
				return nil, fmt.Errorf("local IPv4 address inventory contains an invalid address record")
			}
		}
	}
	found := map[Endpoint]bool{}
	for _, row := range rows {
		for _, item := range *row.Addresses {
			if item.Family != "inet" {
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

// These typed results are valid only after a complete parsed local inventory.
// They are shared by the native backends, IPsec and import UI.
var (
	ErrNotAssigned = errors.New("local IPv4 is not assigned to this host")
	ErrAmbiguous   = errors.New("local IPv4 is assigned on multiple host interfaces")
)

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
	if len(matches) == 0 {
		// A caller that explicitly selected a device may have chosen the
		// wrong interface even when this IPv4 exists elsewhere on the host.
		// That is NOT evidence of a wrong physical receiver.
		if device != "" {
			for _, ep := range endpoints {
				if ep.Address == local {
					return Endpoint{}, fmt.Errorf("local IPv4 is assigned on a different interface; inspect ip -json address show")
				}
			}
		}
		return Endpoint{}, fmt.Errorf("%w; inspect ip -json address show and choose an assigned local endpoint", ErrNotAssigned)
	}
	if len(matches) > 1 {
		return Endpoint{}, fmt.Errorf("%w; inspect ip -json address show and choose a unique local interface", ErrAmbiguous)
	}
	return matches[0], nil
}
