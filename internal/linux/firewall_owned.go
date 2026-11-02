package linux

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// FindOwnedInbound recovers the exact, uniquely marked INPUT rule from the
// host's read-only firewall inventory. It is used for removing a committed
// Link after its underlay route (possibly another STL Link) has disappeared.
// Neither a changed route nor a merely matching source/port authorizes
// adopting or deleting a different rule.
func (f IPTablesFirewall) FindOwnedInbound(ctx context.Context, id domain.LinkID, ipv6 bool) (InboundFirewallRule, bool, error) {
	if err := id.Validate(); err != nil {
		return InboundFirewallRule{}, false, err
	}
	if f.Runner == nil {
		return InboundFirewallRule{}, false, fmt.Errorf("firewall runner is required")
	}
	binary := f.binary(netip.IPv4Unspecified())
	if ipv6 {
		binary = f.binary(netip.IPv6Unspecified())
	}
	inventory, err := f.Runner.Run(ctx, binary, "-w", firewallWaitSeconds, "-S", "INPUT")
	if err != nil {
		return InboundFirewallRule{}, false, fmt.Errorf("inspect owned INPUT firewall rules: %w", err)
	}
	prefix := "stl:" + string(id) + ":"
	var found InboundFirewallRule
	count := 0
	for _, line := range strings.Split(string(inventory.Stdout), "\n") {
		fields := strings.Fields(line)
		owned := false
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "--comment" && strings.HasPrefix(strings.Trim(fields[i+1], "\"'"), prefix) {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		count++
		if count != 1 {
			return InboundFirewallRule{}, false, fmt.Errorf("multiple owned INPUT rules require explicit reconciliation")
		}
		found, err = parseOwnedInboundRule(fields, id, ipv6)
		if err != nil {
			return InboundFirewallRule{}, false, fmt.Errorf("owned INPUT rule cannot be verified: %w", err)
		}
	}
	if count == 0 {
		return InboundFirewallRule{}, false, nil
	}
	exact, err := f.HasInbound(ctx, id, found)
	if err != nil {
		return InboundFirewallRule{}, false, fmt.Errorf("verify recovered exact INPUT rule: %w", err)
	}
	if !exact {
		return InboundFirewallRule{}, false, fmt.Errorf("recovered INPUT rule is no longer present")
	}
	return found, true, nil
}

func parseOwnedInboundRule(fields []string, id domain.LinkID, ipv6 bool) (InboundFirewallRule, error) {
	if len(fields) < 4 || fields[0] != "-A" || fields[1] != "INPUT" {
		return InboundFirewallRule{}, fmt.Errorf("unexpected firewall chain or action")
	}
	values := map[string]string{}
	modules := map[string]bool{}
	for i := 2; i < len(fields); i++ {
		flag := fields[i]
		if i+1 >= len(fields) {
			return InboundFirewallRule{}, fmt.Errorf("truncated firewall rule")
		}
		value := strings.Trim(fields[i+1], "\"'")
		i++
		switch flag {
		case "-i", "-s", "-d", "-p", "--dport", "--comment", "-j":
			if _, duplicate := values[flag]; duplicate || value == "" {
				return InboundFirewallRule{}, fmt.Errorf("duplicate or missing firewall field")
			}
			values[flag] = value
		case "-m":
			if value != "udp" && value != "comment" || modules[value] {
				return InboundFirewallRule{}, fmt.Errorf("unknown or duplicate firewall match")
			}
			modules[value] = true
		default:
			return InboundFirewallRule{}, fmt.Errorf("unexpected firewall field")
		}
	}
	if values["-j"] != "ACCEPT" || !modules["comment"] {
		return InboundFirewallRule{}, fmt.Errorf("firewall rule is not an exact STL allow rule")
	}
	protocol := uint8(0)
	switch values["-p"] {
	case "udp", "17":
		protocol = 17
		if len(values) != 7 || len(modules) != 2 || !modules["udp"] || values["--dport"] == "" {
			return InboundFirewallRule{}, fmt.Errorf("noncanonical UDP allow rule")
		}
	case "gre", "47":
		protocol = 47
	case "ipip", "ipencap", "4":
		protocol = 4
	case "l2tp", "115":
		protocol = 115
	default:
		return InboundFirewallRule{}, fmt.Errorf("unsupported STL firewall protocol")
	}
	if protocol != 17 && (len(values) != 6 || len(modules) != 1 || modules["udp"] || values["--dport"] != "") {
		return InboundFirewallRule{}, fmt.Errorf("noncanonical native IP protocol allow rule")
	}
	toHost := func(raw string) (netip.Addr, error) {
		if addr, err := netip.ParseAddr(raw); err == nil {
			return addr, nil
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() {
			return netip.Addr{}, fmt.Errorf("firewall address must be a single host")
		}
		return prefix.Addr(), nil
	}
	peer, err := toHost(values["-s"])
	if err != nil {
		return InboundFirewallRule{}, err
	}
	local, err := toHost(values["-d"])
	if err != nil {
		return InboundFirewallRule{}, err
	}
	port := uint64(0)
	if protocol == 17 {
		port, err = strconv.ParseUint(values["--dport"], 10, 16)
		if err != nil || port == 0 {
			return InboundFirewallRule{}, fmt.Errorf("invalid firewall UDP port")
		}
	}
	rule := InboundFirewallRule{
		Peer: peer, Local: local, InputInterface: values["-i"],
		Protocol: protocol, DestinationPort: uint16(port),
	}
	if rule.Peer.Is6() != ipv6 || rule.Local.Is6() != ipv6 ||
		rule.Validate() != nil || values["--comment"] != firewallMarker(id, rule) {
		return InboundFirewallRule{}, fmt.Errorf("firewall fields or ownership digest do not match")
	}
	return rule, nil
}

// RecoverOwnedInboundForRemoval reconstructs only an exact, uniquely marked
// existing rule for a committed Link. This is explicitly independent of the
// current route to the peer, which may have changed or vanished. A marker
// alone is not proof: FindOwnedInbound validates the entire canonical rule,
// and the backend must also bind it to durable Link resource claims.
func RecoverOwnedInboundForRemoval(ctx context.Context, f interface {
	FindOwnedInbound(context.Context, domain.LinkID, bool) (InboundFirewallRule, bool, error)
}, id domain.LinkID, local, peer netip.Addr, protocol uint8, port uint16) (InboundFirewallRule, bool, error) {
	rule, present, err := f.FindOwnedInbound(ctx, id, false)
	if err != nil || !present {
		return InboundFirewallRule{}, false, err
	}
	if rule.Local != local || rule.Peer != peer || rule.Protocol != protocol || rule.DestinationPort != port {
		return InboundFirewallRule{}, false, fmt.Errorf("owned firewall rule no longer matches committed tunnel endpoints/protocol")
	}
	return rule, true, nil
}
