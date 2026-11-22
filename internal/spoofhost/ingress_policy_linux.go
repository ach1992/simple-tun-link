//go:build linux

package spoofhost

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// needsIngressException is deliberately a *conservative* check of rules
// directly in the iptables INPUT chain. No firewall policy is changed when
// the relevant path is already accepted. It never guesses that a foreign
// jump chain, stateful extension, or provider ACL is itself a known block.
func needsIngressException(snapshot string, link domain.Link, route managedIngress) (bool, error) {
	policy := ""
	uncertain := false
	for _, line := range strings.Split(snapshot, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "-P" && fields[1] == "INPUT" {
			policy = fields[2]
			continue
		}
		if len(fields) < 4 || fields[0] != "-A" || fields[1] != "INPUT" {
			continue
		}
		// Link-owned rules are not evidence the underlying firewall would
		// have denied the traffic without STL's permission.
		if strings.Contains(line, "stl:spoof:"+string(link.ID)+":") {
			continue
		}
		verdict, relevant, exact := inputRuleVerdict(fields, route, link)
		if !relevant {
			continue
		}
		if !exact {
			uncertain = true
			continue
		}
		if uncertain {
			continue
		}
		switch verdict {
		case "ACCEPT":
			return false, nil
		case "DROP", "REJECT":
			return true, nil
		case "":
		default:
			uncertain = true
		}
	}
	if policy != "ACCEPT" && policy != "DROP" {
		return false, fmt.Errorf("cannot identify original iptables INPUT policy %q", policy)
	}
	if uncertain {
		// Without a proof of obstruction, STL does not alter a host
		// firewall just because the operator selected management.
		// Another manager/chain can be diagnosed separately.
		return false, nil
	}
	return policy == "DROP", nil
}

func inputRuleVerdict(fields []string, route managedIngress, link domain.Link) (verdict string, relevant, exact bool) {
	relevant, exact = true, true
	protocol := map[string]string{"udp": "17", "tcp": "6", "icmp": "1", "gre": "47", "ipip": "4", "proto58": "58", "l2tpv3": "115"}[route.protocol]
	if protocol == "" {
		return "", false, false
	}
	for i := 2; i < len(fields); i++ {
		flag := fields[i]
		if flag == "!" {
			return "", true, false
		}
		if i+1 >= len(fields) {
			return "", true, false
		}
		value := strings.Trim(fields[i+1], "\"'")
		switch flag {
		case "-j":
			verdict = value
		case "-i":
			if value != link.Spoof.Interface {
				return "", false, true
			}
		case "-d":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				address, e := netip.ParseAddr(value)
				if e != nil {
					return "", true, false
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			if !prefix.Contains(route.endpoint.Addr()) {
				return "", false, true
			}
		case "-s":
			if value != "0.0.0.0/0" && value != "0/0" {
				return "", true, false
			}
		case "-p":
			matches := value == "all" || value == "0" || value == protocol ||
				(value == "udp" && protocol == "17") || (value == "tcp" && protocol == "6") ||
				(value == "icmp" && protocol == "1") || (value == "gre" && protocol == "47") ||
				(value == "ipip" && protocol == "4")
			if !matches {
				return "", false, true
			}
		case "--dport":
			if protocol != "17" && protocol != "6" {
				return "", false, true
			}
			port, e := strconv.Atoi(value)
			if e != nil || port < 1 || port > 65535 {
				return "", true, false
			}
			if uint16(port) != route.endpoint.Port() {
				return "", false, true
			}
		case "--icmp-type":
			if protocol != "1" {
				return "", false, true
			}
			if value != "echo-reply" && value != "0" && value != "0/0" {
				return "", true, false
			}
		case "-m":
			if value != "tcp" && value != "udp" && value != "icmp" && value != "comment" {
				return "", true, false
			}
		case "--comment": // metadata only
		default:
			return "", true, false
		}
		i++
	}
	return verdict, relevant, exact
}
