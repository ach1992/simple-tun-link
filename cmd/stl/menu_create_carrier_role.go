package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// recommendCarrierRole is a provisional, symmetric topology tie-breaker.
// An offline Setup Link cannot probe an unconfigured peer's authenticated
// listener. The suggestion MUST NOT be reported as a successful WAN test.
func recommendCarrierRole(local, peer netip.Addr) (role, basis string) {
	localPublic := nonPrivateIPv4Scope(local)
	peerPublic := nonPrivateIPv4Scope(peer)
	switch {
	case localPublic && !peerPublic:
		return "listen", "this endpoint has a non-private IPv4 address"
	case !localPublic && peerPublic:
		return "dial", "the other endpoint has a non-private IPv4 address"
	case local.Compare(peer) < 0:
		return "listen", "deterministic IPv4 ordering (both have the same address scope)"
	default:
		return "dial", "deterministic IPv4 ordering (both have the same address scope)"
	}
}

// A non-RFC1918/global-unicast address is only a topology hint: other
// special-use IPv4 addresses may still be unroutable. This is not a NAT,
// firewall, routing, provider or authenticated peer reachability probe.
func nonPrivateIPv4Scope(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// The operator can accept the suggestion with Enter or select either public
// direction in the same prompt. All persisted and paired configurations
// retain concrete dial/listen roles, not an unverified runtime "auto" role.
func askCarrierRole(p createPrompts, carrier string, local, peer netip.Addr) (role, source string, err error) {
	suggested, basis := recommendCarrierRole(local, peer)
	menuSection(p.out, carrier+" / public connection direction")
	menuProse(p.out, fmt.Sprintf("Suggested: THIS server will %s (%s).", strings.ToUpper(suggested), basis))
	menuProse(p.out, "This is an unverified suggestion, not a reachability check. The OTHER server receives the opposite role.")
	menuOption(p.out, "1", "Listen", "THIS server accepts public connections")
	menuOption(p.out, "2", "Dial", "OTHER server accepts public connections")
	answer, err := p.ask("Direction [Enter=suggested; 1=listen; 2=dial]: ")
	if err != nil {
		return "", "", err
	}
	switch answer {
	case "":
		return suggested, "suggested (unverified)", nil
	case "1":
		return "listen", "manual override", nil
	case "2":
		return "dial", "manual override", nil
	default:
		return "", "", fmt.Errorf("use Enter, 1 or 2 to choose the public connection direction")
	}
}
