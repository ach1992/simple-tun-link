package main

import (
	"fmt"
	"io"
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
	menuProse(p.out, "Unverified default: no WAN test. Address ordering cannot predict reachability.")
	menuProse(p.out, "If you know which server accepts inbound traffic, select that server as Listen.")
	menuOption(p.out, "1", "Listen", "THIS server accepts public connections")
	menuOption(p.out, "2", "Dial", "OTHER server accepts public connections")
	for {
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
			menuNotice(p.out, "WARNING", "Choose Enter, 1 (this server listens), 2 (this server dials), or q to cancel.")
		}
	}
}

// Review must identify the concrete public listener as well as both peer roles.
// Neither the symmetric offline default nor a manual choice proves that the
// selected public listener is reachable from the other endpoint.
func showCarrierDirectionReview(out io.Writer, local, peer netip.Addr, role, source, protocol string, port uint16) {
	peerRole, listener := "listen", peer
	if role == "listen" {
		peerRole, listener = "dial", local
	}
	menuField(out, "This server", local.String()+" ("+role+")")
	menuField(out, "Other server", peer.String()+" ("+peerRole+")")
	menuField(out, "Direction choice", source)
	menuField(out, "Public listener", fmt.Sprintf("%s:%d/%s", listener, port, protocol))
	menuNotice(out, "INFO", "Public reachability is unverified until the peer is paired and private traffic succeeds.")
	menuProse(out, "Listener unreachable? Diagnose both peers; to change direction, safely retire and recreate the incomplete Link. No automatic role switch.")
}
