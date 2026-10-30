package quic

import (
	"fmt"
	"net/netip"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// QUICMinimumIPv4UnderlayMTU is a necessary local-route minimum, not a
// measured peer PMTU: RFC 9000 section 14 requires a 1200-byte UDP payload,
// plus the 20-byte IPv4 and 8-byte UDP headers used by this composition.
const QUICMinimumIPv4UnderlayMTU = 1228

// MinimumIPv4UnderlayMTU adds the selected wire representation's necessary
// overhead to the plain QUIC minimum. The pinned helper's Salamander wrapper
// prepends an eight-byte salt after QUIC packet construction (extras/obfs/
// salamander.go at ca8fbd874fd6ca82413948de6dc5924405e103e1). This lower bound
// neither measures peer PMTU nor guarantees that every handshake packet fits.
func MinimumIPv4UnderlayMTU(obfuscation string) (int, error) {
	switch obfuscation {
	case domain.QUICObfuscationPlain:
		return QUICMinimumIPv4UnderlayMTU, nil
	case domain.QUICObfuscationSalamander:
		return QUICMinimumIPv4UnderlayMTU + 8, nil
	default:
		return 0, fmt.Errorf("unsupported QUIC obfuscation mode for MTU")
	}
}

// MaximumWireGuardMTU returns the conservative, padding-aligned inner IPv4
// limit of the pinned helper. Hysteria app/v2.13.0 (commit
// ca8fbd874fd6ca82413948de6dc5924405e103e1) uses a 4096-byte SendBuf in
// core/client/udp.go. Its core/internal/protocol/proxy.go serializes the
// complete UDP message BEFORE attempting QUIC-datagram fragmentation.
// Subtract its address header and WireGuard's 16-byte transport header plus
// 16-byte AEAD tag, then round down for WireGuard's 16-byte padding units.
// This is a helper capacity limit, not a fixed QUIC encapsulation overhead.
func MaximumWireGuardMTU(plan Plan) (int, error) {
	if err := validMaterialScope(plan); err != nil {
		return 0, err
	}
	if err := plan.validateRolePorts(); err != nil {
		return 0, err
	}
	port := plan.LocalWGUDPPort
	if plan.Role == Dial {
		port = plan.PeerWGUDPPort
	}
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String()
	// All admitted addresses are 127.0.0.1:<uint16>, hence one varint byte.
	if len(addr) > 63 {
		return 0, fmt.Errorf("QUIC helper destination exceeds admitted MTU framing")
	}
	const helperBuffer = 4096
	const wireGuardTransport = 16 + 16
	const wireGuardPadding = 16
	helperHeader := 4 + 2 + 1 + 1 + 1 + len(addr)
	return (helperBuffer - helperHeader - wireGuardTransport) / wireGuardPadding * wireGuardPadding, nil
}
