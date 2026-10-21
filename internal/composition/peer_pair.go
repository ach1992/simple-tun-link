package composition

import (
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// ValidateWSSPeerPair validates the public, endpoint-local intent for one
// explicitly dial/listen WSS+kernel-WireGuard Link before any host resources
// are allocated. It is deliberately not a generic Carrier-pairing protocol.
//
// Only an exact reciprocal physical/inner Link and WG identity is admitted.
// A NAT-translated/non-reciprocal topology requires its own explicit,
// separately validated endpoint contract; do not silently infer one here.
//
// This check does not provision credentials, prove that certificate chains or
// bearer tokens match, reserve ports, or authorize a WSS runtime. Local Build,
// protected material inspection and the Engine transaction remain required.
func ValidateWSSPeerPair(dialLink domain.Link, dialCarrier Carrier, listenLink domain.Link, listenCarrier Carrier) error {
	dial, err := Build(dialLink, dialCarrier)
	if err != nil {
		return fmt.Errorf("WSS dial peer is invalid: %w", err)
	}
	listen, err := Build(listenLink, listenCarrier)
	if err != nil {
		return fmt.Errorf("WSS listen peer is invalid: %w", err)
	}
	if dial.Kind != WSS || dial.Role != Dial || listen.Kind != WSS || listen.Role != Listen {
		return fmt.Errorf("WSS pair requires exactly one dial peer and one listen peer")
	}
	if dialLink.ID != listenLink.ID {
		return fmt.Errorf("WSS peers must have the same Link ID")
	}
	if dial.Physical.Local != listen.Physical.Peer || dial.Physical.Peer != listen.Physical.Local {
		return fmt.Errorf("WSS physical endpoints are not reciprocal")
	}
	if dial.Private.Local != listen.Private.Peer || dial.Private.Peer != listen.Private.Local {
		return fmt.Errorf("WSS private Link Addresses are not reciprocal")
	}
	if dialLink.WireGuard.LocalPublicKey != listenLink.WireGuard.PeerPublicKey ||
		dialLink.WireGuard.PeerPublicKey != listenLink.WireGuard.LocalPublicKey {
		return fmt.Errorf("WSS WireGuard peer identities are not reciprocal")
	}
	if dialLink.WireGuard.ListenPort != listenLink.WireGuard.PeerPort ||
		dialLink.WireGuard.PeerPort != listenLink.WireGuard.ListenPort {
		return fmt.Errorf("WSS WireGuard UDP ports are not reciprocal")
	}
	if dial.TLSName != listen.TLSName || dial.WSSPeerTCP != listen.WSSLocalTCP {
		return fmt.Errorf("WSS TLS server identity or physical TCP endpoint differs between peers")
	}
	return nil
}
