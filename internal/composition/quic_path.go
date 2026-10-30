package composition

import (
	"fmt"
	"net/netip"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// QUICHostPlanForLink derives the complete public carrier plan from one
// validated managed Link. It performs no admission, I/O or host mutation.
func QUICHostPlanForLink(link domain.Link) (QUICHostPlan, error) {
	if link.Backend != domain.BackendWireGuardQUIC {
		return QUICHostPlan{}, fmt.Errorf("QUIC requires the wireguard-quic backend")
	}
	path, err := Build(link, CarrierForLink(link))
	if err != nil {
		return QUICHostPlan{}, err
	}
	return path.QUIC, nil
}

func buildQUICPath(link domain.Link, carrier Carrier, path Path) (Path, error) {
	if (link.Backend != domain.BackendWireGuard && link.Backend != domain.BackendWireGuardQUIC) ||
		link.Encapsulation != domain.EncapUDP || carrier.PublicTCPPort != 0 {
		return Path{}, fmt.Errorf("QUIC composition requires native WireGuard UDP and no TCP carrier endpoint")
	}
	if link.WireGuard.Validate() != nil || link.WireGuard.ListenPort == 0 || link.WireGuard.PeerPort == 0 ||
		carrier.PublicUDPPort == 0 || carrier.CredentialOwner != link.ID {
		return Path{}, fmt.Errorf("QUIC requires complete per-Link WireGuard, UDP and credential identities")
	}
	for _, route := range []netip.Prefix{link.Addresses.Local, link.Addresses.Peer} {
		if err := ValidateComposedPrivateIPv4Route(route); err != nil {
			return Path{}, fmt.Errorf("QUIC private route is invalid: %w", err)
		}
	}
	for _, physical := range []netip.Addr{link.Underlay.Local, link.Underlay.Peer} {
		if !physical.Is4() || physical.IsUnspecified() || physical.IsMulticast() || physical.IsLoopback() ||
			link.Addresses.Local.Contains(physical) || link.Addresses.Peer.Contains(physical) {
			return Path{}, fmt.Errorf("QUIC requires IPv4 physical endpoints outside loopback and the private Link routes")
		}
	}
	local := QUICLocalAdmission{LinkID: link.ID, Role: carrier.Role, LocalWGUDPPort: link.WireGuard.ListenPort}
	physical := link.Underlay.Local
	switch carrier.Role {
	case Dial:
		physical = link.Underlay.Peer
		local.LocalHelperUDPPort = carrier.LocalForwardUDP
		local.RemoteWGUDPPort = link.WireGuard.PeerPort
		path.WGPeerEndpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), carrier.LocalForwardUDP)
	case Listen:
		if carrier.LocalForwardUDP != 0 {
			return Path{}, fmt.Errorf("QUIC listen cannot specify a dial-side forwarding socket")
		}
		local.LocalHelperUDPPort = carrier.PublicUDPPort
	default:
		return Path{}, fmt.Errorf("QUIC requires an explicit dial or listen role")
	}
	name := carrier.TLSServerName
	if name == "" {
		name = physical.String()
	}
	path.QUIC = QUICHostPlan{Local: local, Physical: netip.AddrPortFrom(physical, carrier.PublicUDPPort), TLSName: name, Obfuscation: link.QUIC.Obfuscation}
	if err := path.QUIC.Validate(); err != nil {
		return Path{}, err
	}
	path.Role = carrier.Role
	path.CredentialOwner = link.ID
	path.TLSName = name
	return path, nil
}

// ValidateQUICPeerPair checks reciprocal public topology before either
// endpoint receives credentials or creates host resources. A matching pair
// does not demonstrate authentication or bilateral traffic.
func ValidateQUICPeerPair(dialLink domain.Link, dialCarrier Carrier, listenLink domain.Link, listenCarrier Carrier) error {
	dial, err := Build(dialLink, dialCarrier)
	if err != nil {
		return fmt.Errorf("QUIC dial peer is invalid: %w", err)
	}
	listen, err := Build(listenLink, listenCarrier)
	if err != nil {
		return fmt.Errorf("QUIC listen peer is invalid: %w", err)
	}
	if dial.Kind != QUIC || dial.Role != Dial || listen.Kind != QUIC || listen.Role != Listen ||
		dialLink.ID != listenLink.ID || dial.Physical.Local != listen.Physical.Peer || dial.Physical.Peer != listen.Physical.Local ||
		dial.Private.Local != listen.Private.Peer || dial.Private.Peer != listen.Private.Local {
		return fmt.Errorf("QUIC requires one reciprocal dial/listen pair for the same Link")
	}
	if dialLink.WireGuard.LocalPublicKey != listenLink.WireGuard.PeerPublicKey ||
		dialLink.WireGuard.PeerPublicKey != listenLink.WireGuard.LocalPublicKey ||
		dialLink.WireGuard.ListenPort != listenLink.WireGuard.PeerPort ||
		dialLink.WireGuard.PeerPort != listenLink.WireGuard.ListenPort {
		return fmt.Errorf("QUIC WireGuard keys and ports must be reciprocal")
	}
	if dial.QUIC.Physical != listen.QUIC.Physical || dial.TLSName != listen.TLSName || dial.QUIC.Obfuscation != listen.QUIC.Obfuscation {
		return fmt.Errorf("QUIC peers must agree on the physical UDP listener, TLS server identity and obfuscation mode")
	}
	return nil
}
