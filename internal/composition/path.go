// Package composition describes the *proven* interface between an STL native
// IP backend and its optional carrier. It is a planning boundary, not another
// Link engine, a generic plugin registry, or an authorization to mutate hosts.
//
// A plan is intentionally secret-free and performs no I/O. Runtime admission
// (TLS and executable verification, resource ownership, socket isolation,
// process supervision and transactional rollback) belongs to the one owning
// backend and the existing Engine before an optional carrier can be activated.
package composition

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type Kind string

const (
	// Direct means the selected native backend uses its existing underlay.
	Direct Kind = ""
	// WSS carries only the explicitly proven WireGuard UDP socket protocol
	// in the first candidate. A UDP-shaped packet is NOT blanket permission
	// to compose native GRE/IPIP FOU/GUE or IPsec through WSS.
	WSS Kind = "wss"
)

type Role string

const (
	Dial   Role = "dial"
	Listen Role = "listen"
)

// Payload reports the current native backend's *outer* packet family. This is
// explanatory evidence for capability checks; it is NOT a universal wire codec.
type Payload string

const (
	RawIPProtocol Payload = "raw-ip-protocol"
	UDPDatagrams  Payload = "udp-datagrams"
	IPSecESP      Payload = "ipsec-esp"
)

// Carrier is endpoint-local, comparable and entirely public/secret-free.
// CredentialOwner binds an out-of-band protected per-Link TLS identity; it is
// NOT a credential, file path, arbitrary executable, CA material or authority
// to start an external process. None of this is yet a public Link JSON schema.
type Carrier struct {
	Kind            Kind
	Role            Role
	PublicTCPPort   uint16
	LocalForwardUDP uint16
	TLSServerName   string
	CredentialOwner domain.LinkID
}

// Path separates actual physical addresses, private Link Addresses and the
// optional loopback WG UDP endpoint. In WSS listen mode, WG has *no* static
// peer endpoint: authenticated packets arriving via the loopback carrier are
// the only permitted source of roaming state after isolation enforcement.
type Path struct {
	Provider           domain.Backend
	Encapsulation      domain.Encapsulation
	Payload            Payload
	Kind               Kind
	Role               Role
	Physical           domain.Underlay
	Private            domain.LinkAddresses
	WGPeerEndpoint     netip.AddrPort
	WSSPeerTCP         netip.AddrPort
	WSSLocalTCP        netip.AddrPort
	WSSLocalUDP        netip.AddrPort
	WSSRemoteWGUDPPort uint16
	TLSName            string
	CredentialOwner    domain.LinkID
}

// Build proves a supported *design* combination, never live transport
// readiness. WSS's host admission must separately demonstrate a pinned
// executable, strict mTLS, exact destination restrictions, kernel WG UDP
// ingress isolation and ownership-safe helper process/systemd management.
// Until those adapters are operational, this package must not be treated
// as enabling a new CLI/State/pairing Carrier.
func Build(link domain.Link, carrier Carrier) (Path, error) {
	if err := link.Validate(); err != nil {
		return Path{}, err
	}
	payload, err := nativePayload(link)
	if err != nil {
		return Path{}, err
	}
	plan := Path{
		Provider: link.Backend, Encapsulation: link.Encapsulation,
		Payload: payload, Kind: carrier.Kind,
		Physical: link.Underlay, Private: link.Addresses,
	}
	switch carrier.Kind {
	case Direct:
		if carrier != (Carrier{}) {
			return Path{}, fmt.Errorf("native path must not carry a carrier role, endpoint or identity")
		}
		if link.Backend == domain.BackendWireGuard {
			if link.WireGuard.PeerPort == 0 || link.WireGuard.ListenPort == 0 {
				return Path{}, fmt.Errorf("native WireGuard needs configured peer and listen UDP ports")
			}
			plan.WGPeerEndpoint = netip.AddrPortFrom(link.Underlay.Peer, link.WireGuard.PeerPort)
		}
		return plan, nil
	case WSS:
		// Precisely one proven inner framing/topology is supported today.
		// A matching UDP wire shape alone does not establish GRE FOU/GUE
		// endpoint/device/source compatibility.
		if link.Backend != domain.BackendWireGuard || link.Encapsulation != domain.EncapUDP {
			return Path{}, fmt.Errorf("WSS composition is supported only for kernel WireGuard UDP")
		}
		// The shipped WG route/firewall adapters currently require IPv4
		// physical endpoints. Do not advertise an IPv6 composed path until
		// those specific adapters and local isolation are actually verified.
		if !link.Underlay.Local.Is4() || !link.Underlay.Peer.Is4() {
			return Path{}, fmt.Errorf("WSS kernel WireGuard currently requires IPv4 physical endpoints")
		}
		// A virtual Link route must never capture either underlay endpoint:
		// doing so could route the WSS control connection into its own
		// not-yet-established private link. The same Link may be valid in
		// other native modes, but this particular composition is not.
		for _, physical := range []netip.Addr{link.Underlay.Local, link.Underlay.Peer} {
			if physical.IsLoopback() || physical.IsUnspecified() ||
				link.Addresses.Local.Contains(physical) || link.Addresses.Peer.Contains(physical) {
				return Path{}, fmt.Errorf("WSS physical underlay cannot be loopback or overlap private Link routes")
			}
		}
		if link.WireGuard.ListenPort == 0 || link.WireGuard.PeerPort == 0 {
			return Path{}, fmt.Errorf("WSS WireGuard requires explicit distinct peer UDP port identities")
		}
		if carrier.PublicTCPPort == 0 {
			return Path{}, fmt.Errorf("WSS requires an explicit physical TCP port")
		}
		if carrier.CredentialOwner != link.ID {
			return Path{}, fmt.Errorf("WSS TLS identity must be scoped to this exact Link")
		}
		plan.CredentialOwner = link.ID
		plan.Role = carrier.Role
		switch carrier.Role {
		case Dial:
			if carrier.LocalForwardUDP == 0 || carrier.LocalForwardUDP == link.WireGuard.ListenPort {
				return Path{}, fmt.Errorf("WSS dial side requires a distinct nonzero loopback UDP forwarding port")
			}
			// With no explicit DNS override, strict certificate validation
			// uses the actual physical peer IP/SAN (the tested field setup).
			// An override is only for a separately trusted DNS SAN.
			name := carrier.TLSServerName
			if name == "" {
				name = link.Underlay.Peer.String()
			}
			if !validTLSName(name) {
				return Path{}, fmt.Errorf("WSS dial side requires an exact IP SAN or canonical DNS server identity")
			}
			// wstunnel v11.0.0 implements --tls-sni-override using
			// rustls DnsName, not IpAddress. A different IP SAN cannot
			// be selected as an override: fail here, rather than hand a
			// syntactically accepted but unrunnable plan to the operator.
			if parsed, err := netip.ParseAddr(name); err == nil && parsed != link.Underlay.Peer {
				return Path{}, fmt.Errorf("WSS TLS IP identity must match the physical TCP peer; use DNS SAN for a distinct name")
			}
			plan.TLSName = name
			plan.WSSPeerTCP = netip.AddrPortFrom(link.Underlay.Peer, carrier.PublicTCPPort)
			plan.WSSLocalUDP = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), carrier.LocalForwardUDP)
			plan.WGPeerEndpoint = plan.WSSLocalUDP
			plan.WSSRemoteWGUDPPort = link.WireGuard.PeerPort
		case Listen:
			if carrier.LocalForwardUDP != 0 || carrier.TLSServerName != "" {
				return Path{}, fmt.Errorf("WSS listening side cannot configure a dial-side loopback forwarder or TLS server name")
			}
			plan.WSSLocalTCP = netip.AddrPortFrom(link.Underlay.Local, carrier.PublicTCPPort)
			plan.WSSRemoteWGUDPPort = link.WireGuard.ListenPort
			// No public/physical WG endpoint may be invented here.
		default:
			return Path{}, fmt.Errorf("WSS role must be dial or listen")
		}
		return plan, nil
	default:
		return Path{}, fmt.Errorf("unsupported carrier kind %q", carrier.Kind)
	}
}

func nativePayload(link domain.Link) (Payload, error) {
	switch link.Backend {
	case domain.BackendWireGuard:
		if link.Encapsulation == domain.EncapUDP {
			return UDPDatagrams, nil
		}
	case domain.BackendGRE, domain.BackendIPIP:
		switch link.Encapsulation {
		case domain.EncapNative:
			return RawIPProtocol, nil
		case domain.EncapFOU, domain.EncapGUE:
			return UDPDatagrams, nil
		}
	case domain.BackendIPsec:
		switch link.Encapsulation {
		case domain.EncapESP:
			return IPSecESP, nil
		case domain.EncapNATT:
			return UDPDatagrams, nil
		}
	}
	return "", fmt.Errorf("unsupported native provider/encapsulation %q/%q", link.Backend, link.Encapsulation)
}

func validTLSName(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\:@ \t\n\r") {
		return false
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.Zone() == "" && !ip.IsUnspecified()
	}
	// Only canonical ASCII DNS names, not URL fragments, credentials or raw
	// shell/HTTP syntax. DNS validation is intentionally stricter than regex
	// identity matching; TLS SAN verification still occurs at runtime.
	if net.ParseIP(value) != nil || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}
	return true
}

// CarrierClaims are the extra *exclusive* host-resource reservations a WSS
// adapter must include in the SAME Engine plan as its native L3 provider.
// A claim is a lock/collision identity, not authority to delete that resource.
// The composed backend must still independently inspect physical ownership,
// reserve real firewall/process/file identities, and verify post-apply state.
func (p Path) CarrierClaims() []domain.ResourceClaim {
	if p.Kind != WSS {
		return nil
	}
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceBackendID, Key: "wss/helper/" + string(p.CredentialOwner)},
		{Kind: domain.ResourceBackendID, Key: "wss/tls-identity/" + string(p.CredentialOwner)},
	}
	switch p.Role {
	case Dial:
		claims = append(claims, domain.ResourceClaim{
			Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(p.WSSLocalUDP.Port())),
		})
	case Listen:
		claims = append(claims, domain.ResourceClaim{
			Kind: domain.ResourceTCPListenPort, Key: strconv.Itoa(int(p.WSSLocalTCP.Port())),
		})
	}
	return claims
}
