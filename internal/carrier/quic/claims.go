package quic

import (
	"fmt"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// validateRolePorts is shared by the helper renderer and the proposed
// resource admission. This prevents a helper config from accepting a role
// topology the future canonical Engine cannot safely reserve.
func (p Plan) validateRolePorts() error {
	switch p.Role {
	case Dial:
		if p.LocalForwardUDPPort == 0 || p.PeerWGUDPPort == 0 || p.LocalWGUDPPort != 0 {
			return fmt.Errorf("QUIC dial requires only its loopback forwarding port and remote kernel-WG UDP port")
		}
	case Listen:
		if p.LocalWGUDPPort == 0 || p.LocalForwardUDPPort != 0 || p.PeerWGUDPPort != 0 {
			return fmt.Errorf("QUIC listen requires only its local kernel-WG UDP port")
		}
		if p.Underlay.Port() == p.LocalWGUDPPort {
			return fmt.Errorf("QUIC physical UDP and local kernel-WG UDP ports must differ")
		}
	default:
		return fmt.Errorf("QUIC role must be dial or listen")
	}
	return nil
}

// CarrierClaims proposes the exclusive local resources required by a future
// Engine-managed QUIC/WireGuard Link. The caller supplies the *local* kernel
// WireGuard UDP listen port from its planned native provider; PeerWGUDPPort is
// remote on Dial and must NEVER be reserved as a local socket.
//
// Claims are secret-free collision/lock identities, not evidence that any
// kernel socket, firewall guard, helper, TLS file or process exists or is owned.
// The canonical Engine must union these with native WireGuard/provider claims,
// take its maintenance/Link/resource locks, verify host ownership and journal
// the complete reservation before a single host effect. This function does
// not persist State, stage files, install helpers, or enable QUIC.
func (p Plan) CarrierClaims(localKernelWGUDPPort uint16) ([]domain.ResourceClaim, error) {
	if err := validMaterialScope(p); err != nil {
		return nil, err
	}
	if localKernelWGUDPPort == 0 {
		return nil, fmt.Errorf("QUIC requires the local kernel WireGuard UDP listen port")
	}

	if err := p.validateRolePorts(); err != nil {
		return nil, err
	}
	if p.Role == Listen && p.LocalWGUDPPort != localKernelWGUDPPort {
		return nil, fmt.Errorf("QUIC Listen local kernel WG UDP port must match its exclusive ACL destination")
	}
	var helperListenUDPPort uint16
	if p.Role == Dial {
		helperListenUDPPort = p.LocalForwardUDPPort
	} else {
		helperListenUDPPort = p.Underlay.Port()
	}
	// Existing STL UDP claims conservatively reserve the whole local UDP port,
	// not one bind address. Two listeners inside one Link cannot share it even
	// when one is bound to the physical IP and the other to loopback.
	if helperListenUDPPort == localKernelWGUDPPort {
		return nil, fmt.Errorf("QUIC helper and kernel WireGuard UDP listeners must use distinct local ports")
	}

	link := string(p.LinkID)
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceBackendID, Key: "quic/helper/" + link},
		{Kind: domain.ResourceBackendID, Key: "quic/tls-identity/" + link},
		{Kind: domain.ResourceFirewall, Key: "quic/nft/" + link},
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(localKernelWGUDPPort))},
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(helperListenUDPPort))},
	}
	for _, claim := range claims {
		if err := claim.Validate(); err != nil {
			return nil, fmt.Errorf("invalid QUIC local carrier reservation: %w", err)
		}
	}
	return claims, nil
}
