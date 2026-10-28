package composition

import (
	"fmt"
	"strconv"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// QUICLocalAdmission is only the already-validated physical/loopback port
// projection of a QUIC Plan. The source QUIC Plan still owns TLS identity,
// peer address and the precise authenticated Hysteria configuration; none
// of those can be inferred from or authorized by this public projection.
// LocalHelperUDPPort means 127.0.0.1 forwarder on Dial and physical listener
// on Listen. RemoteWGUDPPort is a peer destination, NEVER a local claim.
type QUICLocalAdmission struct {
	LinkID             domain.LinkID
	Role               Role
	LocalWGUDPPort     uint16
	LocalHelperUDPPort uint16
	RemoteWGUDPPort    uint16
}

// CarrierClaims returns source-only QUIC claims with the same exclusive
// host-wide UDP port semantics used by all existing STL providers.
func (p QUICLocalAdmission) CarrierClaims() ([]domain.ResourceClaim, error) {
	if err := p.LinkID.Validate(); err != nil {
		return nil, fmt.Errorf("invalid QUIC Link ID")
	}
	if p.LocalWGUDPPort == 0 || p.LocalHelperUDPPort == 0 || p.LocalWGUDPPort == p.LocalHelperUDPPort {
		return nil, fmt.Errorf("QUIC helper and kernel WG require distinct local UDP listeners")
	}
	switch p.Role {
	case Dial:
		if p.RemoteWGUDPPort == 0 {
			return nil, fmt.Errorf("QUIC dial requires a remote kernel WG UDP destination")
		}
	case Listen:
		if p.RemoteWGUDPPort != 0 {
			return nil, fmt.Errorf("QUIC listen cannot reserve a dialer's remote kernel WG destination")
		}
	default:
		return nil, fmt.Errorf("QUIC role must be dial or listen")
	}
	id := string(p.LinkID)
	claims := []domain.ResourceClaim{
		{Kind: domain.ResourceBackendID, Key: "quic/helper/" + id},
		{Kind: domain.ResourceBackendID, Key: "quic/tls-identity/" + id},
		{Kind: domain.ResourceFirewall, Key: "quic/nft/" + id},
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(p.LocalWGUDPPort))},
		{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(p.LocalHelperUDPPort))},
	}
	for _, claim := range claims {
		if err := claim.Validate(); err != nil {
			return nil, fmt.Errorf("invalid QUIC local resource claim: %w", err)
		}
	}
	return claims, nil
}
