package quic

import (
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// validateRolePorts is shared by the helper renderer and canonical resource
// admission. Configurations cannot bypass the role's exclusive reservations.
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

// LocalAdmission translates a full public QUIC Plan into the minimum local
// resource identity required for Engine-locked, read-only collision checks.
// It validates the full TLS endpoint/role first. A caller must never treat
// the projection as authority to stage credentials or start a helper.
func (p Plan) LocalAdmission(localKernelWGUDPPort uint16) (composition.QUICLocalAdmission, error) {
	if err := validMaterialScope(p); err != nil {
		return composition.QUICLocalAdmission{}, err
	}
	if localKernelWGUDPPort == 0 {
		return composition.QUICLocalAdmission{}, fmt.Errorf("QUIC requires the local kernel WireGuard UDP listen port")
	}
	if err := p.validateRolePorts(); err != nil {
		return composition.QUICLocalAdmission{}, err
	}
	if p.Role == Listen && p.LocalWGUDPPort != localKernelWGUDPPort {
		return composition.QUICLocalAdmission{}, fmt.Errorf("QUIC Listen local kernel WG UDP port must match its exclusive ACL destination")
	}
	localHelper := p.Underlay.Port()
	if p.Role == Dial {
		localHelper = p.LocalForwardUDPPort
	}
	projection := composition.QUICLocalAdmission{
		LinkID: p.LinkID, Role: composition.Role(p.Role),
		LocalWGUDPPort:     localKernelWGUDPPort,
		LocalHelperUDPPort: localHelper,
	}
	if p.Role == Dial {
		projection.RemoteWGUDPPort = p.PeerWGUDPPort
	}
	if _, err := projection.CarrierClaims(); err != nil {
		return composition.QUICLocalAdmission{}, err
	}
	return projection, nil
}

// CarrierClaims returns the local exclusive resources consumed by canonical
// Engine planning and read-only collision admission. The remote WireGuard
// destination is not a locally owned resource.
func (p Plan) CarrierClaims(localKernelWGUDPPort uint16) ([]domain.ResourceClaim, error) {
	projection, err := p.LocalAdmission(localKernelWGUDPPort)
	if err != nil {
		return nil, err
	}
	return projection.CarrierClaims()
}

// HostPlan is a complete, public-only journal projection of the exact QUIC
// Plan. It does not prove credentials, socket vacancy or authorization for
// helper/host effects, which remain the canonical Engine's responsibility.
func (p Plan) HostPlan(localKernelWGUDPPort uint16) (composition.QUICHostPlan, error) {
	local, err := p.LocalAdmission(localKernelWGUDPPort)
	if err != nil {
		return composition.QUICHostPlan{}, err
	}
	full := composition.QUICHostPlan{
		Local: local, Physical: p.Underlay, TLSName: p.TLSName,
	}
	if err := full.Validate(); err != nil {
		return composition.QUICHostPlan{}, err
	}
	return full, nil
}
