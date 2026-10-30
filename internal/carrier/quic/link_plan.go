package quic

import (
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// PlanFromLink is the carrier's projection of the one canonical composition
// plan. It never admits material or a host effect independently of the Engine.
func PlanFromLink(link domain.Link) (Plan, error) {
	host, err := composition.QUICHostPlanForLink(link)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{LinkID: host.Local.LinkID, Role: Role(host.Local.Role), Underlay: host.Physical, TLSName: host.TLSName}
	if p.Role == Dial {
		p.LocalForwardUDPPort, p.PeerWGUDPPort = host.Local.LocalHelperUDPPort, host.Local.RemoteWGUDPPort
	} else {
		p.LocalWGUDPPort = host.Local.LocalWGUDPPort
	}
	projected, err := p.HostPlan(link.WireGuard.ListenPort)
	if err != nil || projected != host {
		return Plan{}, fmt.Errorf("QUIC carrier and canonical composition differ")
	}
	return p, nil
}
