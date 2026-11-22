//go:build linux

package spoofhost

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// receiveBindEndpoint is LOCAL only; it is never used in pairing, Noise
// transcript, Source discovery or advertised peer destinations.
func receiveBindEndpoint(link domain.Link) netip.AddrPort {
	ip := link.Spoof.BindIPv4
	if !ip.IsValid() {
		ip = link.Underlay.Local
	}
	port := link.Spoof.BindPort
	if port == 0 {
		port = link.Spoof.ListenPort
	}
	return netip.AddrPortFrom(ip, port)
}

func receiveBindEndpoints(link domain.Link) ([]netip.AddrPort, error) {
	primary := receiveBindEndpoint(link)
	alts, err := domain.ParseSpoofAlternates(link.Spoof.BindAlternates, primary)
	if err != nil {
		return nil, err
	}
	return append([]netip.AddrPort{primary}, alts...), nil
}

// A NAT address advertised in a Setup Code need not be assigned locally.
// Its actual post-DNAT *bind* must, however, belong to the local host.
func validateReceiveBindings(link domain.Link) error {
	endpoints, err := receiveBindEndpoints(link)
	if err != nil {
		return err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("inspect local receiver interfaces: %w", err)
	}
	local := map[netip.Addr]bool{}
	for _, iface := range ifaces {
		addrs, e := iface.Addrs()
		if e != nil {
			return fmt.Errorf("inspect IPv4 of interface %s: %w", iface.Name, e)
		}
		for _, raw := range addrs {
			prefix, e := netip.ParsePrefix(raw.String())
			if e == nil && prefix.Addr().Is4() {
				local[prefix.Addr()] = true
			}
		}
	}
	for _, endpoint := range endpoints {
		if !local[endpoint.Addr()] {
			return fmt.Errorf("Spoof receiver bind %s is not locally assigned (advertised NAT IP may differ; use --bind-ipv4 and --bind-port for the post-DNAT destination)", endpoint)
		}
	}
	return nil
}
