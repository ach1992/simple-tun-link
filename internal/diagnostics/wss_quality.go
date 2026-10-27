package diagnostics

import (
	"context"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// ObservePrivateLinkQuality performs the common bounded five-echo test over an
// ALREADY owner-verified, private IPv4 Link interface. The calling carrier
// adapter must independently attest its transport, guard and WireGuard peer
// before invoking this function. It deliberately does NOT derive a path MTU
// from Native WireGuard overhead: WSS/TLS framing is not a fixed overhead.
func VerifyPrivateLinkIdentity(ctx context.Context, link domain.Link, iface string, runner linux.Runner) (int, error) {
	opts := LinuxProbeOptions{Runner: runner, Interface: iface}
	if err := validateLinuxProbeOptions(link, opts); err != nil {
		return 0, err
	}
	// Confirm the exact private address, UP interface, and selected route to
	// the saved peer before sending even a single ICMP packet. No host changes.
	tunnel, err := inspectLinuxInterface(ctx, runner, "ip", true, iface)
	if err != nil {
		return 0, err
	}
	owned := false
	for _, addr := range tunnel.AddrInfo {
		if addr.Family == "inet" && addr.Local == link.Addresses.Local.Addr().String() &&
			addr.PrefixLen == link.Addresses.Local.Bits() {
			owned = true
			break
		}
	}
	if !owned {
		return 0, fmt.Errorf("selected private interface address does not match saved Link")
	}
	route, err := (linux.RouteResolver{Runner: runner}).Resolve(ctx, link.Addresses.Peer.Addr())
	if err != nil {
		return 0, err
	}
	if route.Device != iface || route.Source != link.Addresses.Local.Addr() {
		return 0, fmt.Errorf("private peer route or source identity changed")
	}
	return tunnel.MTU, nil
}

func ObservePrivateLinkQuality(ctx context.Context, link domain.Link, iface string, runner linux.Runner) (Report, error) {
	mtu, err := VerifyPrivateLinkIdentity(ctx, link, iface, runner)
	if err != nil {
		return Report{}, err
	}
	prober, err := NewLinuxDFProber(link, LinuxProbeOptions{Runner: runner, Interface: iface})
	if err != nil {
		return Report{}, err
	}
	quality, err := MeasureQuality(ctx, link, mtu, DefaultQualitySamples, prober)
	if err != nil {
		return Report{}, err
	}
	return Report{SchemaVersion: SchemaVersion, LinkID: link.ID,
		MTU: MTUResult{Mode: "not_measured"}, Quality: quality}, nil
}
