package linux

import (
	"context"
	"fmt"
)

type Capability string

const (
	CapabilityGRENative  Capability = "gre/native"
	CapabilityGREFOU     Capability = "gre/fou"
	CapabilityGREGUE     Capability = "gre/gue"
	CapabilityIPIPNative Capability = "ipip/native"
	CapabilityIPIPFOU    Capability = "ipip/fou"
	CapabilityIPIPGUE    Capability = "ipip/gue"
	CapabilityWireGuard  Capability = "wireguard"
	CapabilityIPsecXFRM  Capability = "ipsec/xfrm"
	CapabilitySystemd    Capability = "systemd"
)

type CapabilityStatus struct {
	Available bool
	Reason    string
}

type CapabilityReport map[Capability]CapabilityStatus

type CapabilityProbe struct {
	Runner          Runner
	IPBinary        string
	WGBinary        string
	SwanctlBinary   string
	SystemctlBinary string
}

// Probe reports optional capabilities independently. A missing optional backend
// never turns the whole report into an error; only an invalid probe setup or
// canceled context does. Reasons are intentionally generic and never expose
// command arguments/stdout/stderr.
func (p CapabilityProbe) Probe(ctx context.Context) (CapabilityReport, error) {
	if p.Runner == nil {
		return nil, fmt.Errorf("capability probe runner is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ip := p.IPBinary
	if ip == "" {
		ip = "ip"
	}
	wg := p.WGBinary
	if wg == "" {
		wg = "wg"
	}
	swanctl := p.SwanctlBinary
	if swanctl == "" {
		swanctl = "swanctl"
	}
	systemctl := p.SystemctlBinary
	if systemctl == "" {
		systemctl = "systemctl"
	}

	report := CapabilityReport{}
	gre := p.commandAvailable(ctx, ip, "-json", "-details", "link", "show", "type", "gre")
	ipip := p.commandAvailable(ctx, ip, "-json", "-details", "link", "show", "type", "ipip")
	fou := p.commandAvailable(ctx, ip, "fou", "show")
	wireguardKernel := p.commandAvailable(ctx, ip, "-json", "-details", "link", "show", "type", "wireguard")
	wireguardTool := p.commandAvailable(ctx, wg, "show", "all", "dump")
	xfrm := p.commandAvailable(ctx, ip, "-json", "-details", "link", "show", "type", "xfrm")
	strongSwan := p.commandAvailable(ctx, swanctl, "--version")
	systemd := p.commandAvailable(ctx, systemctl, "--version")

	report[CapabilityGRENative] = status(gre, "GRE link type is unavailable")
	report[CapabilityIPIPNative] = status(ipip, "IPIP link type is unavailable")
	report[CapabilityGREFOU] = status(gre && fou, "GRE FOU support is unavailable")
	report[CapabilityGREGUE] = status(gre && fou, "GRE GUE support is unavailable")
	report[CapabilityIPIPFOU] = status(ipip && fou, "IPIP FOU support is unavailable")
	report[CapabilityIPIPGUE] = status(ipip && fou, "IPIP GUE support is unavailable")
	report[CapabilityWireGuard] = status(wireguardKernel && wireguardTool, "WireGuard kernel/iproute2 or wg tooling is unavailable")
	report[CapabilityIPsecXFRM] = status(xfrm && strongSwan, "XFRM or strongSwan swanctl is unavailable")
	report[CapabilitySystemd] = status(systemd, "systemd systemctl is unavailable")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return report, nil
}

func (p CapabilityProbe) commandAvailable(ctx context.Context, name string, args ...string) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	_, err := p.Runner.Run(ctx, name, args...)
	return err == nil
}

func status(available bool, unavailableReason string) CapabilityStatus {
	if available {
		return CapabilityStatus{Available: true}
	}
	return CapabilityStatus{Reason: unavailableReason}
}
