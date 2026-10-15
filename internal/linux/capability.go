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
	Available  bool
	Reason     string
	ReasonCode string // optional typed observation, never a guess from command stderr
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
	// A failed read-only FOU query alone is not evidence of an unsupported
	// kernel. It can fail because a loadable module is not yet active.
	fouModule := false
	if !fou {
		fouModule = p.commandAvailable(ctx, "modinfo", "-F", "filename", "fou")
	}
	wireguardKernel := p.commandAvailable(ctx, ip, "-json", "-details", "link", "show", "type", "wireguard")
	wireguardTool := p.commandAvailable(ctx, wg, "show", "all", "dump")
	xfrm := p.commandAvailable(ctx, ip, "-json", "-details", "link", "show", "type", "xfrm")
	// Global --help does not connect to VICI: tool presence, not readiness.
	strongSwan := p.commandAvailable(ctx, swanctl, "--help")
	systemd := p.commandAvailable(ctx, systemctl, "--version")

	report[CapabilityGRENative] = observedCapability(gre, "gre_probe_unconfirmed",
		"GRE read-only kernel query did not succeed; inspect module and permissions")
	report[CapabilityIPIPNative] = observedCapability(ipip, "ipip_probe_unconfirmed",
		"IPIP read-only kernel query did not succeed; inspect module and permissions")
	fouCode, fouReason := "fou_probe_unconfirmed",
		"FOU read-only kernel query did not succeed; support is not yet established"
	if fouModule {
		fouCode, fouReason = "fou_module_present_probe_failed",
			"FOU module is found on disk, but its runtime kernel query failed; it may not be loaded"
	}
	for _, pair := range []struct {
		cap  Capability
		base bool
	}{
		{CapabilityGREFOU, gre}, {CapabilityGREGUE, gre},
		{CapabilityIPIPFOU, ipip}, {CapabilityIPIPGUE, ipip},
	} {
		if !pair.base {
			report[pair.cap] = observedCapability(false, "base_link_probe_unconfirmed",
				"Base GRE/IPIP kernel query did not succeed; inspect its module first")
		} else {
			report[pair.cap] = observedCapability(fou, fouCode, fouReason)
		}
	}
	report[CapabilityWireGuard] = observedCapability(wireguardKernel && wireguardTool,
		"wireguard_probe_unconfirmed", "WireGuard kernel or wg tool query did not succeed")
	switch {
	case !xfrm && !strongSwan:
		report[CapabilityIPsecXFRM] = observedCapability(false, "xfrm_and_swanctl_unconfirmed",
			"XFRM kernel and strongSwan swanctl queries did not succeed")
	case !xfrm:
		report[CapabilityIPsecXFRM] = observedCapability(false, "xfrm_probe_unconfirmed",
			"XFRM kernel link query did not succeed; module/support is not established")
	default:
		report[CapabilityIPsecXFRM] = observedCapability(strongSwan, "swanctl_probe_unconfirmed",
			"strongSwan swanctl tool query did not succeed; check whether it is installed")
	}
	report[CapabilitySystemd] = observedCapability(systemd, "systemd_probe_unconfirmed",
		"systemctl version check failed")
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

func observedCapability(available bool, reasonCode, reason string) CapabilityStatus {
	if available {
		return CapabilityStatus{Available: true}
	}
	return CapabilityStatus{Reason: reason, ReasonCode: reasonCode}
}
