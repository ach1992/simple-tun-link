package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// The exclusive no-clobber provisioner is already shipped and is reached
// through a selected, fresh IPsec PREPARE. The observational doctor must
// describe that current path without treating missing files/units as
// authority to start a service or to take over foreign strongSwan.
const ipsecCurrentPrepareGuidance = "Review stl doctor ipsec --json, especially provisioning_readiness. Only if a fresh STL-exclusive preflight qualifies, use sudo stl menu -> Create tunnel -> Advanced types -> IPsec -> PREPARE."

// IPsecRuntimeNotRegisteredReason is shared by the observational doctor
// and inactive IPsec Link status/diagnose errors. It is a stable machine code.
const IPsecRuntimeNotRegisteredReason = "ipsec_runtime_not_registered"

// IPsecHostCheck reports one bounded, observational prerequisite. It never
// authorizes service startup, VICI writes, kernel mutation or foreign adoption.
type IPsecHostCheck struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
	Summary    string `json:"summary"`
	NextStep   string `json:"next_step"`
}

// IPsecHostReport is an independent v1, secret-safe diagnostic contract.
// The fallback read-only inspector never admits a runtime. The actual
// operational backend is independently registered by the production runtime
// only after its complete, current native-exclusive ownership checks pass.
// Successful commands here are not proof of exclusive ownership.
type IPsecHostReport struct {
	SchemaVersion     int              `json:"schema_version"`
	Backend           string           `json:"backend"`
	RuntimeMode       string           `json:"runtime_mode"`
	ActivationAllowed bool             `json:"activation_allowed"`
	Checks            []IPsecHostCheck `json:"checks"`
}

func InspectIPsecHost(ctx context.Context, runner linux.Runner) (IPsecHostReport, error) {
	return inspectIPsecHostWithInputs(ctx, runner, readIPsecPortInventory, os.Lstat, ipsec.InspectNativeExclusiveConfig, ipsec.InspectNativeExclusiveConfigOrigin, ipsec.InspectNativeExclusiveServiceUnit, ipsec.InspectNativeExclusiveServiceUnitOrigin)
}

// Both readers are test-injectable only within this package. Production uses
// bounded local /proc and fixed-path Lstat; no daemon or service mutation.
func inspectIPsecHostWithInputs(ctx context.Context, runner linux.Runner, ports ipsecPortReader, lstat servicePathLstat, config func() ipsec.NativeConfigAssessment, origin func() ipsec.NativeOriginAssessment, serviceUnit func() ipsec.NativeServiceUnitAssessment, unitOrigin func() ipsec.NativeOriginAssessment) (IPsecHostReport, error) {
	if ctx == nil || runner == nil || ports == nil || lstat == nil || config == nil || origin == nil || serviceUnit == nil || unitOrigin == nil {
		return IPsecHostReport{}, fmt.Errorf("IPsec host inspector requires complete read-only dependencies")
	}
	if err := ctx.Err(); err != nil {
		return IPsecHostReport{}, err
	}

	report := IPsecHostReport{
		SchemaVersion: 1,
		Backend:       "ipsec",
		RuntimeMode:   "native_exclusive",
		Checks:        make([]IPsecHostCheck, 0, 11),
	}
	report.Checks = append(report.Checks, inspectCharonProcesses(ctx, runner))
	report.Checks = append(report.Checks, inspectStrongSwanServiceFiles(ctx, lstat))
	report.Checks = append(report.Checks, inspectNativeExclusiveServiceUnit(serviceUnit))
	report.Checks = append(report.Checks, inspectNativeExclusiveServiceUnitOrigin(unitOrigin))
	report.Checks = append(report.Checks, inspectNativeSystemdLoadedUnit(ctx, runner))
	report.Checks = append(report.Checks, inspectNativeExclusiveConfig(config))
	report.Checks = append(report.Checks, inspectNativeExclusiveConfigOrigin(origin))
	report.Checks = append(report.Checks, inspectIPsecIKEPorts(ctx, ports))
	report.Checks = append(report.Checks, inspectIPsecCommand(ctx, runner, "/usr/sbin/swanctl", []string{"--help"},
		"strongswan_tool", "strongswan_tool_observed", "strongswan_tool_unverified",
		"strongSwan swanctl responded to a read-only help and version summary request.",
		"Cannot verify swanctl from a read-only help request.",
		"Check the installed strongSwan client package and its executable; do not modify a foreign service."))
	report.Checks = append(report.Checks, inspectIPsecCommand(ctx, runner, "/sbin/ip",
		[]string{"-json", "-details", "link", "show", "type", "xfrm"},
		"xfrm_inventory", "xfrm_inventory_readable", "xfrm_inventory_unverified",
		"Read-only XFRM interface inventory completed; XFRM creation is not proven.",
		"Cannot verify the XFRM interface inventory.",
		"Check iproute2, kernel XFRM support and inspection permissions; do not treat missing output as vacant state."))
	report.Checks = append(report.Checks, IPsecHostCheck{
		Name: "operational_runtime", Status: "blocked", ReasonCode: IPsecRuntimeNotRegisteredReason,
		Summary:  "IPsec operational runtime is not registered for this host. Its native-exclusive strongSwan service, private configuration and ownership admission are not proven by this read-only inspection.",
		NextStep: "Review blocked checks and provisioning_readiness in stl doctor ipsec --json; packages alone cannot activate IPsec. If a fresh exclusive preflight qualifies, use the selected IPsec PREPARE in sudo stl menu; recheck doctor before activating a Link.",
	})
	if err := ctx.Err(); err != nil {
		return IPsecHostReport{}, err
	}
	return report, nil
}

func inspectIPsecCommand(ctx context.Context, runner linux.Runner, binary string, args []string,
	name, observedCode, unknownCode, observedText, unknownText, nextStep string) IPsecHostCheck {
	check := IPsecHostCheck{
		Name: name, Status: "unknown", ReasonCode: unknownCode,
		Summary: unknownText, NextStep: nextStep,
	}
	if ctx.Err() != nil {
		return check
	}
	// Fixed root-owned distro executable paths avoid invoking a caller-supplied
	// PATH executable when the CLI is run with elevated privileges.
	// Missing tools fail closed as unknown; alternate distro paths require a
	// separately validated adapter, never arbitrary PATH fallback.
	// No command output, command argv or underlying error is returned.
	if _, err := runner.Run(ctx, binary, args...); err == nil {
		check.Status = "observed"
		check.ReasonCode = observedCode
		check.Summary = observedText
		check.NextStep = "No action for this observation; it is not permission to activate IPsec."
	}
	return check
}

func inspectCharonProcesses(ctx context.Context, runner linux.Runner) IPsecHostCheck {
	// pgrep -x may report both STL-owned and unrelated processes. Until
	// independently authenticated service ownership exists, ANY match blocks.
	// Exit code 1 means no process observed, not a proof no foreign state
	// or third-party writer can race an eventual activation.
	sawUnknown := false
	for _, name := range []string{"charon", "charon-systemd"} {
		if ctx.Err() != nil {
			break
		}
		_, err := runner.Run(ctx, "/usr/bin/pgrep", "-x", name)
		if err == nil {
			return IPsecHostCheck{
				Name: "daemon_process", Status: "blocked", ReasonCode: "charon_process_observed",
				Summary:  "A strongSwan daemon process is already present; STL cannot prove exclusive ownership.",
				NextStep: "Do not stop or adopt the existing daemon. Use another backend or investigate service ownership manually.",
			}
		}
		var cmdErr *linux.CommandError
		if !errors.As(err, &cmdErr) || cmdErr.ExitCode != 1 || cmdErr.TimedOut || cmdErr.Canceled {
			sawUnknown = true
		}
	}
	if sawUnknown {
		return IPsecHostCheck{
			Name: "daemon_process", Status: "unknown", ReasonCode: "charon_process_unverified",
			Summary:  "StrongSwan process inspection was incomplete; absence cannot be inferred.",
			NextStep: "Check whether pgrep can inspect host processes; do not assume an existing daemon is absent.",
		}
	}
	return IPsecHostCheck{
		Name: "daemon_process", Status: "observed", ReasonCode: "charon_process_not_observed",
		Summary:  "No charon process observed by pgrep; installed configurations, ports and kernel ownership remain unverified.",
		NextStep: "A complete ownership and service check is required before operational IPsec activation.",
	}
}
