package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
)

// Only one narrow, pre-vetted distro service may be stopped by the menu.
// Production uses the installed STL exclusive maintenance gate and rechecks
// the exact package-owned systemd identity immediately before mutation.
// Other services remain manual reconciliation, never generic "stop all".
type menuIPsecVendorOps struct {
	inspect   func(context.Context) (ipsecbackend.VendorServiceStopPlan, error)
	stop      func(context.Context, ipsecbackend.VendorServiceStopPlan) error
	readiness func(context.Context) error
}

func productionMenuIPsecVendorOps() menuIPsecVendorOps {
	return menuIPsecVendorOps{
		inspect:   ipsecbackend.InspectVendorServiceStopPlan,
		stop:      ipsecbackend.StopDisableVerifiedVendorService,
		readiness: ipsecbackend.NativeProvisionReadiness,
	}
}

// A failed IPsec admission is NOT automatically license to alter any other
// service. Give the operator a useful way forward: a separately confirmed
// and independently verified supported unit can be stopped/disabled, or the
// operator can manually reconcile then explicitly RECHECK. Both still need
// fresh provisioner admission and a separate Link YES afterwards.
func menuResolveIPsecServiceConflict(input io.Reader, reader *bufio.Reader, out io.Writer,
	allPackagesReady bool,
) bool {
	return menuResolveIPsecServiceConflictWithOps(input, reader, out, allPackagesReady, productionMenuIPsecVendorOps())
}

func menuResolveIPsecServiceConflictWithOps(input io.Reader, reader *bufio.Reader, out io.Writer,
	allPackagesReady bool, ops menuIPsecVendorOps,
) bool {
	if ops.inspect == nil || ops.stop == nil || ops.readiness == nil {
		return false
	}
	menuScreen(out, "IPsec / existing service or ownership conflict")
	menuNotice(out, "WARNING", "IPsec readiness is blocked. Other tunnel backends remain available.")
	menuProse(out, "A real VPN may be using systemd, ports, and credentials. Stopping a service can immediately disconnect its users. Do not delete, adopt, mask, or overwrite unknown services/configuration.")
	menuCopyLine(out, "Read-only IPsec report", "sudo stl doctor ipsec --json")
	menuCopyLine(out, "List loaded IPsec services", "sudo systemctl --system --no-pager --plain --all --type=service list-units 'strongswan*.service' 'charon*.service' 'ipsec.service' 'simple-tun-link-ipsec.service'")
	menuCopyLine(out, "List service files", "sudo systemctl --system --no-pager list-unit-files 'strongswan*.service' 'charon*.service' 'ipsec.service' 'simple-tun-link-ipsec.service'")
	menuNotice(out, "INFO", "Checking exact service and distro package identity; signed public package downloads may be required. No service is changed by this inspection.")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	plan, err := ops.inspect(ctx)
	cancel()
	supported := err == nil && allPackagesReady && plan.Unit == "strongswan.service" &&
		(plan.Active == "active" || plan.Enabled == "enabled")
	if supported {
		menuField(out, "Verified distro unit", plan.Unit)
		menuField(out, "Observed state", fmt.Sprintf("active=%s, enabled=%s", plan.Active, plan.Enabled))
		menuNotice(out, "WARNING", "STOP/DISABLE affects this EXISTING vendor service, not an STL-owned resource; its current VPNs may disconnect, and disabling persists after reboot.")
		menuField(out, "Operator choices", "Type STOP strongswan.service to approve this exact change, or RECHECK after manual repair. Enter cancels.")
	} else {
		if !allPackagesReady {
			menuField(out, "Package state", "Incomplete or recently changed: manual package/service reconciliation required before existing-service control")
		} else {
			menuField(out, "Service ownership", "Not an eligible verified distro unit; no automatic service changes are permitted")
			if err != nil {
				// All lower-level inspector errors are redacted, fixed
				// descriptions of missing proofs, never raw systemctl,
				// process environment, configuration or credential bytes.
				menuField(out, "Reason", safeMenuText(err.Error()))
			}
		}
		menuProse(out, "Inspect any active or enabled service and its dependencies. If it is your VPN, plan the maintenance window, back up its configuration, stop/disable it manually with an explicit administrator decision, and resolve all remaining config/package/unit conflicts. Then type RECHECK.")
	}
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Cannot establish a fresh service confirmation; no service changed.")
		return false
	}
	fmt.Fprint(out, "Service action (Enter cancels): ")
	answer, readErr := readMenuAnswer(reader)
	if readErr != nil || answer == "" {
		menuNotice(out, "INFO", "Existing service was not changed by STL.")
		return false
	}
	if answer == "RECHECK" {
		probeCtx, end := context.WithTimeout(context.Background(), 10*time.Second)
		err = ops.readiness(probeCtx)
		end()
		if err == nil {
			menuNotice(out, "OK", "IPsec host admission now passes; continuing the selected preparation.")
			return true
		}
		menuNotice(out, "WARNING", "Recheck still blocked: inspect the JSON report; do not blindly repeat PREPARE.")
		return false
	}
	if !supported || answer != "STOP "+plan.Unit || strings.ContainsAny(answer, "\r\n") {
		menuNotice(out, "INFO", "No eligible exact-unit STOP/DISABLE consent was provided. No service changed.")
		return false
	}
	// The call is not made on queued input: preview and dangerous STOP
	// acceptance are separate from the earlier package PREPARE token.
	actCtx, done := context.WithTimeout(context.Background(), 120*time.Second)
	err = ops.stop(actCtx, plan)
	done()
	if err != nil {
		menuNotice(out, "FAILED", "Service transition was refused or incomplete. A stop or disable effect may persist; inspect the service before further actions.")
		menuField(out, "Cause", safeMenuText(err.Error()))
		return false
	}
	menuNotice(out, "OK", "Verified distro service stopped and disabled after separate operator consent; no package/config/link was adopted.")
	probeCtx, end := context.WithTimeout(context.Background(), 12*time.Second)
	err = ops.readiness(probeCtx)
	end()
	if err != nil {
		menuNotice(out, "WARNING", "Other IPsec ownership/prerequisite checks still block the new private service. Manual reconciliation is required; no Link created.")
		return false
	}
	menuNotice(out, "OK", "Fresh private IPsec readiness passes; continuing selected preparation.")
	return true
}
