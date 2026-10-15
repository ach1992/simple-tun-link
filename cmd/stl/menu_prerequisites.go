package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// The menu may only prepare explicitly selected, already-published GRE/IPIP
// kernel drivers. It must never use arbitrary user-provided module names.
// Loading a module is a host-wide side effect, but does not install packages,
// create a tunnel, change State, edit systemd, or establish host support.
func plainRequiredModules(selected tunnelOption) []string {
	switch selected.backend {
	case domain.BackendGRE:
		switch selected.mode {
		case domain.EncapNative:
			return []string{"ip_gre"}
		case domain.EncapFOU, domain.EncapGUE:
			return []string{"ip_gre", "fou"}
		}
	case domain.BackendIPIP:
		switch selected.mode {
		case domain.EncapNative:
			return []string{"ipip"}
		case domain.EncapFOU, domain.EncapGUE:
			return []string{"ipip", "fou"}
		}
	}
	return nil
}

// A single failed "ip fou show" is not an instruction to run modprobe.
// Require the backend-specific failed observation, and independent proof that
// every targeted module is absent from /sys/module but loadable on disk.
func plainModuleCandidates(selected tunnelOption, report linux.CapabilityReport, loadable func(string) bool) ([]string, string) {
	required := plainRequiredModules(selected)
	capability := plainBackendCapability(selected.backend, selected.mode)
	if len(required) == 0 || report == nil || capability == "" {
		return nil, "This backend has no automatically preparable kernel module"
	}
	actual, known := report[capability]
	if !known {
		return nil, "Current host prerequisites are unknown; do not load modules on an uncertain observation"
	}
	if actual.Available {
		return nil, ""
	}
	base := plainBackendCapability(selected.backend, domain.EncapNative)
	baseReport, ok := report[base]
	if !ok {
		return nil, "Base GRE/IPIP host inspection is unknown"
	}
	var missing []string
	if !baseReport.Available {
		module := required[0]
		if !loadable(module) {
			return nil, "Base GRE/IPIP module is not proven loadable and inactive; no changes made"
		}
		missing = append(missing, module)
	}
	if len(required) == 2 {
		// The base module's failure can mask the shared FOU failure on
		// this backend. Use a DIFFERENT backend's positive native query
		// and its typed FOU probe to prepare both modules together only
		// when independently observed, never from a guessed missing driver.
		fouUnconfirmed := false
		for _, cap := range []linux.Capability{linux.CapabilityGREFOU, linux.CapabilityIPIPFOU} {
			observation, ok := report[cap]
			if ok && (observation.ReasonCode == "fou_module_present_probe_failed" ||
				observation.ReasonCode == "fou_probe_unconfirmed") {
				fouUnconfirmed = true
			}
		}
		if fouUnconfirmed {
			if !loadable("fou") {
				return nil, "FOU module is not proven loadable and inactive; no changes made"
			}
			missing = append(missing, "fou")
		} else if baseReport.Available {
			return nil, "The cause of the selected tunnel precheck is unknown; no modules were loaded"
		}
	}
	if len(missing) == 0 {
		return nil, "Failed host inspection cannot safely be repaired by module loading"
	}
	return missing, ""
}

func menuCanPrepareKernel(input io.Reader, out io.Writer) bool {
	// Reuse the exact installed binary, root and fresh interactive TTY
	// authority gate already required for privileged menu maintenance.
	return menuCanUpdateNow(input, out)
}

// A dedicated, typed subprocess seam keeps testing and the real root TTY path
// separate. The literal module must be allowed by the selected Backend; the
// command is never constructed from terminal input or shell interpolation.
func loadSelectedKernelModules(ctx context.Context, runner linux.Runner, selected tunnelOption, targets []string) error {
	if runner == nil || len(targets) == 0 || len(targets) > 2 {
		return errors.New("no safe kernel module preparation targets")
	}
	allowed := plainRequiredModules(selected)
	if len(allowed) == 0 {
		return errors.New("selected tunnel is not eligible for kernel module preparation")
	}
	seen := make(map[string]bool)
	index := -1
	for _, name := range targets {
		found := false
		for i, expected := range allowed {
			if name == expected && i > index {
				index, found = i, true
				break
			}
		}
		if !found || seen[name] {
			return errors.New("module outside selected tunnel's exact allowlist")
		}
		seen[name] = true
	}
	for _, name := range targets {
		if _, err := runner.Run(ctx, "/sbin/modprobe", name); err != nil {
			// Prior successfully loaded modules are not unloaded: they may
			// have become shared with another process or tunnel meanwhile.
			return fmt.Errorf("kernel module %s load did not complete; prior loads must be inspected", name)
		}
	}
	return nil
}

// Return true only when the selected prerequisite now positively passed,
// not merely because modprobe exited successfully. Plain tunnel creation
// still uses the canonical Engine/transaction and fresh capability checks.
func menuPrepareSelectedModules(input io.Reader, reader *bufio.Reader, out io.Writer,
	options *runtimeOptions, selected tunnelOption, report linux.CapabilityReport,
) (bool, linux.CapabilityReport) {
	capability := plainBackendCapability(selected.backend, selected.mode)
	if capability == "" || len(plainRequiredModules(selected)) == 0 {
		return true, report
	}
	status, known := report[capability]
	if !known || report == nil {
		return true, report // normal Engine must fail closed on unknown
	}
	if status.Available {
		return true, report
	}
	// Menu badges are time-local observations. A different operator might
	// have loaded the module while this menu was being read.
	if current := menuCapabilitySnapshot(options); current != nil {
		report = current
		if latest, ok := current[capability]; ok && latest.Available {
			return true, current
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	runner := createRunner(options)
	probe := linux.KernelModuleProbe{Runner: runner, ModinfoBinary: "/sbin/modinfo"}
	modules, reason := plainModuleCandidates(selected, report, func(name string) bool {
		return probe.AvailableButNotLoaded(ctx, name)
	})
	if len(modules) == 0 {
		menuNotice(out, "WARNING", "Selected kernel precheck did not pass; automatic preparation is unavailable.")
		menuField(out, "Reason", reason)
		menuField(out, "Next", "Create tunnel -> Availability details (read-only)")
		return false, report
	}
	menuScreen(out, "Prepare selected tunnel / preview")
	menuField(out, "Type", fmt.Sprintf("%s / %s", selected.backend, selected.mode))
	menuField(out, "Kernel module(s)", strings.Join(modules, ", "))
	menuNotice(out, "WARNING", "This loads kernel modules on THIS host only; modules may stay loaded until reboot.")
	menuProse(out, "No Link, route, firewall rule, package, existing service or saved State is changed by this operation.")
	menuProse(out, "The OTHER server must be prepared independently. Kernel readiness is rechecked before Create.")
	if !menuCanPrepareKernel(input, out) {
		menuNotice(out, "INFO", "Preparation requires sudo stl menu on the installed binary and a real interactive terminal.")
		return false, report
	}
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Cannot establish a fresh confirmation. Nothing changed.")
		return false, report
	}
	fmt.Fprintf(out, "Type %s to load only these modules (Enter cancels): ", menuPaint(out, menuYellow, "PREPARE"))
	confirm, err := readMenuAnswer(reader)
	if err != nil || confirm != "PREPARE" {
		menuNotice(out, "INFO", "Preparation cancelled. No modules were loaded.")
		return false, report
	}
	// Recheck the exact module absence/loadability after the human confirms
	// and before doing any host mutation; fail closed on concurrent drift.
	latest := menuCapabilitySnapshot(options)
	verifyCtx, done := context.WithTimeout(context.Background(), 8*time.Second)
	defer done()
	modulesAgain, blocked := plainModuleCandidates(selected, latest, func(name string) bool {
		return probe.AvailableButNotLoaded(verifyCtx, name)
	})
	if len(modulesAgain) != len(modules) || blocked != "" {
		menuNotice(out, "WARNING", "Host preconditions changed after confirmation. No modules loaded.")
		return false, latest
	}
	for i := range modules {
		if modules[i] != modulesAgain[i] {
			menuNotice(out, "WARNING", "Kernel module prerequisites changed. No modules loaded.")
			return false, latest
		}
	}
	loadCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	if err := loadSelectedKernelModules(loadCtx, linux.ExecRunner{}, selected, modules); err != nil {
		menuNotice(out, "WARNING", "Kernel module load failed or is incomplete. Inspect host state before retrying.")
		menuField(out, "Cause", safeMenuText(err.Error()))
		return false, menuCapabilitySnapshot(options)
	}
	now := menuCapabilitySnapshot(options)
	if checked, ok := now[capability]; !ok || !checked.Available {
		menuNotice(out, "WARNING", "Module load completed, but kernel capability is still unverified. No tunnel was created.")
		return false, now
	}
	menuNotice(out, "OK", "Selected kernel prerequisite now passes. Continuing to tunnel setup.")
	return true, now
}
