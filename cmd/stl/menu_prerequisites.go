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
	"github.com/ach1992/simple-tun-link/internal/maintenance"
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

// A failed capability query never justifies speculative modprobe. Examine
// EVERY module required by the selected backend independently, in dependency
// order. Only proven inactive-and-loadable modules enter one consented plan;
// unknown/absent artifacts block the entire plan rather than partial loading.
func menuModulePreparationReason(code string) bool {
	switch code {
	case "gre_probe_unconfirmed", "ipip_probe_unconfirmed", "base_link_probe_unconfirmed",
		"fou_probe_unconfirmed", "fou_module_present_probe_failed", "kernel_module_not_loaded":
		return true
	}
	return false
}

func plainModuleCandidates(selected tunnelOption, report linux.CapabilityReport, observe func(string) linux.KernelModuleState) ([]string, string) {
	required := plainRequiredModules(selected)
	capability := plainBackendCapability(selected.backend, selected.mode)
	if len(required) == 0 || report == nil || capability == "" || observe == nil {
		return nil, "This backend has no automatically preparable kernel module"
	}
	actual, known := report[capability]
	if !known {
		return nil, "Current host prerequisites are unknown; do not load modules on an uncertain observation"
	}
	if actual.Available {
		return nil, ""
	}
	// Only module-related observations are eligible for this specific
	// repair. A typed permission/ownership failure must not invite modprobe.
	if !menuModulePreparationReason(actual.ReasonCode) {
		return nil, "The selected failure is not proven repairable by module loading"
	}
	base := plainBackendCapability(selected.backend, domain.EncapNative)
	if _, known := report[base]; !known {
		return nil, "Base GRE/IPIP host inspection is unknown"
	}
	var missing []string
	for _, module := range required {
		switch observe(module) {
		case linux.KernelModuleLoaded, linux.KernelModuleBuiltin:
			// Nothing loadable is missing for this dependency. A failed
			// kernel query still blocks Create after the final re-observation.
		case linux.KernelModuleLoadableInactive:
			missing = append(missing, module)
		case linux.KernelModuleUnavailable:
			return nil, fmt.Sprintf("Module %s has no verified loadable artifact; no changes made", module)
		default:
			return nil, fmt.Sprintf("Module %s readiness is unknown; no changes made", module)
		}
	}
	if len(missing) == 0 {
		return nil, "Failed host inspection cannot safely be repaired by module loading"
	}
	return missing, ""
}

// Consent is consumed once for the whole selected plan. A successful
// package PREPARE can carry it forward without eating the next Link YES.
func menuConfirmSelectedModules(input io.Reader, reader *bufio.Reader, out io.Writer, approvedSelectedPlan bool) bool {
	if approvedSelectedPlan {
		menuNotice(out, "INFO", "The preceding PREPARE included these possible modules. Rechecking exact host conditions before loading.")
		return true
	}
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Cannot establish a fresh confirmation. Nothing changed.")
		return false
	}
	fmt.Fprintf(out, "Type %s to load only these modules (Enter cancels): ", menuActionToken(out, "PREPARE"))
	confirm, err := readMenuAnswer(reader)
	if err != nil || confirm != "PREPARE" {
		menuNotice(out, "INFO", "Preparation cancelled. No modules were loaded.")
		return false
	}
	return true
}

func menuCanPrepareKernel(input io.Reader, out io.Writer) bool {
	// Reuse the exact installed binary, root and fresh interactive TTY
	// authority gate already required for privileged menu maintenance.
	return menuCanUpdateNow(input, out)
}

// A dedicated, typed subprocess seam keeps testing and the real root TTY path
// separate. The literal module must be allowed by the selected Backend; the
// command is never constructed from terminal input or shell interpolation.
func loadSelectedKernelModules(ctx context.Context, load func(context.Context, string) error, selected tunnelOption, targets []string) error {
	if load == nil || len(targets) == 0 || len(targets) > 2 {
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
		if err := load(ctx, name); err != nil {
			// Prior successfully loaded modules are not unloaded: they may
			// have become shared with another process or tunnel meanwhile.
			return fmt.Errorf("kernel module %s load did not complete; prior loads must be inspected", name)
		}
	}
	return nil
}

// Typed production dependencies expose only narrow disposable test seams.
// The real menu always wires installed-root/TTY admission, locked mutation,
// fresh capability/module probes and the literal allowlisted loader.
type menuKernelPreparationOps struct {
	snapshot   func(*runtimeOptions) linux.CapabilityReport
	canPrepare func(io.Reader, io.Writer) bool
	observe    func(context.Context, string) linux.KernelModuleState
	acquire    func(context.Context) (func(), error)
	load       func(context.Context, string) error
}

func productionMenuKernelOps(options *runtimeOptions) menuKernelPreparationOps {
	probe := linux.KernelModuleProbe{Runner: createRunner(options), ModinfoBinary: "/sbin/modinfo"}
	return menuKernelPreparationOps{
		snapshot:   menuCapabilitySnapshot,
		canPrepare: menuCanPrepareKernel,
		observe:    probe.Observe,
		acquire: func(ctx context.Context) (func(), error) {
			release, err := maintenance.NewInstalledGate().Acquire(ctx)
			if err != nil {
				return nil, err
			}
			return func() { release() }, nil
		},
		load: linux.LoadTrustedKernelModule,
	}
}

// Return true only when the selected prerequisite now positively passed,
// not merely because modprobe exited successfully. Plain tunnel creation
// still uses the canonical Engine/transaction and fresh capability checks.
func menuPrepareSelectedModules(input io.Reader, reader *bufio.Reader, out io.Writer,
	options *runtimeOptions, selected tunnelOption, report linux.CapabilityReport, approval menuPackagePreparation,
) (bool, linux.CapabilityReport) {
	return menuPrepareSelectedModulesWithOps(input, reader, out, options, selected, report, approval, productionMenuKernelOps(options))
}

func menuPrepareSelectedModulesWithOps(input io.Reader, reader *bufio.Reader, out io.Writer,
	options *runtimeOptions, selected tunnelOption, report linux.CapabilityReport,
	approval menuPackagePreparation, ops menuKernelPreparationOps,
) (bool, linux.CapabilityReport) {
	if ops.snapshot == nil || ops.canPrepare == nil || ops.observe == nil || ops.acquire == nil || ops.load == nil {
		return false, report
	}
	approvedSelectedPlan := approval.approvedFor(selected)
	capability := plainBackendCapability(selected.backend, selected.mode)
	if approvedSelectedPlan {
		// A package transaction may have changed kernel/tool readiness.
		// Never rely on the capability snapshot taken before APT.
		report = ops.snapshot(options)
		if report == nil {
			menuNotice(out, "WARNING", "Post-package kernel readiness is unknown. No modules loaded or tunnel created.")
			return false, nil
		}
	}
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
	if current := ops.snapshot(options); current != nil {
		report = current
		if latest, ok := current[capability]; ok && latest.Available {
			return true, current
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	modules, reason := plainModuleCandidates(selected, report, func(name string) linux.KernelModuleState {
		return ops.observe(ctx, name)
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
	if !ops.canPrepare(input, out) {
		menuNotice(out, "INFO", "Preparation requires sudo stl menu on the installed binary and a real interactive terminal.")
		return false, report
	}
	if !menuConfirmSelectedModules(input, reader, out, approvedSelectedPlan) {
		return false, report
	}
	// Wait for the installed maintenance lease BEFORE the last preflight.
	// Acquisition re-attests /proc/self/exe after any installer/update wait,
	// so a stale, replaced executable cannot mutate the host. RestoreAll
	// already holds this same shared lease for committed Links.
	loadCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	release, lockErr := ops.acquire(loadCtx)
	if lockErr != nil {
		menuNotice(out, "WARNING", "Installed STL maintenance identity unavailable or busy; no module loaded.")
		menuField(out, "NEXT ACTION", "Check installed STL ownership and active maintenance/update operations; retry only after the competing operation has finished.")
		return false, ops.snapshot(options)
	}
	defer release()
	// Recheck the exact module absence/loadability under the installed lease.
	latest := ops.snapshot(options)
	verifyCtx, done := context.WithTimeout(loadCtx, 8*time.Second)
	defer done()
	modulesAgain, blocked := plainModuleCandidates(selected, latest, func(name string) linux.KernelModuleState {
		return ops.observe(verifyCtx, name)
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
	if err := loadSelectedKernelModules(loadCtx, ops.load, selected, modules); err != nil {
		menuNotice(out, "WARNING", "Kernel module load failed or is incomplete. Inspect host state before retrying.")
		menuField(out, "Cause", safeMenuText(err.Error()))
		menuField(out, "NEXT ACTION", "Run lsmod and modinfo for the selected module(s) and Create tunnel -> Availability details (read-only); prior loads may persist.")
		return false, ops.snapshot(options)
	}
	now := ops.snapshot(options)
	// Do not treat a successful modprobe exit or iproute2 query as enough:
	// verify every dependency is actually loaded after preparation.
	postCtx, postDone := context.WithTimeout(loadCtx, 8*time.Second)
	defer postDone()
	for _, module := range plainRequiredModules(selected) {
		observed := ops.observe(postCtx, module)
		if observed != linux.KernelModuleLoaded && observed != linux.KernelModuleBuiltin {
			menuNotice(out, "WARNING", "Module loading ended, but a selected dependency is not verified ready. No tunnel was created.")
			menuField(out, "Module", module)
			return false, now
		}
	}
	if checked, ok := now[capability]; !ok || !checked.Available {
		menuNotice(out, "WARNING", "Module load completed, but kernel capability is still unverified. No tunnel was created.")
		return false, now
	}
	menuNotice(out, "OK", "Selected kernel prerequisite now passes. Continuing to tunnel setup.")
	return true, now
}
