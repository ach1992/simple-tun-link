package ipsec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/maintenance"
)

// VendorServiceStopPlan is a *time-local* read-only preview, not permission
// to adopt a service. Only the official charon-systemd strongswan.service
// is eligible for an operator's separate, explicit STOP/DISABLE consent.
// Other services, aliases, custom units, drop-ins, and unknown states require
// manual ownership reconciliation and remain outside automatic mutation.
type VendorServiceStopPlan struct {
	Unit    string
	Active  string
	Enabled string
}

const vendorServiceName = "strongswan.service"

// nativeVendorUnitMetadataStrict rejects alias/drop-in/overridden fragments.
// The normal Go native-exclusive runtime never uses the vendor unit; this
// routine authorizes stopping only the proven distro-owned service, not using
// any of its config, process or credentials.
func nativeVendorUnitMetadataStrict(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 2048 || raw[len(raw)-1] != '\n' {
		return "", errors.New("vendor unit metadata missing or oversized")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		k, v, found := strings.Cut(line, "=")
		_, repeated := values[k]
		if !found || repeated || k == "" {
			return "", errors.New("vendor metadata invalid or repeated")
		}
		switch k {
		case "FragmentPath", "SourcePath", "DropInPaths", "NeedDaemonReload", "LoadState":
		default:
			return "", errors.New("unexpected vendor unit metadata")
		}
		values[k] = v
	}
	if len(values) != 5 || values["SourcePath"] != "" ||
		values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" ||
		values["LoadState"] != "loaded" {
		return "", errors.New("custom or unverified vendor unit identity")
	}
	if values["FragmentPath"] != "/usr/lib/systemd/system/strongswan.service" &&
		values["FragmentPath"] != "/lib/systemd/system/strongswan.service" {
		return "", errors.New("vendor systemd fragment outside supported distro path")
	}
	return values["FragmentPath"], nil
}

func nativeVendorDistroOwnership(ctx context.Context, fragment string) error {
	resolved, err := filepath.EvalSymlinks(fragment)
	if err != nil || resolved != "/usr/lib/systemd/system/strongswan.service" {
		return errors.New("vendor unit cannot be resolved to its standard distro path")
	}
	for _, dir := range []string{"/", "/usr", "/usr/lib", "/usr/lib/systemd", "/usr/lib/systemd/system"} {
		info, e := os.Lstat(dir)
		if e != nil || !rootControlledExecutableMetadata(info, true) {
			return errors.New("vendor unit directory ancestry not root-controlled")
		}
	}
	info, err := os.Lstat(resolved)
	if err != nil || !rootControlledExecutableMetadata(info, false) {
		return errors.New("vendor unit is not a root-owned regular distro file")
	}
	// dpkg ownership of the exact file is required. This is an existing
	// distro package identity, NOT ownership by STL; never replace the file.
	for _, path := range []string{fragment, "/lib/systemd/system/strongswan.service"} {
		ctxCheck, cancel := context.WithTimeout(ctx, 4*time.Second)
		cmd := exec.CommandContext(ctxCheck, "/usr/bin/dpkg-query", "-S", "--", path)
		cmd.Env = nativeSystemdFixedEnvironment()
		output, e := cmd.Output()
		cancel()
		if e == nil && len(output) < 512 && string(output) == "charon-systemd: "+path+"\n" {
			return nil
		}
	}
	return errors.New("vendor systemd fragment is not uniquely owned by charon-systemd")
}

// InspectVendorServiceStopPlan returns a candidate only if a recognized,
// independently vetted official distro service is currently active or
// enabled. It performs no writes. No automatic action is allowed for an
// alternate unit, a missing package, ambiguous status or foreign override.
func InspectVendorServiceStopPlan(ctx context.Context) (VendorServiceStopPlan, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return VendorServiceStopPlan{}, errors.New("root systemd inspection required")
	}
	active, err := readNativeVendorUnitState(ctx, "is-active", vendorServiceName)
	if err != nil || (active != "active" && active != "inactive") {
		return VendorServiceStopPlan{}, errors.New("vendor service activity unknown or absent")
	}
	enabled, err := readNativeVendorUnitState(ctx, "is-enabled", vendorServiceName)
	if err != nil || (enabled != "enabled" && enabled != "disabled") {
		return VendorServiceStopPlan{}, errors.New("vendor service enablement unknown or not eligible")
	}
	if active == "inactive" && enabled == "disabled" {
		return VendorServiceStopPlan{}, errors.New("vendor service is already stopped and disabled")
	}
	// An alternate service can remain dangerous even if the conventional
	// strongswan.service appears package-owned. Refuse mutation if ANY
	// nonselected vendor unit is active or boot-enabled/ambiguous.
	for _, other := range []string{"strongswan-starter.service", "charon-systemd.service", "ipsec.service"} {
		a, err := readNativeVendorUnitState(ctx, "is-active", other)
		if err != nil || (a != "inactive" && a != "unknown") {
			return VendorServiceStopPlan{}, errors.New("another IPsec service is present or unverified")
		}
		e, err := readNativeVendorUnitState(ctx, "is-enabled", other)
		if err != nil || (e != "disabled" && e != "masked" && e != "not-found") {
			return VendorServiceStopPlan{}, errors.New("another IPsec service is enabled or unverified")
		}
	}
	runner := nativeSystemdRunner{Timeout: 4 * time.Second}
	result, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 2048, Stderr: 256},
		nativeSystemctlBinary, "--system", "--no-pager", "show",
		vendorServiceName, "-p", "FragmentPath", "-p", "SourcePath",
		"-p", "DropInPaths", "-p", "NeedDaemonReload", "-p", "LoadState")
	if err != nil || len(result.Stderr) != 0 {
		return VendorServiceStopPlan{}, errors.New("vendor effective unit metadata unavailable")
	}
	fragment, err := nativeVendorUnitMetadataStrict(result.Stdout)
	if err != nil {
		return VendorServiceStopPlan{}, err
	}
	if err := nativeVendorDistroOwnership(ctx, fragment); err != nil {
		return VendorServiceStopPlan{}, err
	}
	return VendorServiceStopPlan{Unit: vendorServiceName, Active: active, Enabled: enabled}, nil
}

// StopDisableVerifiedVendorService has no implicit authority from PREPARE.
// The human menu must collect a fresh, separately typed exact-unit decision.
// After acquiring exclusive installed-STL maintenance ownership, the plan is
// re-attested; only this allowlisted distro unit is touched. Stopping it can
// immediately interrupt external VPN traffic, and disabling it persists
// across reboot. On partial failure, do not blindly restore foreign state.
func StopDisableVerifiedVendorService(ctx context.Context, approved VendorServiceStopPlan) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 ||
		approved.Unit != vendorServiceName ||
		(approved.Active != "active" && approved.Active != "inactive") ||
		(approved.Enabled != "enabled" && approved.Enabled != "disabled") {
		return errors.New("no valid explicitly selected vendor service")
	}
	release, err := maintenance.NewInstalledGate().AcquireExclusive(ctx)
	if err != nil {
		return errors.New("exclusive STL installed maintenance lease unavailable")
	}
	defer release()
	current, err := InspectVendorServiceStopPlan(ctx)
	if err != nil || current != approved {
		return errors.New("vendor identity or state changed since operator consent; no service modified")
	}
	runner := nativeSystemdRunner{Timeout: 20 * time.Second}
	transition := func(action string) error {
		result, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 1024, Stderr: 1024},
			nativeSystemctlBinary, "--system", "--no-pager", action, vendorServiceName)
		clear(result.Stdout)
		clear(result.Stderr)
		return err
	}
	if approved.Active == "active" {
		if err := transition("stop"); err != nil {
			return errors.New("verified vendor service stop failed or uncertain; inspect effects before retry")
		}
	}
	if approved.Enabled == "enabled" {
		if err := transition("disable"); err != nil {
			return errors.New("verified vendor service disable failed or uncertain; stop may have succeeded")
		}
	}
	active, aerr := readNativeVendorUnitState(ctx, "is-active", vendorServiceName)
	enabled, eerr := readNativeVendorUnitState(ctx, "is-enabled", vendorServiceName)
	if aerr != nil || eerr != nil || active != "inactive" || enabled != "disabled" {
		return fmt.Errorf("vendor stop/disable postcheck unverified; do not start STL IPsec until reconciled")
	}
	return nil
}
