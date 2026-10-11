package diagnostics

import (
	"bytes"
	"context"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// This is deliberately a *time-local, untrusted systemd-manager observation*.
// It cannot certify PID 1, executable provenance, effective ExecStart or
// Environment, secure strongSwan logging or exclusive VICI writer access.
// It never starts/reloads/enables a unit or authorizes IPsec activation.
const (
	nativeSystemdUnitName = "simple-tun-link-ipsec.service"
	maxSystemdShowBytes   = 16 * 1024
)

var nativeSystemdShowArgs = []string{
	"--system", "--no-pager", "show", "--all",
	"--property=Id,Names,Following,LoadState,FragmentPath,SourcePath,DropInPaths,NeedDaemonReload,Transient,UnitFileState",
	"--", nativeSystemdUnitName,
}

// inspectNativeSystemdLoadedUnit is read-only. The fixed absolute executable,
// system bus and unit name do not depend on caller-supplied arguments or PATH.
// No systemctl output, error, or raw property is included in public results.
func inspectNativeSystemdLoadedUnit(ctx context.Context, runner linux.Runner) IPsecHostCheck {
	check := IPsecHostCheck{
		Name: "native_systemd_loaded_unit", Status: "unknown",
		ReasonCode: "native_systemd_unit_unverified",
		Summary:    "The systemd manager's loaded IPsec unit identity could not be verified.",
		NextStep:   "Check the system manager and loaded unit identity read-only; do not start, reload or adopt any strongSwan service.",
	}
	if ctx == nil || runner == nil || ctx.Err() != nil {
		return check
	}
	result, err := runner.Run(ctx, "/usr/bin/systemctl", nativeSystemdShowArgs...)
	if err != nil {
		return check
	}
	values, ok := parseNativeSystemdShow(result.Stdout)
	if !ok {
		return check
	}
	// PID 1 may change these properties immediately after the read. Even a
	// fully matching snapshot is NOT a resource reservation or origin proof.
	// Non-canonical manager identities and any override remain blocked, not
	// silently interpreted as a successful STL-owned service.
	if values["Id"] != nativeSystemdUnitName ||
		values["Names"] != nativeSystemdUnitName ||
		values["Following"] != "" ||
		values["SourcePath"] != "" ||
		values["DropInPaths"] != "" ||
		values["Transient"] != "no" ||
		values["NeedDaemonReload"] != "no" {
		return nativeSystemdLoadedConflict()
	}
	switch values["LoadState"] {
	case "not-found":
		if values["FragmentPath"] != "" || values["UnitFileState"] != "" {
			return nativeSystemdLoadedConflict()
		}
		check.Status = "blocked"
		check.ReasonCode = "native_systemd_unit_not_loaded"
		check.Summary = "systemd has not loaded the proposed STL-only IPsec unit."
		check.NextStep = "Do not install or start the source-only unit on a live host; qualify protected publication and systemd admission in a disposable environment."
		return check
	case "loaded":
		if values["FragmentPath"] != ipsec.NativeExclusiveServiceUnitPath ||
			values["UnitFileState"] != "static" {
			return nativeSystemdLoadedConflict()
		}
		check.Status = "observed"
		check.ReasonCode = "native_systemd_unit_loaded_snapshot"
		check.Summary = "systemd reports the canonical IPsec unit fragment loaded without reported aliases, drop-ins, generators or stale reload; effective runtime and ownership are not verified."
		check.NextStep = "Independently attest exact service properties, package and process origin, STRONGSWAN_CONF, CFG logging, VICI writers and host resources before any activation."
		return check
	default:
		return nativeSystemdLoadedConflict()
	}
}

func nativeSystemdLoadedConflict() IPsecHostCheck {
	return IPsecHostCheck{
		Name: "native_systemd_loaded_unit", Status: "blocked",
		ReasonCode: "native_systemd_unit_conflict",
		Summary:    "The loaded IPsec unit identity is masked, overridden, changed or incompatible with the reviewed STL-only profile.",
		NextStep:   "Inspect systemd unit aliases, drop-ins, generators and other owners manually; never replace, start or reload a foreign service.",
	}
}

// parseNativeSystemdShow accepts ONLY a complete, bounded ASCII property
// snapshot from systemctl show --all. Incomplete, duplicated, injected or
// unfamiliar output is unknown, never proof of no foreign management state.
func parseNativeSystemdShow(raw []byte) (map[string]string, bool) {
	const fields = "Id,Names,Following,LoadState,FragmentPath,SourcePath,DropInPaths,NeedDaemonReload,Transient,UnitFileState"
	if len(raw) == 0 || len(raw) > maxSystemdShowBytes || raw[len(raw)-1] != '\n' {
		return nil, false
	}
	for _, b := range raw {
		if b != '\n' && (b < 0x20 || b > 0x7e) {
			return nil, false
		}
	}
	allowed := make(map[string]struct{}, 10)
	for _, key := range strings.Split(fields, ",") {
		allowed[key] = struct{}{}
	}
	values := make(map[string]string, len(allowed))
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n")) {
		key, value, ok := bytes.Cut(line, []byte("="))
		if !ok {
			return nil, false
		}
		name := string(key)
		if _, found := allowed[name]; !found {
			return nil, false
		}
		if _, duplicate := values[name]; duplicate {
			return nil, false
		}
		values[name] = string(value)
	}
	return values, len(values) == len(allowed)
}
