package diagnostics

import (
	"bytes"
	"context"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Only the systemd in-memory unit INVENTORY is safe to query without loading
// an absent unit. systemctl show <UNIT> can cause systemd to load that unit's
// metadata, so it must NEVER be used by this observation. In-memory identity
// is not the effective unit configuration or an admission/ownership grant.
const (
	nativeSystemdUnitName = "simple-tun-link-ipsec.service"
	maxSystemdListBytes   = 16 * 1024
	maxSystemdStderrBytes = 1024
)

// A glob forces list-units' in-memory enumeration (not a unit-object lookup).
// '?' matches only the final 'e'; unexpected rows are unknown, not adoption.
var nativeSystemdListArgs = []string{
	"--system", "--no-pager", "--no-legend", "--plain", "--full",
	"--all", "--type=service", "list-units", "simple-tun-link-ipsec.servic?",
}

type nativeSystemdInventoryState int

const (
	systemdInventoryUnknown nativeSystemdInventoryState = iota
	systemdInventoryNotListed
	systemdInventoryNotFound
	systemdInventoryListed
	systemdInventoryConflict
)

// inspectNativeSystemdLoadedUnit never invokes a unit-object lookup, let
// alone start/stop/reload or daemon operations. If the named unit is loaded,
// the in-memory list alone does NOT expose FragmentPath, DropInPaths, Names,
// generators or NeedDaemonReload: return UNKNOWN until those effective values
// can be attested without causing a load or a race-induced reload. Existing
// protected disk snapshots remain separate and cannot fill this proof gap.
func inspectNativeSystemdLoadedUnit(ctx context.Context, runner linux.Runner) IPsecHostCheck {
	check := IPsecHostCheck{
		Name:       "native_systemd_loaded_unit",
		Status:     "unknown",
		ReasonCode: "native_systemd_unit_unverified",
		Summary:    "The systemd manager's existing loaded-unit inventory could not be verified.",
		NextStep:   "Inspect the existing unit and manager using an independently verified non-loading method; do not start, reload or adopt a strongSwan service.",
	}
	if ctx == nil || runner == nil || ctx.Err() != nil {
		return check
	}
	bounded, ok := runner.(linux.BoundedRunner)
	if !ok {
		// Never silently fall back to Runner.Run, which buffers unbounded
		// command output before the diagnostic parser can inspect it.
		return check
	}
	result, err := bounded.RunBounded(ctx, linux.CaptureLimits{
		Stdout: maxSystemdListBytes, Stderr: maxSystemdStderrBytes,
	}, "/usr/bin/systemctl", nativeSystemdListArgs...)
	if err != nil || len(result.Stderr) != 0 {
		return check
	}
	state, ok := parseNativeSystemdList(result.Stdout)
	if !ok {
		return check
	}
	switch state {
	case systemdInventoryNotListed:
		check.Status = "blocked"
		check.ReasonCode = "native_systemd_unit_not_loaded"
		check.Summary = "The proposed STL IPsec service is not listed under its primary name in systemd's current in-memory unit inventory; on-disk units and aliases remain unverified."
		check.NextStep = "Do not install or start the source-only unit on a live host; validate unit identity, aliases, packages and systemd admission in an authorized disposable environment."
	case systemdInventoryNotFound:
		// A systemd entry with LOAD=not-found is not proof of a foreign
		// unit: it may be the residue of an earlier harmless lookup.
		// This is still BLOCKED, not permission to publish or start a
		// service. On-disk aliases and effective manager state remain
		// separately subject to the existing fail-closed provision gate.
		check.Status = "blocked"
		check.ReasonCode = "native_systemd_unit_not_loaded"
		check.Summary = "systemd lists an in-memory placeholder for the STL IPsec service with LOAD=not-found; the service is not verified or ready."
		check.NextStep = "Continue through the verified STL-owned provisioning workflow; absence of a trusted service and conflicting aliases must be checked before any mutation."
	case systemdInventoryConflict:
		return nativeSystemdLoadedConflict()
	case systemdInventoryListed:
		check.Summary = "systemd lists the proposed unit in memory, but its effective fragment, aliases, drop-ins, generators and reload status cannot be safely attested by this non-loading probe."
		check.NextStep = "Keep IPsec blocked; qualify a non-loading effective-unit attestation and independent package, process, environment, logger and VICI ownership."
	}
	return check
}

func nativeSystemdLoadedConflict() IPsecHostCheck {
	return IPsecHostCheck{
		Name: "native_systemd_loaded_unit", Status: "blocked",
		ReasonCode: "native_systemd_unit_conflict",
		Summary:    "The existing in-memory IPsec unit entry has an incompatible or failed load state.",
		NextStep:   "Inspect systemd unit identity and foreign owners manually; never replace, start or reload an unowned service.",
	}
}

// parseNativeSystemdList accepts a complete, one-row in-memory list only.
// Empty stdout from a SUCCESSFUL bounded list-units request means that no
// matching primary unit was listed *at that instant*, NOT that no file,
// alias, generator, other daemon or future writer exists. Untrusted text,
// Unicode terminal markers, extra units, truncated rows and future output
// changes always degrade to UNKNOWN instead of a false clean inventory.
func parseNativeSystemdList(raw []byte) (nativeSystemdInventoryState, bool) {
	if len(raw) > maxSystemdListBytes {
		return systemdInventoryUnknown, false
	}
	if len(raw) == 0 {
		return systemdInventoryNotListed, true
	}
	if raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		return systemdInventoryUnknown, false
	}
	for _, b := range raw {
		if b != '\n' && (b < 0x20 || b > 0x7e) {
			return systemdInventoryUnknown, false
		}
	}
	fields := strings.Fields(string(raw[:len(raw)-1]))
	if len(fields) < 5 || fields[0] != nativeSystemdUnitName {
		return systemdInventoryUnknown, false
	}
	// The text columns are UNIT LOAD ACTIVE SUB DESCRIPTION; descriptions
	// may have spaces but cannot qualify ownership. LOAD's unknown future
	// variants do not prove that an expected unit was loaded.
	switch fields[1] {
	case "loaded":
		return systemdInventoryListed, true
	case "not-found":
		if fields[2] == "inactive" && fields[3] == "dead" {
			return systemdInventoryNotFound, true
		}
		return systemdInventoryUnknown, false
	case "masked", "bad-setting", "error":
		return systemdInventoryConflict, true
	default:
		return systemdInventoryUnknown, false
	}
}
