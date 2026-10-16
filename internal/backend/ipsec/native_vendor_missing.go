package ipsec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// systemctl is-active/is-enabled return version-dependent exit codes for a
// genuinely absent service. A failed command is NOT proof of absence.
// Permit a secondary observation only when the effective manager explicitly
// reports a missing, inactive, never-loaded unit and every canonical disk
// identity is also absent. A loaded/disabled vendor unit is handled by the
// normal is-active/is-enabled contract, not this fallback.
func nativeMissingVendorUnitProperties(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 1024 || raw[len(raw)-1] != '\n' {
		return false
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
		switch key {
		case "LoadState", "ActiveState", "UnitFileState", "FragmentPath", "SourcePath", "DropInPaths", "NeedDaemonReload":
		default:
			return false
		}
		if _, duplicate := fields[key]; duplicate {
			return false
		}
		fields[key] = value
	}
	return len(fields) == 7 &&
		fields["LoadState"] == "not-found" &&
		fields["ActiveState"] == "inactive" &&
		fields["UnitFileState"] == "" &&
		fields["FragmentPath"] == "" &&
		fields["SourcePath"] == "" &&
		fields["DropInPaths"] == "" &&
		fields["NeedDaemonReload"] == "no"
}

func nativeKnownVendorUnit(name string) bool {
	switch name {
	case "strongswan.service", "strongswan-starter.service", "charon-systemd.service", "ipsec.service":
		return true
	}
	return false
}

func nativeMissingVendorUnitFiles(root, name string) bool {
	if !nativeKnownVendorUnit(name) {
		return false
	}
	// Inspect every systemd UnitPath already approved for the vendor STOP
	// safety boundary, including attached/transient/unit-control paths.
	// A search-path shadow, stale boot edge or dormant prefix drop-in is
	// not independent proof that the unit is absent.
	for _, dir := range vendorUnitSearchPaths {
		base := filepath.Join(root, strings.TrimPrefix(dir, "/"))
		if _, err := os.Lstat(filepath.Join(base, name)); !errors.Is(err, os.ErrNotExist) {
			return false // includes dangling symlinks and foreign files
		}
		for _, suffix := range []string{"*.wants", "*.requires"} {
			edges, err := filepath.Glob(filepath.Join(base, suffix))
			if err != nil || len(edges) > 128 {
				return false
			}
			for _, edge := range edges {
				if _, err := os.Lstat(filepath.Join(edge, name)); !errors.Is(err, os.ErrNotExist) {
					return false
				}
			}
		}
		for _, dropin := range []string{name + ".d", "service.d"} {
			if _, err := os.Lstat(filepath.Join(base, dropin)); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
	}
	if name == "ipsec.service" || name == "strongswan.service" || name == "strongswan-starter.service" {
		script := strings.TrimSuffix(name, ".service")
		if _, err := os.Lstat(filepath.Join(root, "etc/init.d", script)); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func nativeVendorUnitVerifiedMissing(ctx context.Context, name string) bool {
	if ctx == nil || ctx.Err() != nil || !nativeKnownVendorUnit(name) {
		return false
	}
	bound, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	out, diag := &privateCapture{max: 1024}, &privateCapture{max: 256}
	cmd := exec.CommandContext(bound, nativeSystemctlBinary,
		"--system", "--no-pager", "show", name,
		"-p", "LoadState", "-p", "ActiveState", "-p", "UnitFileState",
		"-p", "FragmentPath", "-p", "SourcePath", "-p", "DropInPaths", "-p", "NeedDaemonReload")
	cmd.Env = nativeSystemdFixedEnvironment()
	cmd.Stdout, cmd.Stderr = out, diag
	if err := cmd.Run(); err != nil || bound.Err() != nil || out.overflow || diag.overflow ||
		diag.output.Len() != 0 || !nativeMissingVendorUnitProperties(out.output.Bytes()) {
		return false
	}
	// The manager may search alternate attached or transient directories.
	// Accept absence only if the effective UnitPath set itself is verified.
	if err := vendorStopUnitPaths(ctx); err != nil {
		return false
	}
	return nativeMissingVendorUnitFiles("/", name)
}

// Only nonpositive, otherwise unverified status outputs can enter the
// alternate absence proof. Never reinterpret an active/enabled/failed state,
// even when a later observation claims vacancy during a possible race.
func nativeVendorMissingStatusFallbackEligible(raw []byte) bool {
	switch string(raw) {
	case "", "inactive\n", "unknown\n", "not-found\n":
		return true
	default:
		return false
	}
}
