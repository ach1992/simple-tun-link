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

// These are the exact vendor unit identities, plus the only supported
// distribution alias for strongswan.service. A dormant alias may be loaded
// after a later daemon-reload even when the canonical name is missing now.
func nativeMissingVendorIdentities(name string) []string {
	if name == "strongswan.service" {
		return []string{name, "strongswan-swanctl.service"}
	}
	return []string{name}
}

// systemd.unit(5) loads the exact unit's drop-ins, the type-wide service.d,
// and progressively shorter dash-prefix drop-ins. For example
// charon-systemd.service inherits charon-.service.d as well as
// charon-systemd.service.d. All relevant names are literal allowlisted.
func nativeMissingVendorDropIns(name string) []string {
	dropins := []string{"service.d", name + ".d"}
	stem := strings.TrimSuffix(name, ".service")
	for i := strings.LastIndexByte(stem, '-'); i >= 0; i = strings.LastIndexByte(stem[:i], '-') {
		dropins = append(dropins, stem[:i+1]+".service.d")
	}
	return dropins
}

// Detect arbitrary dormant symlink aliases that target a known vendor unit,
// including when the alias is itself inside a boot-edge directory. The
// symlink's bytes cannot be trusted; even a dangling link is a conflict.
// Other packages' unrelated service aliases do not block STL.
func nativeMissingVendorAliasesAbsent(dir string, identities map[string]bool) bool {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || len(entries) > 4096 {
		return false
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".service") {
			continue
		}
		mode := entry.Type()
		if mode == 0 {
			// Handle filesystems reporting DT_UNKNOWN with an exact Lstat.
			info, e := os.Lstat(filepath.Join(dir, entry.Name()))
			if e != nil {
				return false
			}
			mode = info.Mode()
		}
		if mode&os.ModeSymlink == 0 {
			continue
		}
		destination, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			return false
		}
		if identities[filepath.Base(destination)] {
			return false
		}
	}
	return true
}

// Systemd's installed dependency edges live in three directory families:
// WantedBy=, RequiredBy= and (since v249) UpheldBy=. Share this enumeration
// between missing-vendor admission and separately consented vendor STOP,
// so a new dependency type cannot be covered by only one safety gate.
// An uninspectable or symlinked directory is not proof of a safe edge.
func vendorSystemdBootEdgeDirs(base string) ([]string, error) {
	var result []string
	for _, suffix := range []string{"*.wants", "*.requires", "*.upholds"} {
		dirs, err := filepath.Glob(filepath.Join(base, suffix))
		if err != nil || len(dirs) > 128 {
			return nil, errors.New("systemd dependency inventory unavailable")
		}
		for _, edge := range dirs {
			info, err := os.Lstat(edge)
			if err != nil || !info.IsDir() {
				return nil, errors.New("systemd dependency directory identity unverified")
			}
			result = append(result, edge)
		}
	}
	return result, nil
}

func nativeMissingVendorUnitFiles(root, name string) bool {
	if !nativeKnownVendorUnit(name) {
		return false
	}
	ids := nativeMissingVendorIdentities(name)
	identity := make(map[string]bool, len(ids))
	dropins := make(map[string]bool)
	for _, n := range ids {
		identity[n] = true
		for _, dropin := range nativeMissingVendorDropIns(n) {
			dropins[dropin] = true
		}
	}

	// Require vacancy in the complete trusted manager UnitPath inventory,
	// including future-reload boot edges, prefix drop-ins and known/dynamic
	// symlink aliases. Missing entries are proved with Lstat (not Stat).
	for _, dir := range vendorUnitSearchPaths {
		base := filepath.Join(root, strings.TrimPrefix(dir, "/"))
		for id := range identity {
			if _, err := os.Lstat(filepath.Join(base, id)); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
		for dirName := range dropins {
			if _, err := os.Lstat(filepath.Join(base, dirName)); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
		if !nativeMissingVendorAliasesAbsent(base, identity) {
			return false
		}
		edges, err := vendorSystemdBootEdgeDirs(base)
		if err != nil {
			return false
		}
		for _, edge := range edges {
			for id := range identity {
				if _, err := os.Lstat(filepath.Join(edge, id)); !errors.Is(err, os.ErrNotExist) {
					return false
				}
			}
			if !nativeMissingVendorAliasesAbsent(edge, identity) {
				return false
			}
		}
	}
	// SysV compatibility may synthesize a new generated unit on manager
	// reload/reboot. This includes charon-systemd, not just starter/ipsec.
	for id := range identity {
		script := strings.TrimSuffix(id, ".service")
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

// Only a narrow, known nonzero missing-unit response may enter this
// independent absence attestation. Arbitrary stderr, success exit codes,
// unknown failures, contradictory stdout and unrelated service identities
// must not be reinterpreted as safe absence. The subsequent effective
// systemd-show plus full disk-identity checks are still mandatory.
func nativeVendorMissingStatusFallbackEligible(action, name string, stdout, stderr []byte, code int) bool {
	if !nativeKnownVendorUnit(name) || (action != "is-active" && action != "is-enabled") ||
		(code != 1 && code != 4) {
		return false
	}
	switch action {
	case "is-active":
		switch string(stdout) {
		case "", "inactive\n", "unknown\n", "not-found\n":
		default:
			return false
		}
	case "is-enabled":
		switch string(stdout) {
		case "", "not-found\n":
		default:
			return false
		}
	}
	if len(stderr) == 0 {
		return true
	}
	// systemctl emits these exact, locale-fixed diagnostics for absent
	// units on supported releases; no generic substring matches allowed.
	if len(stdout) != 0 {
		return false
	}
	switch string(stderr) {
	case "Unit " + name + " could not be found.\n",
		"Failed to get unit file state for " + name + ": No such file or directory\n",
		"Failed to get unit file state for '" + name + "': No such file or directory\n":
		return true
	}
	return false
}
