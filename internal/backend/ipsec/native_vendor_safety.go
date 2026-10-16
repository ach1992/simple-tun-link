package ipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// A vendor service STOP is a high-impact host transition. Unlike native
// private-service admission, its IKE ports/process may be occupied by the
// exact existing vendor. Every other incompatible owner must be excluded
// BEFORE offering STOP, and the full gate is repeated under STL's exclusive
// maintenance lease before the actual systemctl transition.
type vendorStopSafetyOps struct {
	manager  func(context.Context) error
	packages func(context.Context) error
	private  func(context.Context) error
	aliases  func(context.Context, string) error
	configs  func(context.Context) error
	owners   func(context.Context, string) error
}

func productionVendorStopSafetyOps() vendorStopSafetyOps {
	return vendorStopSafetyOps{
		manager: func(ctx context.Context) error {
			return NewNativeRuntimeAdmission().attestSystemdManagerIdentity(ctx)
		},
		packages: vendorStopPackagesReady,
		private:  vendorStopPrivateVacant,
		aliases:  vendorStopUnitAliasesSafe,
		configs:  vendorStopForeignConfigAbsent,
		owners:   vendorStopProcessAndPortsOwned,
	}
}

func vendorStopHostSafe(ctx context.Context, state, fragment string, ops vendorStopSafetyOps) error {
	if ctx == nil || ctx.Err() != nil || (state != "active" && state != "inactive") ||
		fragment == "" || ops.manager == nil || ops.packages == nil || ops.private == nil ||
		ops.aliases == nil || ops.configs == nil || ops.owners == nil {
		return errors.New("vendor STOP safety dependencies unverified")
	}
	// systemctl's system bus must refer to the actual local PID1 before
	// any of its selected-service identity becomes STOP authorization.
	if err := ops.manager(ctx); err != nil {
		return fmt.Errorf("systemd PID1 conflict: %w", err)
	}
	if err := ops.packages(ctx); err != nil {
		return fmt.Errorf("selected package state: %w", err)
	}
	if err := ops.private(ctx); err != nil {
		return fmt.Errorf("private IPsec conflict: %w", err)
	}
	if err := ops.aliases(ctx, fragment); err != nil {
		return fmt.Errorf("unit/alias conflict: %w", err)
	}
	if err := ops.configs(ctx); err != nil {
		return fmt.Errorf("IPsec config conflict: %w", err)
	}
	if err := ops.owners(ctx, state); err != nil {
		return fmt.Errorf("IKE process/port conflict: %w", err)
	}
	return nil
}

// All selected packages must be in the final, configured dpkg state, even
// after any delay between the menu PREPARE and its separate STOP consent.
// package-file ownership alone is not an installed-package proof.
func vendorStopPackagesReady(ctx context.Context) error {
	audit, err := vendorReadOnlyCommand(ctx, "/usr/bin/dpkg", "--audit")
	if err != nil || len(audit) != 0 {
		return errors.New("dpkg has incomplete or uninspectable transactions")
	}
	for _, pkg := range []string{"iproute2", "iptables", "kmod",
		"charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins"} {
		status, err := vendorReadOnlyCommand(ctx, "/usr/bin/dpkg-query",
			"-W", "-f="+"$"+"{Status}", "--", pkg)
		if err != nil || string(status) != "install ok installed" {
			return errors.New("selected package is not fully configured")
		}
	}
	// Distro conffile modifications indicate that the host may have a live
	// externally managed IPsec configuration. Never silently stop/adopt it.
	for _, pkg := range []string{"charon-systemd", "strongswan-swanctl",
		"libstrongswan-standard-plugins", "libstrongswan"} {
		out, err := vendorReadOnlyCommand(ctx, "/usr/bin/dpkg", "--verify", pkg)
		if err != nil || !vendorOnlyOmittedDistroDocs(out, func(path string) bool {
			_, statErr := os.Lstat(path)
			return errors.Is(statErr, os.ErrNotExist)
		}) {
			// Minimal Debian/Ubuntu images may exclude optional manpages
			// and package documentation. Only confirmed missing NON-runtime
			// files are tolerated; changed/missing executables, libraries
			// and configurations are always disqualifying.
			return fmt.Errorf("distro package %s runtime file-integrity or configuration check failed", pkg)
		}
	}
	return nil
}

// dpkg --verify may report optional manuals and package documents missing
// from lean Debian/Ubuntu images. Operational configuration, binaries, and
// libraries must NEVER be exempted. Accept only exact "missing" rows for
// still-absent documentation. The callback is exclusively a test seam.
func vendorOnlyOmittedDistroDocs(raw []byte, absent func(string) bool) bool {
	if absent == nil || len(raw) > 4096 {
		return false
	}
	if len(raw) == 0 {
		return true
	}
	if raw[len(raw)-1] != '\n' {
		return false
	}
	for _, b := range raw {
		if b != '\n' && (b < 0x20 || b > 0x7e) {
			return false
		}
	}
	for _, row := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		const missing = "missing     "
		if !strings.HasPrefix(row, missing) {
			return false
		}
		path := strings.TrimPrefix(row, missing)
		if !(strings.HasPrefix(path, "/usr/share/doc/") ||
			strings.HasPrefix(path, "/usr/share/man/")) ||
			filepath.Clean(path) != path || strings.ContainsAny(path, " \t") ||
			!absent(path) {
			return false
		}
	}
	return true
}

func vendorReadOnlyCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("expired read-only observation")
	}
	switch binary {
	case "/usr/bin/dpkg", "/usr/bin/dpkg-query":
	default:
		return nil, errors.New("unapproved package inspector")
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = nativeSystemdFixedEnvironment()
	stdout := &privateCapture{max: 32 << 10}
	stderr := &privateCapture{max: 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if err != nil || stdout.overflow || stderr.overflow || stderr.output.Len() != 0 {
		return nil, errors.New("package inspector failed or emitted diagnostics")
	}
	return append([]byte(nil), stdout.output.Bytes()...), nil
}

// Private partial publications, origin receipts and leftover VICI sockets
// must be classified BEFORE taking an existing working vendor VPN offline.
func vendorStopPrivateVacant(ctx context.Context) error {
	if _, err := os.Lstat("/var/lib/simple-tun-link/ipsec"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("private STL IPsec directory exists or is uninspectable")
	}
	if InspectNativeExclusiveConfig() != NativeConfigMissing ||
		InspectNativeExclusiveConfigOrigin() != NativeOriginMissing ||
		InspectNativeExclusiveServiceUnit() != NativeServiceUnitMissing ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginMissing {
		return errors.New("STL-exclusive private publication already exists or is uncertain")
	}
	if _, err := os.Lstat(NativeExclusiveVICIPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("STL-exclusive private VICI state occupied or uninspectable")
	}
	runner := nativeSystemdRunner{}
	out, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 2048, Stderr: 1024},
		nativeSystemctlBinary, "--system", "--no-pager", "--no-legend", "--plain",
		"--full", "--all", "--type=service", "list-units", "simple-tun-link-ipsec.servic?")
	if err != nil || len(out.Stderr) != 0 || !nativeProvisionInventoryUnoccupied(out.Stdout) {
		return errors.New("STL-exclusive in-memory systemd unit is not vacant")
	}
	return nil
}

// The fixed narrow systemd unit search inventory matches the canonical
// installer contract; unapproved generator/attached paths are never assumed
// absent simply because /etc/systemd/system has no conflicting unit.
var vendorUnitSearchPaths = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control",
	"/run/systemd/transient", "/run/systemd/generator.early",
	"/etc/systemd/system", "/etc/systemd/system.attached",
	"/run/systemd/system", "/run/systemd/system.attached",
	"/run/systemd/generator", "/usr/local/lib/systemd/system",
	"/lib/systemd/system", "/usr/lib/systemd/system",
	"/run/systemd/generator.late",
}

func vendorStopUnitPaths(ctx context.Context) error {
	runner := nativeSystemdRunner{}
	result, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 2048, Stderr: 1024},
		nativeSystemctlBinary, "--system", "--no-pager", "show", "-p", "UnitPath")
	if err != nil || len(result.Stderr) != 0 ||
		!strings.HasPrefix(string(result.Stdout), "UnitPath=") ||
		len(result.Stdout) < 12 || result.Stdout[len(result.Stdout)-1] != '\n' ||
		strings.Count(string(result.Stdout), "\n") != 1 {
		return errors.New("systemd manager unit search path unverified")
	}
	allowed := make(map[string]bool, len(vendorUnitSearchPaths))
	for _, path := range vendorUnitSearchPaths {
		allowed[path] = true
	}
	seen := map[string]bool{}
	etc, vendor := false, false
	for _, path := range strings.Fields(strings.TrimSuffix(strings.TrimPrefix(string(result.Stdout), "UnitPath="), "\n")) {
		if !allowed[path] || seen[path] {
			return errors.New("unexpected or duplicate systemd unit search path")
		}
		seen[path] = true
		etc = etc || path == "/etc/systemd/system"
		vendor = vendor || path == "/usr/lib/systemd/system" || path == "/lib/systemd/system"
	}
	if !etc || !vendor {
		return errors.New("canonical systemd unit search paths incomplete")
	}
	return nil
}

func vendorStopUnitAliasesSafe(ctx context.Context, fragment string) error {
	if err := vendorStopUnitPaths(ctx); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(fragment)
	if err != nil || resolved != "/usr/lib/systemd/system/strongswan.service" {
		return errors.New("selected vendor fragment changed")
	}
	for _, dir := range vendorUnitSearchPaths {
		// Never allow an on-disk shadow of the selected vendor in an
		// alternate manager unit path, even before a future daemon-reload.
		if dir != "/usr/lib/systemd/system" && dir != "/lib/systemd/system" {
			if _, err := os.Lstat(filepath.Join(dir, vendorServiceName)); err == nil ||
				!errors.Is(err, os.ErrNotExist) {
				return errors.New("foreign vendor service shadow present in unit search path")
			}
		}
		// A preexisting STL-private boot edge or an alternate vendor boot
		// edge may be dormant without appearing in list-units; it is still
		// an unapproved owner and must block stopping an existing VPN.
		for _, suffix := range []string{"*.wants", "*.requires"} {
			edges, err := filepath.Glob(filepath.Join(dir, suffix))
			if err != nil || len(edges) > 128 {
				return errors.New("systemd boot-edge paths unverified")
			}
			for _, edge := range edges {
				for _, unit := range []string{"simple-tun-link-ipsec.service",
					"strongswan-starter.service", "charon-systemd.service",
					"ipsec.service"} {
					if _, err := os.Lstat(filepath.Join(edge, unit)); err == nil ||
						!errors.Is(err, os.ErrNotExist) {
						return errors.New("foreign or stale IPsec boot edge occupies manager")
					}
				}
			}
		}
		// The vendor package's exact swanctl alias is permitted only as a
		// symlink to the vetted official fragment. Every other IPsec unit,
		// override or prefix drop-in is a separate, unapproved owner.
		for _, name := range []string{"service.d", "strongswan.service.d",
			"strongswan-swanctl.service.d", "strongswan-starter.service.d",
			"strongswan-.service.d", "charon-systemd.service.d",
			"charon-.service.d", "ipsec.service.d",
			"simple-tun-link-ipsec.service.d", "simple-tun-link-.service.d",
			"simple-tun-.service.d", "simple-.service.d",
			"strongswan-starter.service", "charon-systemd.service",
			"ipsec.service", "simple-tun-link-ipsec.service"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); err == nil ||
				!errors.Is(err, os.ErrNotExist) {
				return errors.New("unexpected alternate IPsec unit or drop-in exists")
			}
		}
		path := filepath.Join(dir, "strongswan-swanctl.service")
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return errors.New("vendor alias is foreign or uninspectable")
		}
		target, err := filepath.EvalSymlinks(path)
		if err != nil || target != resolved {
			return errors.New("vendor alias points outside the approved unit")
		}
	}
	runner := nativeSystemdRunner{}
	result, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 2048, Stderr: 1024},
		nativeSystemctlBinary, "--system", "--no-pager", "show", "strongswan-swanctl.service",
		"-p", "FragmentPath", "-p", "DropInPaths", "-p", "NeedDaemonReload")
	if err != nil || len(result.Stderr) != 0 || len(result.Stdout) == 0 ||
		result.Stdout[len(result.Stdout)-1] != '\n' ||
		strings.Count(string(result.Stdout), "\n") != 3 {
		return errors.New("effective vendor alias properties unverified")
	}
	lines := strings.Split(strings.TrimSuffix(string(result.Stdout), "\n"), "\n")
	found := map[string]string{}
	for _, line := range lines {
		key, val, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return errors.New("invalid effective alias property")
		}
		if _, exists := found[key]; exists {
			return errors.New("duplicate effective alias property")
		}
		found[key] = val
	}
	if len(found) != 3 || found["DropInPaths"] != "" || found["NeedDaemonReload"] != "no" {
		return errors.New("unexpected vendor alias override")
	}
	if found["FragmentPath"] != "" {
		target, err := filepath.EvalSymlinks(found["FragmentPath"])
		if err != nil || target != resolved {
			return errors.New("effective vendor alias is a separate unit")
		}
	}
	return nil
}

// dpkg-query -S prints multiarch owners as e.g. libstrongswan:amd64
// on Debian/Ubuntu. Only the current package architecture and these exact
// vetted vendor packages are eligible; alternate-arch or foreign packages
// do not establish trust of effective daemon configuration.
func vendorDistroConfigOwner(pkg string) bool {
	base, arch, qualified := strings.Cut(pkg, ":")
	if qualified && arch != runtime.GOARCH {
		return false
	}
	switch base {
	case "charon-systemd", "strongswan-swanctl",
		"libstrongswan", "libstrongswan-standard-plugins",
		"libcharon-extauth-plugins":
		return true
	default:
		return false
	}
}

// Only package-owned and unmodified distro default configuration is eligible.
// A third-party VPN's credentials/profiles are never stopped in the hope that
// a subsequent private STL provisioner might happen to succeed.
func vendorStopForeignConfigAbsent(ctx context.Context) error {
	for _, path := range []string{"/etc/ipsec.conf", "/etc/ipsec.secrets", "/etc/ipsec.d"} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("legacy or foreign IPsec configuration exists")
		}
	}
	var files []string
	for _, root := range []string{"/etc/strongswan.conf", "/etc/strongswan.d", "/etc/swanctl"} {
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return errors.New("distro configuration path cannot be inspected")
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || len(files) > 256 {
				return errors.New("distro configuration inventory incomplete")
			}
			info, err := entry.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("foreign symlink or unreadable distro config")
			}
			if info.IsDir() {
				if info.Mode().Perm()&0o022 != 0 {
					return errors.New("writable distro config directory")
				}
				return nil
			}
			if !info.Mode().IsRegular() || len(files) == 256 {
				return errors.New("foreign distro config entry or inventory overflow")
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(files) == 0 {
		return nil
	}
	args := append([]string{"-S", "--"}, files...)
	raw, err := vendorReadOnlyCommand(ctx, "/usr/bin/dpkg-query", args...)
	if err != nil {
		return errors.New("existing vendor files lack verified package ownership")
	}
	expected := make(map[string]bool, len(files))
	for _, path := range files {
		expected[path] = true
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		pkg, path, ok := strings.Cut(line, ": ")
		if !ok || !expected[path] {
			return errors.New("unowned or unexpected vendor config file")
		}
		if !vendorDistroConfigOwner(pkg) {
			return errors.New("foreign package owns vendor configuration")
		}
		delete(expected, path)
	}
	if len(expected) != 0 {
		return errors.New("distro config file ownership incomplete")
	}
	return nil
}

func vendorStopProcessAndPortsOwned(ctx context.Context, state string) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("vendor process attestation expired")
	}
	if state == "inactive" {
		if err := verifyNoForeignStrongSwanProcess(0); err != nil {
			return err
		}
		return nativeIKEPortsVacant()
	}
	runner := nativeSystemdRunner{}
	result, err := runner.RunBounded(ctx, CaptureLimits{Stdout: 128, Stderr: 128},
		nativeSystemctlBinary, "--system", "--no-pager", "show", vendorServiceName, "-p", "MainPID")
	if err != nil || len(result.Stderr) != 0 ||
		!strings.HasPrefix(string(result.Stdout), "MainPID=") ||
		strings.Count(string(result.Stdout), "\n") != 1 ||
		result.Stdout[len(result.Stdout)-1] != '\n' {
		return errors.New("official vendor MainPID unavailable")
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(string(result.Stdout), "MainPID=")), 10, 32)
	if err != nil || pid < 2 {
		return errors.New("invalid existing official vendor daemon PID")
	}
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	if err := verifyTrustedNativeExecutable(exe, nativeStrongSwanExecutable); err != nil {
		return err
	}
	if err := vendorStopEnvironmentSafe(uint32(pid)); err != nil {
		return err
	}
	vendorNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	selfNS, selfErr := os.Readlink("/proc/self/ns/net")
	if err != nil || selfErr != nil || vendorNS != selfNS {
		return errors.New("vendor daemon network namespace unverified")
	}
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil || len(cgroup) > 8192 ||
		(!strings.Contains(string(cgroup), "/system.slice/"+vendorServiceName+"\n") &&
			!strings.Contains(string(cgroup), "/system.slice/"+vendorServiceName+"/")) {
		return errors.New("selected daemon is not in official vendor systemd cgroup")
	}
	if err := verifyNoForeignStrongSwanProcess(uint32(pid)); err != nil {
		return err
	}
	return verifyNativeUDPPorts(uint32(pid))
}

func vendorStopEnvironmentSafe(pid uint32) error {
	path := fmt.Sprintf("/proc/%d/environ", pid)
	file, err := os.Open(path)
	if err != nil {
		return errors.New("existing vendor daemon environment unreadable")
	}
	defer file.Close()
	env, err := io.ReadAll(io.LimitReader(file, 32769))
	defer clear(env)
	if err != nil || len(env) == 0 || len(env) > 32768 || env[len(env)-1] != 0 {
		return errors.New("existing vendor daemon environment unverified")
	}
	for _, item := range strings.Split(string(env), "\x00") {
		if strings.HasPrefix(item, "STRONGSWAN_CONF=") &&
			item != "STRONGSWAN_CONF=/etc/strongswan.conf" {
			return errors.New("existing vendor daemon uses external configuration override")
		}
		if strings.HasPrefix(item, "LD_") ||
			strings.HasPrefix(item, "GCONV_PATH=") ||
			(strings.HasPrefix(item, "STRONGSWAN_") &&
				!strings.HasPrefix(item, "STRONGSWAN_CONF=")) {
			return errors.New("unverified vendor executable loader or environment override")
		}
	}
	return nil
}
