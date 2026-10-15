package ipsec

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const nativeServiceName = "simple-tun-link-ipsec.service"
const nativeStrongSwanExecutable = "/usr/sbin/charon-systemd"
const nativeBusctl = "/usr/bin/busctl"

var nativeUnitObject = regexp.MustCompile("^/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+$")

// NativeRuntimeAdmission NEVER starts, installs, stops or reconfigures a
// service. Provenance of the protected on-disk source is a prerequisite,
// not an operational permit. Every denied observation keeps IPsec disabled.
type NativeRuntimeAdmission struct{ Runner BoundedCommandRunner }

func NewNativeRuntimeAdmission() NativeRuntimeAdmission {
	return NativeRuntimeAdmission{Runner: nativeSystemdRunner{Timeout: 4 * time.Second}}
}

func (a NativeRuntimeAdmission) readBus(ctx context.Context, args ...string) (string, error) {
	if a.Runner == nil || ctx == nil {
		return "", fmt.Errorf("systemd inspector unavailable")
	}
	result, err := a.Runner.RunBounded(ctx, CaptureLimits{Stdout: 8192, Stderr: 1024},
		nativeBusctl, append([]string{nativeSystemdManagerAddress}, args...)...)
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	if err != nil || len(result.Stdout) == 0 || len(result.Stdout) > 8192 ||
		result.Stdout[len(result.Stdout)-1] != '\n' || strings.Count(string(result.Stdout), "\n") != 1 ||
		strings.IndexByte(string(result.Stdout), 0) >= 0 {
		return "", fmt.Errorf("unverified systemd D-Bus reply")
	}
	return string(result.Stdout[:len(result.Stdout)-1]), nil
}

func decodeDBusString(reply, kind string) (string, error) {
	if !strings.HasPrefix(reply, kind+" ") {
		return "", fmt.Errorf("unexpected systemd property type")
	}
	v, err := strconv.Unquote(strings.TrimPrefix(reply, kind+" "))
	if err != nil || strings.ContainsAny(v, "\x00\n\r") {
		return "", fmt.Errorf("invalid systemd string")
	}
	return v, nil
}

func (a NativeRuntimeAdmission) loadedUnit(ctx context.Context) (string, error) {
	raw, err := a.readBus(ctx, "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
		"org.freedesktop.systemd1.Manager", "GetUnit", "s", nativeServiceName)
	if err != nil {
		return "", err
	}
	value, err := decodeDBusString(raw, "o")
	if err != nil || !nativeUnitObject.MatchString(value) {
		return "", fmt.Errorf("native-exclusive unit not already loaded")
	}
	return value, nil
}

func (a NativeRuntimeAdmission) property(ctx context.Context, path, iface, key string) (string, error) {
	if !nativeUnitObject.MatchString(path) {
		return "", fmt.Errorf("invalid systemd object reference")
	}
	return a.readBus(ctx, "get-property", "org.freedesktop.systemd1", path,
		"org.freedesktop.systemd1."+iface, key)
}

func (a NativeRuntimeAdmission) require(ctx context.Context, path, iface, key, value string) error {
	raw, err := a.property(ctx, path, iface, key)
	if err != nil {
		return err
	}
	got, err := decodeDBusString(raw, "s")
	if err != nil || got != value {
		return fmt.Errorf("native service property differs from fixed profile")
	}
	return nil
}

func (a NativeRuntimeAdmission) servicePID(ctx context.Context) (uint32, error) {
	path, err := a.loadedUnit(ctx)
	if err != nil {
		return 0, err
	}
	for _, prop := range []struct{ category, key, value string }{
		{"Unit", "LoadState", "loaded"}, {"Unit", "ActiveState", "active"},
		{"Unit", "FragmentPath", NativeExclusiveServiceUnitPath},
		{"Unit", "SourcePath", ""},
		{"Service", "Type", "notify"}, {"Service", "User", ""},
		{"Service", "Group", ""}, {"Service", "RootDirectory", ""},
	} {
		if err := a.require(ctx, path, prop.category, prop.key, prop.value); err != nil {
			return 0, err
		}
	}
	// A statically defined native service becomes UnitFileState=enabled after
	// an explicitly installed multi-user.target.wants edge. Reject every
	// unrecognized or foreign enablement source; never infer authorization
	// solely from a matching systemd property string.
	fileState, err := a.property(ctx, path, "Unit", "UnitFileState")
	if err != nil {
		return 0, fmt.Errorf("native unit file state unavailable")
	}
	if fileState != `s "static"` &&
		!nativeUnitFileStateVerified(fileState, trustedNativeBootEnablementAt("/", 0)) {
		return 0, fmt.Errorf("native unit enablement origin unverified")
	}
	for _, prop := range []struct{ category, key, value string }{
		{"Unit", "DropInPaths", "as 0"}, {"Unit", "NeedDaemonReload", "b false"},
		{"Service", "UMask", "u 63"},
		{"Service", "Environment", "as 1 \"STRONGSWAN_CONF=/var/lib/simple-tun-link/ipsec/strongswan.conf\""},
	} {
		got, err := a.property(ctx, path, prop.category, prop.key)
		if err != nil || got != prop.value {
			return 0, fmt.Errorf("native unit overrides or effective service settings unverified")
		}
	}
	pidText, err := a.property(ctx, path, "Service", "MainPID")
	if err != nil || !strings.HasPrefix(pidText, "u ") {
		return 0, fmt.Errorf("native service PID unavailable")
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(pidText, "u "), 10, 32)
	if err != nil || n < 2 {
		return 0, fmt.Errorf("invalid native service PID")
	}
	if second, e := a.loadedUnit(ctx); e != nil || second != path {
		return 0, fmt.Errorf("native systemd object identity changed")
	}
	return uint32(n), nil
}

// No generic enabled unit is trusted: an enabled state needs an exact
// root-owned canonical boot edge verified on this invocation.
func nativeUnitFileStateVerified(state string, trustedBootEdge bool) bool {
	return state == `s "static"` || (state == `s "enabled"` && trustedBootEdge)
}

// StrongSwan is launched with root privileges and receives the IKE PSK.
// Inode equality alone is insufficient: an unprivileged owner may replace
// bytes inside an otherwise mode-0755 executable. Verify all components of
// the executable's root-controlled path as well as its pinned file descriptor.
func rootControlledExecutableMetadata(info os.FileInfo, directory bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 ||
		info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if directory {
		return info.IsDir()
	}
	return info.Mode().IsRegular()
}

func verifyTrustedNativeExecutable(processExe, installedPath string) error {
	if !filepath.IsAbs(installedPath) || filepath.Clean(installedPath) != installedPath {
		return fmt.Errorf("native executable path invalid")
	}
	process, err := os.Stat(processExe)
	if err != nil {
		return fmt.Errorf("native executable process identity unavailable")
	}
	checkAncestors := func() error {
		for parent := filepath.Dir(installedPath); ; parent = filepath.Dir(parent) {
			info, statErr := os.Lstat(parent)
			if statErr != nil || !rootControlledExecutableMetadata(info, true) {
				return fmt.Errorf("native executable ancestry is not root-controlled")
			}
			if parent == "/" {
				return nil
			}
		}
	}
	if err := checkAncestors(); err != nil {
		return err
	}
	fd, err := unix.Open(installedPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("native executable cannot be pinned")
	}
	file := os.NewFile(uintptr(fd), "native-strongswan-executable")
	defer file.Close()
	installed, err := file.Stat()
	if err != nil || !rootControlledExecutableMetadata(installed, false) || !os.SameFile(process, installed) {
		return fmt.Errorf("native executable origin or root ownership unverified")
	}
	path, err := os.Lstat(installedPath)
	if err != nil || !rootControlledExecutableMetadata(path, false) || !os.SameFile(path, installed) {
		return fmt.Errorf("native executable path changed during attestation")
	}
	if err := checkAncestors(); err != nil {
		return err
	}
	return nil
}

func verifyNativeProcess(pid uint32) error {
	if pid < 2 {
		return fmt.Errorf("missing native daemon PID")
	}
	base := fmt.Sprintf("/proc/%d", pid)
	if err := verifyTrustedNativeExecutable(base+"/exe", nativeStrongSwanExecutable); err != nil {
		return err
	}
	gotNS, err := os.Readlink(base + "/ns/net")
	selfNS, err2 := os.Readlink("/proc/self/ns/net")
	if err != nil || err2 != nil || gotNS != selfNS {
		return fmt.Errorf("native daemon belongs to another network namespace")
	}
	file, err := os.Open(base + "/environ")
	if err != nil {
		return fmt.Errorf("native process environment unavailable")
	}
	defer file.Close()
	env, err := io.ReadAll(io.LimitReader(file, 32769))
	defer clear(env)
	if err != nil || len(env) == 0 || len(env) > 32768 || env[len(env)-1] != 0 {
		return fmt.Errorf("native process environment ambiguous")
	}
	counter := 0
	for _, kv := range strings.Split(string(env), "\x00") {
		if kv == "STRONGSWAN_CONF="+NativeExclusiveConfigPath {
			counter++
		}
		if strings.HasPrefix(kv, "LD_") ||
			(strings.HasPrefix(kv, "STRONGSWAN_") && kv != "STRONGSWAN_CONF="+NativeExclusiveConfigPath) {
			return fmt.Errorf("unexpected native daemon environment override")
		}
	}
	if counter != 1 {
		return fmt.Errorf("strongSwan process did not use STL config")
	}
	raw, err := os.ReadFile(base + "/cgroup")
	if err != nil || len(raw) > 8192 ||
		!strings.Contains(string(raw), "/system.slice/"+nativeServiceName) {
		return fmt.Errorf("strongSwan daemon is not in the STL systemd unit")
	}
	return nil
}

func verifyNativeVICI(ctx context.Context, pid uint32) error {
	for index, dir := range []string{filepath.Dir(NativeExclusiveVICIPath),
		filepath.Dir(filepath.Dir(NativeExclusiveVICIPath))} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			(index == 0 && info.Mode().Perm()&0o077 != 0) ||
			(index != 0 && info.Mode().Perm()&0o022 != 0) {
			return fmt.Errorf("private VICI directory unsafe")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
			return fmt.Errorf("private VICI directory not root-owned")
		}
	}
	info, err := os.Lstat(NativeExclusiveVICIPath)
	// The VICI plugin on strongSwan 5.9/6.0 creates socket mode 0770
	// even when the service UMask is 0077. The immediate parent directory
	// was already attested as root-owned 0700 above, so group access to
	// this socket cannot traverse its parent. Do not reject the supported
	// daemon merely for its harmless group bits; reject world bits and
	// retain the root-only parent, socket owner and SO_PEERCRED checks.
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("private VICI socket unverified")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return fmt.Errorf("private VICI socket not root-owned")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", NativeExclusiveVICIPath)
	if err != nil {
		return fmt.Errorf("private VICI peer unavailable")
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("private VICI endpoint is not Unix")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("private peer credentials unavailable")
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) { cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil ||
		sockErr != nil || cred == nil || cred.Pid != int32(pid) || cred.Uid != 0 {
		return fmt.Errorf("private VICI peer differs from native daemon MainPID")
	}
	return nil
}

// A foreign strongSwan daemon in the same network namespace is a
// native-exclusive conflict even when it is temporarily not listening.
func verifyNoForeignStrongSwanProcess(allowedPID uint32) error {
	// Separate network namespaces are independent IKE port/VICI domains.
	// Do not reject an unrelated isolated strongSwan peer, but never accept
	// another daemon in the calling host network namespace.
	ownerNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("cannot attest calling IPsec network namespace")
	}
	processes, err := os.ReadDir("/proc")
	if err != nil || len(processes) > 32768 {
		return fmt.Errorf("foreign daemon process inventory unavailable")
	}
	for _, entry := range processes {
		pid, e := strconv.ParseUint(entry.Name(), 10, 32)
		if e != nil || pid == uint64(allowedPID) {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		raw, e := os.ReadFile(filepath.Join(base, "comm"))
		if e != nil {
			// Missing processes may have exited. A permission-denied or
			// malformed procfs reader cannot establish exclusivity.
			if os.IsNotExist(e) {
				continue
			}
			return fmt.Errorf("foreign process inventory access incomplete")
		}
		name := strings.TrimSpace(string(raw))
		if name != "charon" && name != "charon-systemd" && name != "starter" {
			continue
		}
		observedNS, e := os.Readlink(filepath.Join(base, "ns/net"))
		if e != nil {
			if os.IsNotExist(e) {
				continue
			}
			return fmt.Errorf("foreign strongSwan network namespace unknown")
		}
		if observedNS == ownerNetNS {
			return fmt.Errorf("foreign strongSwan process already exists in current network namespace")
		}
	}
	return nil
}

// Authorize may repeat a complete *read-only* attestation once when a
// transient procfs descriptor close or systemd property transition interrupts
// the first snapshot. It never carries a partial successful observation from
// one pass into another, never retries an effect, and never grants access
// unless one entire current scan succeeds.
func (a NativeRuntimeAdmission) Authorize(ctx context.Context) error {
	err := a.authorizeOnce(ctx)
	if err == nil || ctx == nil || ctx.Err() != nil {
		return err
	}
	return a.authorizeOnce(ctx)
}

func (a NativeRuntimeAdmission) authorizeOnce(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return fmt.Errorf("root-owned native-exclusive IPsec admission required")
	}
	if InspectNativeExclusiveConfigOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveConfig() != NativeConfigExact ||
		InspectNativeExclusiveServiceUnit() != NativeServiceUnitExact {
		return fmt.Errorf("STL native config and unit origin receipts unverified")
	}
	pid, err := a.servicePID(ctx)
	if err != nil {
		return fmt.Errorf("loaded service identity not attested")
	}
	if err := verifyNativeProcess(pid); err != nil {
		return err
	}
	if err := verifyNativeVICI(ctx, pid); err != nil {
		return err
	}
	if err := verifyNoForeignStrongSwanProcess(pid); err != nil {
		return err
	}
	if err := verifyNativeUDPPorts(pid); err != nil {
		return err
	}
	// Revalidate durable source and same loaded service rather than caching
	// a point-in-time permit; Engine calls this under Link/resource locks.
	if InspectNativeExclusiveConfigOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginVerified {
		return fmt.Errorf("STL native publication identity changed")
	}
	current, err := a.servicePID(ctx)
	if err != nil || pid != current {
		return fmt.Errorf("STL native daemon PID changed during admission")
	}
	return nil
}
