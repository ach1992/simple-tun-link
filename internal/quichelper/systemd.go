package quichelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"golang.org/x/sys/unix"
)

type hostIdentity struct {
	BootID, NetworkNS, MountNS, PIDNS, UserNS string
	ManagerStartTime                          uint64
}
type systemdHost struct{}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	room := (64 << 10) - w.Len()
	if len(p) > room {
		w.overflow = true
		p = p[:room]
	}
	_, _ = w.Buffer.Write(p)
	return n, nil
}

// Fixed local system-manager tools only. Never inherit bus, remote-host,
// loader or tool-search environment from an interactive caller. Open the
// trusted root-owned executable before exec so PATH and final-symlink
// substitution cannot redirect this command.
func localManagerCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, func(), error) {
	if ctx == nil || (name != "systemctl" && name != "systemd-run" && name != "systemd-analyze" && name != "journalctl") {
		return nil, nil, fmt.Errorf("invalid local systemd command")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	path := "/usr/bin/" + name
	for _, parent := range []string{"/usr", "/usr/bin"} {
		var st unix.Stat_t
		if unix.Lstat(parent, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return nil, nil, fmt.Errorf("systemd command directory is untrusted")
		}
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, nil, fmt.Errorf("trusted local systemd command unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0o022 != 0 || st.Mode&0o111 == 0 || st.Mode&0o6000 != 0 {
		_ = f.Close()
		return nil, nil, fmt.Errorf("local systemd executable is untrusted")
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	cmd := exec.CommandContext(bounded, "/proc/self/fd/3", args...)
	cmd.Args[0] = path
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	cmd.WaitDelay = time.Second
	return cmd, func() { cancel(); _ = f.Close() }, nil
}

func managerCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, &managerFailure{Kind: "invalid_context"}
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd, release, err := localManagerCommand(bounded, name, args...)
	if err != nil {
		return nil, &managerFailure{Kind: "command_unavailable", cause: err}
	}
	defer release()
	var out, stderr boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	// stderr can contain manager/config context; never expose it as ordinary
	// diagnostics. Identity fields and a bounded error stage are sufficient.
	if out.overflow || stderr.overflow {
		return nil, &managerFailure{Kind: "output_limit", cause: err}
	}
	if err != nil {
		kind, code := "command_failed", 0
		if errors.Is(bounded.Err(), context.DeadlineExceeded) {
			kind = "timeout"
		} else if errors.Is(bounded.Err(), context.Canceled) {
			kind = "canceled"
		} else {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				kind, code = "command_exit", exit.ExitCode()
			}
		}
		return nil, &managerFailure{Kind: kind, ExitCode: code, cause: err}
	}
	return out.Bytes(), nil
}

func queryUnit(ctx context.Context, name string) (map[string]string, error) {
	raw, err := managerCommand(ctx, "systemctl", "--system", "show", name, "--property="+unitPropertyNames(), "--no-pager", "--all")
	if err != nil {
		return nil, err
	}
	return parseProperties(raw)
}

func currentHostIdentity() (hostIdentity, error) {
	var result hostIdentity
	if os.Geteuid() != 0 {
		return result, fmt.Errorf("original QUIC systemd start requires root admission")
	}
	boot, e := hostidentity.CurrentKernelBootID()
	if e != nil {
		return result, fmt.Errorf("original QUIC system-manager boot source unverified")
	}
	result.BootID = boot
	for _, pair := range []struct {
		name   string
		target *string
	}{{"net", &result.NetworkNS}, {"mnt", &result.MountNS}, {"pid", &result.PIDNS}, {"user", &result.UserNS}} {
		current, e1 := os.Readlink("/proc/thread-self/ns/" + pair.name)
		manager, e2 := os.Readlink("/proc/1/ns/" + pair.name)
		if e1 != nil || e2 != nil || current == "" || current != manager {
			return hostIdentity{}, fmt.Errorf("QUIC caller and system manager namespaces differ")
		}
		*pair.target = current
	}
	var callerRoot, managerRoot unix.Stat_t
	if unix.Stat("/", &callerRoot) != nil || unix.Stat("/proc/1/root", &managerRoot) != nil || callerRoot.Dev != managerRoot.Dev || callerRoot.Ino != managerRoot.Ino {
		return hostIdentity{}, fmt.Errorf("QUIC caller and manager filesystem roots differ")
	}
	comm, e := readBoundedFile("/proc/1/comm", 64)
	if e != nil || string(comm) != "systemd\n" {
		return hostIdentity{}, fmt.Errorf("local PID 1 is not the system manager")
	}
	result.ManagerStartTime, e = processStartTime(1)
	if e != nil {
		return hostIdentity{}, e
	}
	var socket unix.Stat_t
	if unix.Lstat("/run/systemd/private", &socket) != nil || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Uid != 0 {
		return hostIdentity{}, fmt.Errorf("local system-manager socket is untrusted")
	}
	return result, nil
}

func (systemdHost) preflight(ctx context.Context, s unitSpec) (hostIdentity, error) {
	if ctx == nil || ctx.Err() != nil {
		return hostIdentity{}, fmt.Errorf("QUIC manager preflight context unavailable")
	}
	// Apply a cancellation deadline while reading filesystem inventories
	// in chunks, rather than imposing an installed-unit or Link-count quota.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	host, err := currentHostIdentity()
	if err != nil {
		return host, err
	}
	if !safeArgument(s.Name) || !strings.HasSuffix(s.Name, ".service") || strings.Contains(s.Name, "/") || !safeArgument(s.Description) {
		return hostIdentity{}, fmt.Errorf("invalid QUIC unit request")
	}
	for _, arg := range append([]string{s.Binary}, s.Args...) {
		if !safeArgument(arg) {
			return hostIdentity{}, fmt.Errorf("unsafe systemd argument syntax")
		}
	}
	raw, err := managerCommand(ctx, "systemctl", "--system", "show", "--property=UnitPath,Environment", "--no-pager", "--all")
	if err != nil {
		return hostIdentity{}, err
	}
	manager, err := parseProperties(raw)
	if err != nil {
		return hostIdentity{}, err
	}
	if env, ok := manager["Environment"]; !ok || !safeManagerEnvironment(env) {
		return hostIdentity{}, fmt.Errorf("QUIC manager has an unapproved inherited environment")
	}
	if err := checkUnitSearchPaths(ctx, manager["UnitPath"], s.Name); err != nil {
		return hostIdentity{}, err
	}
	values, err := queryUnit(ctx, s.Name)
	if err != nil {
		return hostIdentity{}, err
	}
	if err := verifyUnitVacant(values, s); err != nil {
		return hostIdentity{}, err
	}
	if err := verifyEffectiveUnitDependencies(ctx, s, values, true); err != nil {
		return hostIdentity{}, err
	}
	again, err := currentHostIdentity()
	if err != nil || again != host {
		return hostIdentity{}, fmt.Errorf("system-manager identity changed during QUIC preflight")
	}
	return host, nil
}

func checkUnitSearchPaths(ctx context.Context, raw, name string) error {
	return checkUnitSearchPathsPolicy(ctx, raw, name, false)
}

func checkUnitSearchPathsPolicy(ctx context.Context, raw, name string, allowTransient bool) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("systemd unit search inspection canceled")
	}
	paths := strings.Fields(raw)
	if len(paths) == 0 || len(paths) > 64 {
		return fmt.Errorf("systemd unit search path unverified")
	}
	stem := strings.TrimSuffix(name, ".service")
	entries := []string{name, name + ".d", name + ".wants", name + ".requires", name + ".upholds", "service.d"}
	for i, c := range stem {
		if c == '-' {
			entries = append(entries, stem[:i+1]+".service.d")
		}
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("systemd unit search inspection canceled")
		}
		if !safeArgument(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return fmt.Errorf("systemd unit search path syntax is unsafe")
		}
		_, err := os.Lstat(path)
		if os.IsNotExist(err) {
			if err = trustedMissingDirectory(path); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("systemd unit search path cannot be inspected")
		}
		if err := trustedDirectoryChain(path); err != nil {
			return err
		}
		for _, entry := range entries {
			if allowTransient && path == "/run/systemd/transient" && entry == name {
				if err := trustedTransientFragment(path, name); err != nil {
					return err
				}
				continue
			}
			_, err := os.Lstat(filepath.Join(path, entry))
			if !os.IsNotExist(err) {
				return fmt.Errorf("foreign QUIC unit file, dependency or drop-in exists or cannot be excluded")
			}
		}
		if err := checkUnitReverseReferencesPolicy(ctx, path, name, allowTransient && path == "/run/systemd/transient"); err != nil {
			return err
		}
	}
	return nil
}

func trustedDirectoryChain(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		var st unix.Stat_t
		if unix.Lstat(current, &st) != nil || st.Uid != 0 {
			return fmt.Errorf("systemd unit search directory is not root controlled")
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if st.Mode&0o022 != 0 {
				return fmt.Errorf("systemd unit search directory is writable by another principal")
			}
		case unix.S_IFLNK:
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil || resolved == current {
				return fmt.Errorf("systemd unit search alias cannot be resolved")
			}
			if err := trustedDirectoryChain(resolved); err != nil {
				return err
			}
		default:
			return fmt.Errorf("systemd unit search ancestor is not a directory")
		}
		if current == "/" {
			break
		}
	}
	return nil
}

func (systemdHost) start(ctx context.Context, s unitSpec) error {
	args := []string{"--system", "--unit=" + s.Name, "--description=" + s.Description, "--service-type=exec", "--quiet"}
	properties := specSecurityProperties(s)
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if key == "Type" || key == "EnvironmentFiles" {
			continue
		}
		args = append(args, "--property="+key+"="+properties[key])
	}
	args = append(args, "--", s.Binary)
	args = append(args, s.Args...)
	_, err := managerCommand(ctx, "systemd-run", args...)
	if err != nil {
		return fmt.Errorf("original QUIC helper start is uncertain; preserve attempt and journal")
	}
	return nil
}

func readBoundedFile(path string, limit int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(raw) > limit {
		return nil, fmt.Errorf("process observation is incomplete")
	}
	return raw, nil
}
func processStartTime(pid int) (uint64, error) {
	raw, e := readBoundedFile("/proc/"+strconv.Itoa(pid)+"/stat", 4096)
	if e != nil {
		return 0, fmt.Errorf("helper process stat unavailable")
	}
	return parseStartTime(raw, pid)
}
func parseStartTime(raw []byte, pid int) (uint64, error) {
	s := string(raw)
	prefix := strconv.Itoa(pid) + " ("
	end := strings.LastIndex(s, ") ")
	if !strings.HasPrefix(s, prefix) || end < 0 {
		return 0, fmt.Errorf("invalid process stat identity")
	}
	parts := strings.Fields(s[end+2:])
	if len(parts) < 20 || parts[0] == "Z" || parts[0] == "X" {
		return 0, fmt.Errorf("helper process is not live")
	}
	v, e := strconv.ParseUint(parts[19], 10, 64)
	if e != nil || v == 0 {
		return 0, fmt.Errorf("invalid process start identity")
	}
	return v, nil
}

type processObservation struct {
	PID                                                   int
	StartTime                                             uint64
	InvocationID, ControlGroup, NetworkNS                 string
	ExecutableDevice, ExecutableInode, StartMonotonicUSec uint64
}
type processPin struct {
	fd          int
	Observation processObservation
}

func (p *processPin) Close() error {
	if p == nil || p.fd < 0 {
		return nil
	}
	err := unix.Close(p.fd)
	p.fd = -1
	return err
}
func (p *processPin) alive() error {
	if p == nil || p.fd < 0 {
		return fmt.Errorf("original process pin unavailable")
	}
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	n, e := unix.Poll(fds, 0)
	if e != nil || n != 0 {
		return fmt.Errorf("original QUIC process exited or identity is uncertain")
	}
	return nil
}

func (systemdHost) observe(ctx context.Context, s unitSpec) (*processPin, error) {
	v, e := queryUnit(ctx, s.Name)
	if e != nil {
		return nil, e
	}
	if e = verifyUnitProperties(v, s); e != nil {
		return nil, e
	}
	pid, _ := strconv.Atoi(v["MainPID"])
	fd, e := unix.PidfdOpen(pid, 0)
	if e != nil {
		return nil, fmt.Errorf("original QUIC process cannot be retained")
	}
	p := &processPin{fd: fd}
	success := false
	defer func() {
		if !success {
			_ = p.Close()
		}
	}()
	if e = p.alive(); e != nil {
		return nil, e
	}
	obs, e := observeProcess(pid, s, v)
	if e != nil {
		return nil, e
	}
	again, e := queryUnit(ctx, s.Name)
	if e != nil || verifyUnitProperties(again, s) != nil || again["MainPID"] != v["MainPID"] || again["InvocationID"] != v["InvocationID"] || again["ExecMainStartTimestampMonotonic"] != v["ExecMainStartTimestampMonotonic"] {
		return nil, fmt.Errorf("original QUIC systemd invocation changed")
	}
	if e := verifyEffectiveUnitDependencies(ctx, s, again, false); e != nil {
		return nil, e
	}
	second, e := observeProcess(pid, s, again)
	if e != nil || second != obs || p.alive() != nil {
		return nil, fmt.Errorf("original QUIC process changed during readback")
	}
	p.Observation = obs
	success = true
	return p, nil
}

func observeProcess(pid int, s unitSpec, v map[string]string) (processObservation, error) {
	return observeProcessEnvironment(pid, s, v, false)
}

func observeProcessEnvironment(pid int, s unitSpec, v map[string]string, journal bool) (processObservation, error) {
	var obs processObservation
	obs.PID = pid
	start, e := processStartTime(pid)
	if e != nil {
		return obs, e
	}
	obs.StartTime = start
	prefix := "/proc/" + strconv.Itoa(pid)
	cmdline, e := readBoundedFile(prefix+"/cmdline", 16<<10)
	if e != nil || len(cmdline) == 0 || cmdline[len(cmdline)-1] != 0 {
		return obs, fmt.Errorf("original QUIC command line unavailable")
	}
	want := append([]string{s.Binary}, s.Args...)
	got := strings.Split(string(cmdline[:len(cmdline)-1]), "\x00")
	if !slices.Equal(got, want) {
		return obs, fmt.Errorf("original QUIC process argv differs")
	}
	var exe, path unix.Stat_t
	if unix.Stat(prefix+"/exe", &exe) != nil || unix.Stat(s.Binary, &path) != nil || exe.Dev != path.Dev || exe.Ino != path.Ino || exe.Mode&unix.S_IFMT != unix.S_IFREG {
		return obs, fmt.Errorf("original QUIC executable inode differs")
	}
	obs.ExecutableDevice = uint64(exe.Dev)
	obs.ExecutableInode = exe.Ino
	obs.NetworkNS, e = os.Readlink(prefix + "/ns/net")
	if e != nil {
		return obs, fmt.Errorf("original QUIC process network namespace unavailable")
	}
	current, e := os.Readlink("/proc/thread-self/ns/net")
	if e != nil || current != obs.NetworkNS {
		return obs, fmt.Errorf("original QUIC process network namespace differs")
	}
	cgroups, e := readBoundedFile(prefix+"/cgroup", 16<<10)
	if e != nil {
		return obs, fmt.Errorf("original QUIC process cgroup unavailable")
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(cgroups)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return obs, fmt.Errorf("invalid QUIC process cgroup readback")
		}
		if parts[0] == "0" && parts[1] == "" || parts[1] == "name=systemd" {
			if found || parts[2] != v["ControlGroup"] {
				return obs, fmt.Errorf("original QUIC process cgroup differs")
			}
			found = true
		}
	}
	if !found {
		return obs, fmt.Errorf("original QUIC process systemd cgroup missing")
	}
	if e := verifyProcessEnvironmentPolicy(prefix, v["InvocationID"], journal); e != nil {
		return obs, e
	}
	obs.InvocationID = v["InvocationID"]
	obs.ControlGroup = v["ControlGroup"]
	obs.StartMonotonicUSec, _ = strconv.ParseUint(v["ExecMainStartTimestampMonotonic"], 10, 64)
	return obs, nil
}

func monotonicUSec() (uint64, error) {
	var ts unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); e != nil || ts.Sec < 0 || ts.Nsec < 0 {
		return 0, fmt.Errorf("monotonic start bound unavailable")
	}
	return uint64(ts.Sec)*1_000_000 + uint64(ts.Nsec)/1000, nil
}

func trustedMissingDirectory(path string) error {
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		_, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("systemd missing search path ancestor cannot be inspected")
		}
		return trustedDirectoryChain(current)
	}
}

func safeManagerEnvironment(raw string) bool {
	if len(raw) > 16<<10 {
		return false
	}
	seen := map[string]bool{}
	for _, item := range strings.Fields(raw) {
		k, v, ok := strings.Cut(item, "=")
		if !ok || seen[k] || !safeArgument(v) {
			return false
		}
		switch k {
		case "PATH", "LANG", "LC_ALL", "LC_CTYPE":
		default:
			if !slices.Contains(strings.Fields(helperUnsetEnvironment), k) {
				return false
			}
		}
		seen[k] = true
	}
	return true
}
func verifyProcessEnvironment(prefix, invocation string) error {
	return verifyProcessEnvironmentPolicy(prefix, invocation, false)
}

func verifyProcessEnvironmentPolicy(prefix, invocation string, journal bool) error {
	raw, err := readBoundedFile(prefix+"/environ", 16<<10)
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != 0 {
		return fmt.Errorf("original QUIC process environment unavailable")
	}
	defer clear(raw)
	want := map[string]string{"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "LC_CTYPE": "C", "INVOCATION_ID": invocation}
	if journal {
		// systemd.exec(249): JOURNAL_STREAM identifies the stderr stream when
		// both output descriptors use journald. Merely seeing the key is not
		// evidence; bind it to the actual inherited descriptor.
		var stream unix.Stat_t
		if unix.Stat(prefix+"/fd/2", &stream) != nil || stream.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return fmt.Errorf("managed QUIC journal stream is unavailable")
		}
		want["JOURNAL_STREAM"] = strconv.FormatUint(uint64(stream.Dev), 10) + ":" + strconv.FormatUint(stream.Ino, 10)
	}
	got := map[string]string{}
	for _, item := range strings.Split(string(raw[:len(raw)-1]), "\x00") {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return fmt.Errorf("original QUIC process environment invalid")
		}
		if _, exists := got[k]; exists {
			return fmt.Errorf("original QUIC process environment ambiguous")
		}
		if expected, known := want[k]; !known || v != expected {
			return fmt.Errorf("original QUIC process environment differs")
		}
		got[k] = v
	}
	if len(got) != len(want) {
		return fmt.Errorf("original QUIC process environment incomplete")
	}
	return nil
}
