//go:build linux

package quichelper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/systemdunit"
	"golang.org/x/sys/unix"
)

// This opt-in test starts only a harmless sleep process on an explicitly
// disposable GitHub-hosted runner. It exercises the production systemd and
// process verifiers, not the canonical Engine/Hysteria activation transaction.
// No connected field host or existing managed Link is an eligible fixture.
func TestQUICHelperDisposableSystemdOriginal(t *testing.T) {
	if os.Getenv("STL_QUIC_HELPER_DISPOSABLE_SYSTEMD") != "approved" {
		t.Skip("requires an explicitly approved disposable systemd runner")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" ||
		os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv("GITHUB_REPOSITORY") != "ach1992/simple-tun-link" || os.Geteuid() != 0 {
		t.Fatal("disposable GitHub-hosted root fixture required")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		t.Fatal("native disposable PID-1 systemd required")
	}
	run := disposableRunNumber(t, "GITHUB_RUN_ID")
	attempt := disposableRunNumber(t, "GITHUB_RUN_ATTEMPT")
	digest := sha256.Sum256([]byte("quic-helper-systemd:" + run + ":" + attempt))
	id := fmt.Sprintf("%x", digest[:5])
	binary, executable := pinDisposableExecutable(t)
	spec := unitSpec{
		Name:        "stl-quic-" + id + ".service",
		Description: fmt.Sprintf("STL-QUIC-stl-%s:tx:%x", id, digest[:16]),
		Binary:      binary,
		Args:        []string{"45"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	host := systemdHost{}
	if _, err := host.preflight(ctx, spec); err != nil {
		logDisposableManagerEnvironment(t, ctx)
		t.Fatalf("original empty-unit preflight failed: %v", err)
	}
	if err := host.start(ctx, spec); err != nil {
		// A failed/uncertain launch never grants stop-by-name authority. The
		// fixture's fixed sleep is intrinsically bounded even in this case.
		t.Fatalf("original start failed or uncertain; no name-based cleanup: %v", err)
	}
	pin, err := host.observe(ctx, spec)
	if err != nil {
		t.Fatalf("original process ownership unverified; bounded fixture retained: %v", err)
	}
	// Cleanup addresses the independently retained original pidfd only.
	// A reused PID, unit name or current systemd shape cannot redirect it.
	t.Cleanup(func() { disposeOriginalProcess(t, pin) })
	original := pin.Observation
	if original.PID <= 1 || original.StartTime == 0 || original.InvocationID == "" ||
		original.ControlGroup == "" || original.NetworkNS == "" ||
		original.StartMonotonicUSec == 0 {
		t.Fatal("original process observation lacks a required identity witness")
	}
	if original.ExecutableDevice != uint64(executable.Dev) || original.ExecutableInode != executable.Ino {
		t.Fatal("systemd did not execute the originally retained executable inode")
	}
	values, err := queryUnit(ctx, spec.Name)
	if err != nil {
		t.Fatalf("actual systemd readback failed: %v", err)
	}
	if err := verifyUnitProperties(values, spec); err != nil {
		t.Fatalf("production verifier rejected actual systemd properties: %v", err)
	}

	// An existing exact-looking unit is not vacancy or a second original
	// start. Rejection must leave the first process and invocation intact.
	if _, err := host.preflight(ctx, spec); err == nil {
		t.Fatal("preflight admitted an already loaded original unit")
	}
	if err := host.start(ctx, spec); err == nil {
		t.Fatal("systemd accepted a second original start of an existing unit")
	}
	after, err := host.observe(ctx, spec)
	if err != nil {
		t.Fatalf("collision attempt disrupted the original process: %v", err)
	}
	if after.Observation != original {
		after.Close()
		t.Fatal("collision attempt changed original process identity")
	}
	if err := after.Close(); err != nil {
		t.Fatalf("close duplicate observation pin: %v", err)
	}

	// The actual live unit must fail observation when its expected owner
	// differs. No stop/restart is issued by an unsuccessful read-only gate.
	foreign := spec
	foreign.Description = "different generation owner"
	if unexpected, err := host.observe(ctx, foreign); err == nil {
		unexpected.Close()
		t.Fatal("foreign expected owner adopted the original unit")
	}

	// Start from this runner's actual property representation, not a
	// mock-shaped success fixture. Corrupt only properties decisive to
	// effect safety so 249/newer formatting cannot hide foreign behavior.
	for _, tc := range []struct{ name, property, value string }{
		{"foreign_pre_start", "ExecStartPre", values["ExecStart"]},
		{"foreign_post_start", "ExecStartPost", values["ExecStart"]},
		{"foreign_stop", "ExecStop", values["ExecStart"]},
		{"restart_authority", "Restart", "always"},
		{"foreign_environment", "Environment", "STL_FOREIGN=present"},
		{"foreign_drop_in", "DropInPaths", "/run/systemd/system/foreign.conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				t.Fatal("actual systemd fixture omitted required main execution evidence")
			}
			changed := make(map[string]string, len(values))
			for key, value := range values {
				changed[key] = value
			}
			changed[tc.property] = tc.value
			if err := verifyUnitProperties(changed, spec); err == nil {
				t.Fatalf("production verifier accepted %s in actual systemd readback", tc.property)
			}
		})
	}
	t.Run("effective_foreign_upholder_blocks_first_start", func(t *testing.T) {
		verifyDisposableForeignUpholder(t, run, attempt, binary, executable)
	})
	t.Log("actual transient first-start, process pin, collision denial and strict unit-property evidence passed; no managed QUIC Link was created")
}

// This regression declares an actual direct dependency on a separate absent
// helper. It never starts that target, writes a unit file or reloads PID 1.
// Its one explicitly owned upholder is a bounded harmless process.
func verifyDisposableForeignUpholder(t *testing.T, run, attempt, binary string, executable unix.Stat_t) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	digest := sha256.Sum256([]byte("quic-helper-upholds:" + run + ":" + attempt))
	id := fmt.Sprintf("%x", digest[:5])
	target := unitSpec{
		Name:        "stl-quic-" + id + ".service",
		Description: fmt.Sprintf("STL-QUIC-stl-%s:tx:%x", id, digest[:16]),
		Binary:      binary,
		Args:        []string{"45"},
	}
	upholder := target
	upholder.Name = "stl-quic-lab-upholder-" + id + ".service"
	upholder.Description = fmt.Sprintf("STL-QUIC-LAB-UPHOLDER-%s:tx:%x", id, digest[16:])
	host := systemdHost{}
	if _, err := host.preflight(ctx, target); err != nil {
		t.Fatalf("negative target was not independently vacant before the fixture: %v", err)
	}
	if _, err := host.preflight(ctx, upholder); err != nil {
		t.Fatalf("disposable upholder identity already present or unverified: %v", err)
	}
	before, err := monotonicUSec()
	if err != nil {
		t.Fatal("upholder original start lower bound unavailable")
	}
	args := []string{"--system", "--unit=" + upholder.Name, "--description=" + upholder.Description,
		"--service-type=exec", "--quiet", "--property=Upholds=" + target.Name}
	properties := specSecurityProperties(upholder)
	keys := make([]string, 0, len(properties))
	for key := range properties {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if key != "Type" && key != "EnvironmentFiles" {
			args = append(args, "--property="+key+"="+properties[key])
		}
	}
	args = append(args, "--", upholder.Binary)
	args = append(args, upholder.Args...)
	if _, err := managerCommand(ctx, "systemd-run", args...); err != nil {
		t.Fatalf("original bounded upholder start uncertain; no name cleanup: %v", err)
	}
	after, err := monotonicUSec()
	if err != nil {
		t.Fatal("upholder original start upper bound unavailable; bounded fixture retained")
	}
	pin, err := pinDisposableUpholder(ctx, upholder, target, before, after)
	if err != nil {
		t.Fatalf("upholder original process not proved; bounded fixture retained: %v", err)
	}
	t.Cleanup(func() { disposeOriginalProcess(t, pin) })
	if pin.Observation.ExecutableDevice != uint64(executable.Dev) || pin.Observation.ExecutableInode != executable.Ino {
		t.Fatal("upholder did not execute the originally retained harmless inode")
	}
	if _, err := host.preflight(ctx, target); err == nil {
		t.Fatal("first-start preflight admitted an effective foreign Upholds dependency")
	}
	if observed, err := inspectManagedUnit(ctx, target); err == nil {
		if observed.Process != nil {
			_ = observed.Process.Close()
		}
		t.Fatal("managed helper admission accepted an independently verified foreign Upholds dependency")
	}
	values, err := queryUnit(ctx, target.Name)
	if err != nil || values["LoadState"] != "not-found" || values["MainPID"] != "0" ||
		values["ExecMainPID"] != "0" || values["ExecStart"] != "" || values["ExecStartEx"] != "" {
		t.Fatal("negative helper target no longer has verified absent executable/process state")
	}
	if err := pin.alive(); err != nil {
		t.Fatal("target rejection did not preserve the independently owned live upholder")
	}
	if _, modern := values["UpheldBy"]; modern {
		t.Log("effective edge verified through actual UpheldBy/Upholds properties")
	} else {
		t.Log("effective edge verified through actual legacy PID-1 Manager.Dump observations for both selected units")
	}
	t.Log("actual effective Upholds edge rejected before helper dispatch; original upholder cleanup uses its retained pidfd only")
}

// Production correctly refuses this unit's deliberately nonempty outgoing
// Upholds. The fixture explicitly attests that one declared extension, then
// checks every other actual property and the original process with the same
// production primitives. No unknown graph property is normalized away.
func pinDisposableUpholder(ctx context.Context, upholder, target unitSpec, before, after uint64) (*processPin, error) {
	inspect := func() (map[string]string, error) {
		values, err := queryUnit(ctx, upholder.Name)
		if err != nil {
			return nil, err
		}
		if err := verifyDisposableUpholdsEdge(ctx, upholder, target, values); err != nil {
			return nil, err
		}
		checked := make(map[string]string, len(values))
		for key, value := range values {
			checked[key] = value
		}
		if _, supported := checked["Upholds"]; supported {
			// Only the exact, independently observed fixture edge is allowed.
			checked["Upholds"] = ""
		}
		if err := verifyUnitProperties(checked, upholder); err != nil {
			return nil, err
		}
		return values, nil
	}
	values, err := inspect()
	if err != nil {
		return nil, err
	}
	pid, err := strconv.Atoi(values["MainPID"])
	if err != nil || pid <= 1 {
		return nil, errors.New("original upholder PID invalid")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, errors.New("original upholder pidfd unavailable")
	}
	pin := &processPin{fd: fd}
	confirmed := false
	defer func() {
		if !confirmed {
			pin.Close()
		}
	}()
	first, err := observeProcess(pid, upholder, values)
	if err != nil || first.StartMonotonicUSec < before || first.StartMonotonicUSec > after {
		return nil, errors.New("original upholder process or start interval unverified")
	}
	again, err := inspect()
	if err != nil || again["MainPID"] != values["MainPID"] {
		return nil, errors.New("original upholder unit changed during readback")
	}
	second, err := observeProcess(pid, upholder, again)
	if err != nil || second != first || pin.alive() != nil {
		return nil, errors.New("original upholder process changed during readback")
	}
	pin.Observation = first
	confirmed = true
	return pin, nil
}

func verifyDisposableUpholdsEdge(ctx context.Context, upholder, target unitSpec, observed map[string]string) error {
	targetValues, err := queryUnit(ctx, target.Name)
	if err != nil {
		return err
	}
	if incoming, supported := targetValues["UpheldBy"]; supported {
		if incoming != upholder.Name || observed["Upholds"] != target.Name {
			return errors.New("actual disposable Upholds edge does not match both exact unit names")
		}
		return nil
	}
	versionRaw, err := managerCommand(ctx, "systemctl", "--system", "show", "--property=Version", "--no-pager", "--all")
	if err != nil {
		return err
	}
	version, valid := systemdunit.ParseVersion(versionRaw)
	if !valid || (version != 249 && version != 250) {
		return errors.New("missing UpheldBy property outside the proven legacy manager versions")
	}
	targetGraph, err := readLegacyUnitGraph(ctx, target.Name, version)
	if err != nil || !targetGraph.Present || !targetGraph.IncomingUpholds || targetGraph.OutgoingUpholds {
		return errors.New("actual legacy manager dump does not attest the selected target's incoming Upholds")
	}
	upholderGraph, err := readLegacyUnitGraph(ctx, upholder.Name, version)
	if err != nil || !upholderGraph.Present || !upholderGraph.OutgoingUpholds || upholderGraph.IncomingUpholds {
		return errors.New("actual legacy manager dump does not attest the original upholder's outgoing Upholds")
	}
	return nil
}

// Fixture-only diagnostics expose validated environment KEY NAMES, never
// values or raw manager output. They do not alter production admission.
func logDisposableManagerEnvironment(t *testing.T, ctx context.Context) {
	t.Helper()
	raw, err := managerCommand(ctx, "systemctl", "--system", "show", "--property=Environment", "--no-pager", "--all")
	if err != nil {
		t.Log("manager_environment_diagnostic=query_unavailable")
		return
	}
	defer clear(raw)
	properties, err := parseProperties(raw)
	if err != nil {
		t.Log("manager_environment_diagnostic=property_parse_invalid")
		return
	}
	environment, present := properties["Environment"]
	if !present {
		t.Log("manager_environment_diagnostic=property_missing")
		return
	}
	keys, invalid := diagnosticEnvironmentKeys(environment)
	var rejected []string
	for _, key := range keys {
		// Probe only the name with a harmless synthetic value. This tells
		// whether the current policy rejects a key without printing its value.
		if !safeManagerEnvironment(key + "=C") {
			rejected = append(rejected, key)
		}
	}
	t.Logf("manager_environment_diagnostic=property_present policy_accepted=%t key_names=%v key_probe_rejected=%v malformed_or_bounded=%t",
		safeManagerEnvironment(environment), keys, rejected, invalid)
}

func diagnosticEnvironmentKeys(raw string) ([]string, bool) {
	if len(raw) > 16<<10 {
		return nil, true
	}
	var keys []string
	seen := make(map[string]bool)
	invalid := false
	start, quote, escaped := -1, byte(0), false
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || (quote == 0 && !escaped && (raw[i] == ' ' || raw[i] == '\t')) {
			if start >= 0 {
				field := raw[start:i]
				if len(field) >= 2 && (field[0] == '"' || field[0] == '\'') && field[len(field)-1] == field[0] {
					field = field[1 : len(field)-1]
				}
				key, _, hasValue := strings.Cut(field, "=")
				valid := hasValue && len(key) > 0 && len(key) <= 64
				for j, ch := range key {
					if !(ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || j > 0 && ch >= '0' && ch <= '9') {
						valid = false
					}
				}
				if valid && !seen[key] && len(keys) < 64 {
					keys = append(keys, key)
					seen[key] = true
				} else {
					invalid = true
				}
				start = -1
			}
			if i == len(raw) {
				invalid = invalid || quote != 0 || escaped
				break
			}
			continue
		}
		if start < 0 {
			start = i
		}
		ch := raw[i]
		if escaped {
			escaped = false
		} else if ch == '\\' {
			escaped = true
		} else if quote != 0 {
			if ch == quote {
				quote = 0
			}
		} else if ch == '"' || ch == '\'' {
			quote = ch
		}
	}
	slices.Sort(keys)
	return keys, invalid
}

func TestDisposableEnvironmentDiagnosticsNamesOnly(t *testing.T) {
	keys, invalid := diagnosticEnvironmentKeys(`LANG=C "PRIVATE_VALUE=secret with OTHER=hidden" PATH=/usr/bin`)
	if invalid || !slices.Equal(keys, []string{"LANG", "PATH", "PRIVATE_VALUE"}) {
		t.Fatal("quoted environment values were not kept out of diagnostic names")
	}
	keys, invalid = diagnosticEnvironmentKeys("LANG=C INVALID-SECRET=value LANG=C")
	if !invalid || !slices.Equal(keys, []string{"LANG"}) {
		t.Fatal("malformed or duplicated names were not bounded without exposing values")
	}
}

func pinDisposableExecutable(t *testing.T) (string, unix.Stat_t) {
	t.Helper()
	if err := trustedDirectoryChain("/usr/bin"); err != nil {
		t.Fatalf("fixture executable directory is untrusted: %v", err)
	}
	fd, err := unix.Open("/usr/bin/sleep", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open original fixture executable without following links: %v", err)
	}
	file := os.NewFile(uintptr(fd), "original-sleep")
	// Registered before process cleanup: LIFO keeps this descriptor alive
	// until the original child has been observed and terminated by pidfd.
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close original executable descriptor: %v", err)
		}
	})
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != 0 || st.Mode&0o022 != 0 || st.Mode&0o111 == 0 || st.Mode&0o6000 != 0 || st.Nlink != 1 {
		t.Fatal("fixture original executable is not a singly linked root-controlled regular executable")
	}
	// Exercise the same retained-descriptor execution boundary as the
	// production helper, including the actual systemd sandbox permissions.
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd), st
}

func disposableRunNumber(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
		t.Fatalf("canonical positive %s required", key)
	}
	return value
}

func disposeOriginalProcess(t *testing.T, pin *processPin) {
	t.Helper()
	defer func() {
		if err := pin.Close(); err != nil {
			t.Errorf("close original process pin: %v", err)
		}
	}()
	if err := unix.PidfdSendSignal(pin.fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		t.Errorf("original pidfd termination failed; no name-based cleanup attempted: %v", err)
		return
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		fds := []unix.PollFd{{Fd: int32(pin.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 200)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Errorf("original pidfd exit verification failed: %v", err)
			return
		}
		if n > 0 && fds[0].Revents&unix.POLLIN != 0 {
			return
		}
	}
	t.Error("original bounded fixture exit was not confirmed; no other process was signaled")
}
