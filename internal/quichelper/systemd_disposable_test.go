//go:build linux

package quichelper

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

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
	t.Log("actual transient first-start, process pin, collision denial and strict unit-property evidence passed; no managed QUIC Link was created")
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
