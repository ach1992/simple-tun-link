package ipsec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A disposable, disconnected PID1-systemd guest deliberately sets the
// manager-wide LD_PRELOAD. The library's constructor creates a marker only
// if the root charon-systemd executable is actually launched. No production
// host or vendor systemd environment is ever modified by this fixture.
func TestIsolatedNativePreStartRejectsManagerEnvironmentWithoutExecuting(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_SYSTEMD_FIXTURE") != "approved" ||
		os.Getenv("STL_IPSEC_MANAGER_ENV_NEGATIVE") != "approved" {
		t.Skip("requires explicit disposable manager-environment acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("manager-environment test requires guest root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("manager-environment test must run only in Docker guest")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		t.Fatal("manager-environment test requires PID1 systemd")
	}
	route, err := exec.Command("/usr/sbin/ip", "-4", "route", "show", "default").Output()
	if err != nil || strings.TrimSpace(string(route)) != "" {
		t.Fatal("manager-environment guest must be disconnected")
	}
	const library = "/usr/local/lib/stl-manager-preload.so"
	const marker = "/run/stl-manager-env-charon-executed"
	lib, err := os.Lstat(library)
	if err != nil || !lib.Mode().IsRegular() {
		t.Fatal("preload test library missing from private guest runtime")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign execution marker must not exist before injection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	// Calibrate the otherwise-negative marker using a harmless copied true
	// executable with the same basename, never the real IKE daemon.
	const calibrator = "/run/charon-systemd"
	if err := exec.CommandContext(ctx, "/usr/bin/cp", "/usr/bin/true", calibrator).Run(); err != nil {
		t.Fatalf("disposable preload signal calibration unavailable: %v", err)
	}
	probe := exec.CommandContext(ctx, calibrator)
	probe.Env = append(os.Environ(), "LD_PRELOAD="+library)
	if err := probe.Run(); err != nil {
		t.Fatalf("disposable preload calibration failed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("preload constructor marker not functional in guest")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal("cannot clear disposable calibration marker")
	}
	if err := os.Remove(calibrator); err != nil {
		t.Fatal("cannot remove disposable calibration executable")
	}
	if err := NativeProvisionReadiness(ctx); err != nil {
		t.Fatalf("disposable manager env fixture cannot reach production path: %v", err)
	}
	// Only the inside-guest PID1 is modified and the container is destroyed
	// after this test. Never unset or edit the administrator's real manager.
	if out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "set-environment",
		"LD_PRELOAD="+library).CombinedOutput(); err != nil {
		t.Fatalf("guest manager environment injection failed: %v", err)
	} else {
		clear(out)
	}
	if err := NewNativeRuntimeAdmission().attestManagerEnvironment(ctx); err == nil {
		t.Fatal("production D-Bus manager inspector missed planted LD_PRELOAD")
	}
	if err := ProvisionNativeExclusive(ctx); err == nil ||
		!strings.Contains(err.Error(), "PRE-START") {
		t.Fatalf("manager override was not denied before production service start: %v", err)
	}
	if InspectNativeExclusiveConfigOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginVerified {
		t.Fatal("manager-environment denial did not retain protected publication receipts")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign preload constructor ran in root charon-systemd: %v", err)
	}
	if trustedNativeBootEnablementAt("/", 0) {
		t.Fatal("manager-environment denial created an unverified boot edge")
	}
	status, err := exec.CommandContext(ctx, "/usr/bin/systemctl",
		"--system", "is-active", nativeServiceName).CombinedOutput()
	if err == nil || (strings.TrimSpace(string(status)) != "inactive" &&
		strings.TrimSpace(string(status)) != "failed") {
		t.Fatalf("unverified private service became active: status=%q err=%v", status, err)
	}
	if err := ProvisionNativeExclusive(ctx); err == nil {
		t.Fatal("partially published sources were blindly adopted on second attempt")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign preload executed after denied retry")
	}
	t.Log("NATIVE_MANAGER_ENV_LD_PRELOAD_REJECTED_BEFORE_START=PASS")
	t.Log("NATIVE_MANAGER_ENV_CHARON_MARKER_NEVER_EXECUTED=PASS")
	t.Log("NATIVE_MANAGER_ENV_NO_BOOT_EDGE=PASS")
	t.Log("NATIVE_MANAGER_ENV_RETRY_FAIL_CLOSED=PASS")
}
