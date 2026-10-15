package ipsec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This test intentionally plants a harmless foreign ExecStartPre in a fresh,
// network-disconnected, privileged PID1-systemd Docker guest ONLY. It must
// never execute or mutate a live host. It proves the actual producer refuses
// before systemd can execute the planted command.
func TestIsolatedNativePreStartRejectsForeignDropInWithoutExecuting(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_SYSTEMD_FIXTURE") != "approved" ||
		os.Getenv("STL_IPSEC_PRESTART_NEGATIVE") != "approved" {
		t.Skip("requires explicit disposable foreign-unit acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("pre-start test requires isolated guest root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("pre-start test must run only inside Docker guest")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		t.Fatal("pre-start test requires isolated systemd PID1")
	}
	route, err := exec.Command("/usr/sbin/ip", "-4", "route", "show", "default").Output()
	if err != nil || strings.TrimSpace(string(route)) != "" {
		t.Fatal("pre-start guest must be disconnected from external networks")
	}
	const marker = "/run/stl-foreign-execstartpre-marker"
	dropinDir := filepath.Join("/etc/systemd/system", nativeServiceName+".d")
	if err := os.MkdirAll(dropinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropinDir, "foreign.conf"),
		[]byte("[Service]\nExecStartPre=/usr/bin/touch "+marker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if err := NativeProvisionReadiness(ctx); err != nil {
		t.Fatalf("pre-start test did not reach publication path: %v", err)
	}
	if err := ProvisionNativeExclusive(ctx); err == nil ||
		!strings.Contains(err.Error(), "PRE-START") {
		t.Fatalf("foreign drop-in was not refused by pre-start systemd attestation: %v", err)
	}
	if InspectNativeExclusiveConfigOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginVerified {
		t.Fatal("negative fixture did not publish protected sources before loaded-unit attestation")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign ExecStartPre marker was executed: %v", err)
	}
	if trustedNativeBootEnablementAt("/", 0) {
		t.Fatal("denied service would automatically start on a future reboot")
	}
	s, err := exec.Command("/usr/bin/systemctl", "--system", "is-active", nativeServiceName).CombinedOutput()
	if err == nil || (strings.TrimSpace(string(s)) != "inactive" &&
		strings.TrimSpace(string(s)) != "failed") {
		t.Fatalf("unverified private service unexpectedly active: %q %v", s, err)
	}
	if err := ProvisionNativeExclusive(ctx); err == nil {
		t.Fatal("partial protected publication was blindly retried or adopted")
	}
	t.Log("NATIVE_FOREIGN_DROPIN_REJECTED_BEFORE_START=PASS")
	t.Log("NATIVE_FOREIGN_MARKER_NOT_EXECUTED=PASS")
	t.Log("NATIVE_NO_UNVERIFIED_BOOT_EDGE=PASS")
}
