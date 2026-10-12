package ipsec

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestIsolatedNativeExclusivePublication is NEVER run on a connected
// Linux host. Its only purpose is to provision fixture-owned files inside
// an explicitly authorized ephemeral, disconnected systemd Docker container.
// It does not install packages, stop vendor services, start a daemon or
// authorize future mutation; actual runtime admission remains independent.
func TestIsolatedNativeExclusivePublication(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_SYSTEMD_FIXTURE") != "approved" {
		t.Skip("requires explicit isolated disposable systemd fixture approval")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native fixture requires container root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("native fixture must be inside Docker")
	}
	cmd := exec.CommandContext(context.Background(), "/usr/sbin/ip", "-4", "route", "show", "default")
	route, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(route)) != "" {
		t.Fatal("native fixture must have no default route")
	}
	enabled, err := exec.CommandContext(context.Background(), "/usr/bin/systemctl", "is-enabled", "strongswan.service").CombinedOutput()
	if strings.TrimSpace(string(enabled)) != "disabled" {
		t.Fatalf("vendor service must be disabled in the disposable image, status=%q exit=%v", enabled, err)
	}
	active, err := exec.CommandContext(context.Background(), "/usr/bin/systemctl", "is-active", "strongswan.service").CombinedOutput()
	if strings.TrimSpace(string(active)) != "inactive" {
		t.Fatalf("vendor daemon must be inactive before source publication, status=%q exit=%v", active, err)
	}
	if err := verifyNoForeignStrongSwanProcess(0); err != nil {
		t.Fatal("existing foreign daemon prevents native fixture publication")
	}
	if err := publishNativeConfigAt("/", 0, nativePublishHooks{}); err != nil {
		t.Fatalf("protected no-replace config publication rejected: %v", err)
	}
	if err := publishNativeUnitAt("/", 0, nativeUnitPublishHooks{}); err != nil {
		t.Fatalf("protected no-replace service unit publication rejected: %v", err)
	}
	if InspectNativeExclusiveConfigOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveConfig() != NativeConfigExact ||
		InspectNativeExclusiveServiceUnit() != NativeServiceUnitExact {
		t.Fatal("published native config/unit origin receipt did not verify")
	}
	if err := publishNativeConfigAt("/", 0, nativePublishHooks{}); err == nil {
		t.Fatal("repeated source publication was allowed to adopt or replace existing config")
	}
	if err := publishNativeUnitAt("/", 0, nativeUnitPublishHooks{}); err == nil {
		t.Fatal("repeated source publication was allowed to adopt or replace existing unit")
	}
	t.Log("ISOLATED_NATIVE_SYSTEMD_SOURCE_ORIGIN=PASS")
}

// TestIsolatedNativeExclusiveRuntimeAdmission checks the actual effective
// systemd unit, root-owned config receipts, daemon process and VICI peer.
// It is read-only and only runs inside a disconnected disposable fixture.
func TestIsolatedNativeExclusiveRuntimeAdmission(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_SYSTEMD_FIXTURE") != "approved" {
		t.Skip("requires isolated native-exclusive systemd fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires isolated root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("Docker marker missing")
	}
	route, err := exec.Command("/usr/sbin/ip", "-4", "route", "show", "default").Output()
	if err != nil || strings.TrimSpace(string(route)) != "" {
		t.Fatal("fixture must have no default route")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admission := NewNativeRuntimeAdmission()
	for pass := 1; pass <= 8; pass++ {
		if err := admission.Authorize(ctx); err != nil {
			t.Fatalf("ISOLATED_NATIVE_SYSTEMD_RUNTIME_ADMISSION_SAMPLE_%d=FAIL: %v", pass, err)
		}
	}
	t.Log("ISOLATED_NATIVE_SYSTEMD_RUNTIME_ADMISSION_8_REPEATS=PASS")
}
