package ipsec

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Read-only verifier for existing fixtures in a separate, disconnected
// disposable PID1-systemd guest. The fixture driver alone owns guest reloads
// and file creation. Nothing in this test changes a service or host file.
func TestIsolatedNativeMissingVendorFixture(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_SYSTEMD_FIXTURE") != "approved" {
		t.Skip("not a separately approved isolated systemd guest")
	}
	kind := os.Getenv("STL_IPSEC_VENDOR_MISSING_CASE")
	if kind != "clean" && kind != "prefix" && kind != "alias" && kind != "sysv" {
		t.Skip("no recognized vendor-missing fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires disposable guest root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires a disposable Docker guest")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		t.Fatal("requires real PID1 systemd")
	}
	route, err := exec.Command("/usr/sbin/ip", "-4", "route", "show", "default").Output()
	if err != nil || strings.TrimSpace(string(route)) != "" {
		t.Fatal("disposable guest must have no default network route")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	const name = "charon-systemd.service"
	absent := nativeVendorUnitVerifiedMissing(ctx, name)
	if (kind == "clean") != absent {
		t.Fatalf("systemd %s fixture returned verified-missing=%t", kind, absent)
	}
	if kind != "clean" {
		result, err := interpretNativeVendorUnitState(ctx, "is-enabled", name,
			[]byte("not-found\n"), nil, 1, nativeVendorUnitVerifiedMissing)
		if err == nil || result != "" {
			t.Fatalf("systemd %s fixture admitted foreign identity via fallback: %q %v", kind, result, err)
		}
	}
	if kind == "sysv" {
		out, err := exec.CommandContext(ctx, nativeSystemctlBinary,
			"--system", "--no-pager", "show", name, "-p", "LoadState", "-p", "SourcePath").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "LoadState=loaded") ||
			!strings.Contains(string(out), "/etc/init.d/charon-systemd") {
			t.Fatalf("systemd SysV generator fixture not actually loaded: state=%q err=%v", out, err)
		}
	}
	t.Logf("NATIVE_VENDOR_MISSING_%s_SYSTEMD=PASS", strings.ToUpper(kind))
}
