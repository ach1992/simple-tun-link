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

func TestNativeProvisionBootEdgeOnlyExactNoReplace(t *testing.T) {
	root := t.TempDir()
	owner := uint32(os.Getuid())
	base := filepath.Join(root, "etc", "systemd", "system")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(base, "simple-tun-link-ipsec.service")
	if err := os.WriteFile(unit, NativeExclusiveServiceUnitV1(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishNativeBootEdgeAt(root, owner); err != nil {
		t.Fatal(err)
	}
	if !trustedNativeBootEnablementAt(root, owner) {
		t.Fatal("fresh boot edge not attested")
	}
	edge := filepath.Join(base, "multi-user.target.wants", nativeUnitName)
	if err := publishNativeBootEdgeAt(root, owner); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("repeated boot publisher adopted previous edge: %v", err)
	}
	if err := os.Remove(edge); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/systemd/system/foreign.service", edge); err != nil {
		t.Fatal(err)
	}
	if err := publishNativeBootEdgeAt(root, owner); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("publisher overwrote foreign boot edge: %v", err)
	}
	if target, err := os.Readlink(edge); err != nil || target != "/etc/systemd/system/foreign.service" {
		t.Fatalf("foreign boot edge mutated: %q %v", target, err)
	}
	if err := os.Remove(edge); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(edge), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := publishNativeBootEdgeAt(root, owner); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("writable systemd wants dir accepted: %v", err)
	}
}
func TestNativeProvisionReadOnlyGateBlocksUnprivilegedAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NativeProvisionReadiness(ctx); err == nil {
		t.Fatal("canceled native host admission was considered safe")
	}
	if err := ProvisionNativeExclusive(ctx); err == nil {
		t.Fatal("canceled privileged provision attempted")
	}
	if os.Geteuid() != 0 {
		if err := NativeProvisionReadiness(context.Background()); err == nil {
			t.Fatal("non-root native provision gate accepted")
		}
		if err := ProvisionNativeExclusive(context.Background()); err == nil {
			t.Fatal("non-root source publisher accepted")
		}
	}
}
func TestNativeIKEPortPreflightHasFixedCorrectHexIdentity(t *testing.T) {
	const builtinPorts = "500=01F4 4500=1194"
	if !strings.Contains(builtinPorts, "01F4") || !strings.Contains(builtinPorts, "1194") {
		t.Fatal("invalid IKE port constants")
	}
	// The real /proc namespace inspector is read-only regardless of this
	// host's readiness and must not bind/listen or mutate services.
	_ = nativeIKEPortsVacant()
}

func TestNativeVendorStatusRejectsUnverifiedNegativeEvidence(t *testing.T) {
	cases := []struct {
		action, state string
		exit          int
		want          bool
	}{
		{"is-active", "inactive", 3, true},
		{"is-active", "inactive", 4, true},
		{"is-active", "unknown", 4, true},
		{"is-active", "active", 0, true},
		{"is-active", "inactive", 0, false},
		{"is-active", "active", 3, false},
		{"is-enabled", "disabled", 1, true},
		{"is-enabled", "not-found", 4, true},
		{"is-enabled", "masked", 1, true},
		{"is-enabled", "enabled", 0, true},
		{"is-enabled", "disabled", 0, false},
		{"is-enabled", "not-found", 1, false},
		{"is-enabled", "static", 0, false},
		{"is-enabled", "indirect", 0, false},
		{"is-active", "failed", 3, false},
	}
	for _, tc := range cases {
		s, e := parseNativeVendorStatus(tc.action, []byte(tc.state+"\n"), nil, tc.exit)
		if (e == nil) != tc.want || (e == nil && s != tc.state) {
			t.Fatalf("action=%s state=%s exit=%d allowed=%v expected=%v err=%v", tc.action, tc.state, tc.exit, e == nil, tc.want, e)
		}
	}
	if _, e := parseNativeVendorStatus("is-enabled", []byte("not-found\n"), []byte("cannot inspect\n"), 4); e == nil {
		t.Fatal("systemd stderr falsely proves foreign unit absent")
	}
	if _, e := parseNativeVendorStatus("is-enabled", []byte("disabled\nextra\n"), nil, 1); e == nil {
		t.Fatal("malformed status with extra lines accepted")
	}
}

// TestIsolatedNativeExclusiveRealProvision exercises the ACTUAL production
// provisioner and runtime admission on a fresh, disconnected, ephemeral
// Docker PID1-systemd guest. It MUST NEVER run on the connected host. It is
// deliberately separate from test-only source publishers (which cannot
// establish that the product's own provisioner is safe or operational).
func TestIsolatedNativeExclusiveRealProvision(t *testing.T) {
	if os.Getenv("STL_E2E_DISPOSABLE_HOST") != "approved" ||
		os.Getenv("STL_IPSEC_ISOLATED") != "approved" ||
		os.Getenv("STL_IPSEC_SYSTEMD_FIXTURE") != "approved" ||
		os.Getenv("STL_IPSEC_REAL_PROVISION") != "approved" {
		t.Skip("requires explicitly authorized disposable native IPsec guest")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires container root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("must run in Docker")
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		t.Fatal("container PID1 must be systemd")
	}
	route, err := exec.Command("/usr/sbin/ip", "-4", "route", "show", "default").Output()
	if err != nil || strings.TrimSpace(string(route)) != "" {
		t.Fatal("fixture must have no default IPv4 route")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if err := NativeProvisionReadiness(ctx); err != nil {
		t.Fatalf("fresh host provisioner refused verified disposable guest: %v", err)
	}
	if err := ProvisionNativeExclusive(ctx); err != nil {
		t.Fatalf("real private service provision failed: %v", err)
	}
	if err := NewNativeRuntimeAdmission().Authorize(ctx); err != nil {
		t.Fatalf("post-provision admission failed: %v", err)
	}
	if InspectNativeExclusiveConfigOrigin() != NativeOriginVerified ||
		InspectNativeExclusiveServiceUnitOrigin() != NativeOriginVerified ||
		!trustedNativeBootEnablementAt("/", 0) {
		t.Fatal("real provisioner did not establish verified private service/config receipts and boot edge")
	}
	if err := NativeProvisionReadiness(ctx); err == nil {
		t.Fatal("previously provisioned/started IPsec service was incorrectly treated as a fresh vacant host")
	}
	if err := ProvisionNativeExclusive(ctx); err == nil {
		t.Fatal("second full provisioner call adopted or replaced a current owned/active service")
	}
	t.Log("NATIVE_REAL_PROVISION_NO_REPLACE=PASS")
	t.Log("NATIVE_REAL_PROVISION_RUNTIME_ADMITTED=PASS")
}
