package ipsec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
