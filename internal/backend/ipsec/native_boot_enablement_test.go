package ipsec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedNativeBootEnablementRequiresExactRootControlledWantsEdge(t *testing.T) {
	root := t.TempDir()
	owner := uint32(os.Getuid())
	unitDir := filepath.Join(root, "etc", "systemd", "system")
	wants := filepath.Join(unitDir, "multi-user.target.wants")
	if err := os.MkdirAll(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(unitDir, nativeUnitName)
	if err := os.WriteFile(unit, NativeExclusiveServiceUnitV1(), 0o600); err != nil {
		t.Fatal(err)
	}
	edge := filepath.Join(wants, nativeUnitName)
	check := func(expected bool) {
		t.Helper()
		if got := trustedNativeBootEnablementAt(root, owner); got != expected {
			t.Fatalf("boot-enable attestation=%t, expected=%t", got, expected)
		}
	}
	check(false)
	if err := os.Symlink(NativeExclusiveServiceUnitPath, edge); err != nil {
		t.Fatal(err)
	}
	check(true)
	for _, target := range []string{"../" + nativeUnitName, "/etc/systemd/system/strongswan.service", "/tmp/foreign.service"} {
		if err := os.Remove(edge); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, edge); err != nil {
			t.Fatal(err)
		}
		check(false)
	}
	if err := os.Remove(edge); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(NativeExclusiveServiceUnitPath, edge); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wants, 0o777); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err := os.Chmod(wants, 0o755); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", unit); err != nil {
		t.Fatal(err)
	}
	check(false)
}
