package linux

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInterfaceSysctlSetAndRollback(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "net", "ipv4", "conf", "stl0", "rp_filter")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	undo, changed, err := (InterfaceSysctl{ProcRoot: root}).Set(context.Background(), "ipv4", "stl0", "rp_filter", "0")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected sysctl change")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "0" {
		t.Fatalf("value = %q, want 0", got)
	}
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "1" {
		t.Fatalf("rolled-back value = %q, want 1", got)
	}
}

func TestInterfaceSysctlRejectsGlobalPseudoInterfaces(t *testing.T) {
	for _, name := range []string{"all", "default"} {
		if _, _, err := (InterfaceSysctl{ProcRoot: t.TempDir()}).Set(context.Background(), "ipv4", name, "rp_filter", "0"); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}

func TestInterfaceSysctlIsIdempotent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "net", "ipv6", "conf", "stl0", "disable_policy")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, changed, err := (InterfaceSysctl{ProcRoot: root}).Set(context.Background(), "ipv6", "stl0", "disable_policy", "1")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("equal sysctl should not be rewritten")
	}
}

func TestInterfaceSysctlRejectsUnsafeInterfaceNames(t *testing.T) {
	for _, name := range []string{"../eth0", "eth0/../all", "eth 0", "eth0:1", ""} {
		if _, _, err := (InterfaceSysctl{ProcRoot: t.TempDir()}).Set(context.Background(), "ipv4", name, "rp_filter", "0"); err == nil {
			t.Fatalf("expected interface name %q to be rejected", name)
		}
	}
}

func TestInterfaceSysctlRejectsUnapprovedNamesFamiliesAndValues(t *testing.T) {
	manager := InterfaceSysctl{ProcRoot: t.TempDir()}
	cases := []struct {
		family string
		name   string
		value  string
	}{
		{family: "ipv4", name: "ip_forward", value: "1"},
		{family: "ipv6", name: "rp_filter", value: "0"},
		{family: "ipv4", name: "rp_filter", value: "3"},
		{family: "ipv4", name: "disable_policy", value: "-1"},
	}
	for _, tc := range cases {
		if _, _, err := manager.Set(context.Background(), tc.family, "stl0", tc.name, tc.value); err == nil {
			t.Fatalf("expected %s/%s=%s to be rejected", tc.family, tc.name, tc.value)
		}
	}
}
