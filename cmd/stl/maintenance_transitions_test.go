package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestUninstallRetiresOnlyVerifiedSTLLocks(t *testing.T) {
	trust := func(string) error { return nil }
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	locks := filepath.Join(root, "locks")
	if err := os.Mkdir(locks, 0o700); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(locks, strings.Repeat("f", 64)+".lock")
	if err := os.WriteFile(generated, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	foreign := filepath.Join(locks, "foreign.lock")
	if err := os.WriteFile(foreign, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := retireOrphanStateRoot(root, trust); err == nil {
		t.Fatal("foreign lock deleted")
	}
	if _, err := os.Lstat(generated); err != nil {
		t.Fatal("known lock modified after refusal", err)
	}
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatal("foreign lock modified after refusal", err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}

	if err := retireOrphanStateRoot(root, trust); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("verified lock-only root not retired: %v", err)
	}
	if err := retireOrphanStateRoot(root, trust); err != nil {
		t.Fatalf("idempotent missing root: %v", err)
	}

	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte(`{"schema_version":4,"links":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := retireOrphanStateRoot(root, trust); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "state.json")); err != nil {
		t.Fatal("committed State deleted", err)
	}
}

func TestEmptyStateVersionedDowngradeIsLosslessAndPrivate(t *testing.T) {
	for _, tc := range []struct {
		name, raw, target string
		ok                bool
		want              int
	}{
		{"v4 to v3", `{"schema_version":4,"links":[]}`, "v0.1.9", true, 3},
		{"v4 to v4", `{"schema_version":4,"links":[]}`, "v0.1.10", true, 4},
		{"already v3", `{"schema_version":3,"links":[]}`, "v0.1.9", true, 3},
		{"unknown target", `{"schema_version":4,"links":[]}`, "v0.1.7", false, 4},
		{"pending journal", `{"schema_version":4,"links":[],"wss_crash_operations":[{"private":"do-not-drop"}]}`, "v0.1.9", false, 4},
		{"foreign field", `{"schema_version":4,"links":[],"unrecognized":42}`, "v0.1.9", false, 4},
		{"active link", `{"schema_version":4,"links":[{"id":"must-not-drop"}]}`, "v0.1.9", false, 4},
		{"unknown version", `{"schema_version":999,"links":[]}`, "v0.1.9", false, 999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "state.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			err := stageEmptyStateForDowngrade(root, tc.target)
			if tc.ok && err != nil || !tc.ok && err == nil {
				t.Fatalf("unexpected stage result: ok=%v err=%v", tc.ok, err)
			}
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("State removed", err)
			}
			if !tc.ok && string(current) != tc.raw {
				t.Fatal("unsafe input State changed despite refusal")
			}
			if tc.ok {
				store := state.NewFileStore(root)
				snap, err := store.Load(context.Background())
				if err != nil || !uninstallSnapshotEmpty(snap) {
					t.Fatalf("downlevel State not readable: %v", err)
				}
			}
		})
	}
}

func TestCanonicalInstallerInheritanceMustMatchExactLockedInode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "maintenance.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := installerLockInherited(int(f.Fd()), path); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installerLockInherited(int(f.Fd()), other); err == nil {
		t.Fatal("different lock identity admitted")
	}
	if err := installerLockInherited(-1, path); err == nil {
		t.Fatal("missing installer lock admitted")
	}
}

func TestEmptyStateDowngradeCannotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(external, []byte(`{"schema_version":4,"links":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := stageEmptyStateForDowngrade(root, "v0.1.9"); err == nil {
		t.Fatal("symlinked State was replaced")
	}
	raw, err := os.ReadFile(external)
	if err != nil || !strings.Contains(string(raw), "schema_version") {
		t.Fatal(err)
	}
}

func TestUnsupportedPublishedStateSchemaIsExplicit(t *testing.T) {
	for _, tag := range []string{"v0.1.7", "v1.0.0", "v0.1.9-rc.1", "latest", "../main"} {
		if _, err := publishedStateSchema(tag); err == nil {
			t.Fatalf("unsupported target granted schema authority: %s", tag)
		}
	}
	for _, tc := range []struct {
		tag    string
		schema int
	}{
		{"v0.1.8", 3}, {"v0.1.9", 3}, {"v0.1.10", 4}, {"v0.1.12", 4},
	} {
		got, err := publishedStateSchema(tc.tag)
		if err != nil || got != tc.schema {
			t.Fatalf("schema %s: %d %v", tc.tag, got, err)
		}
	}
	if err := stageEmptyStateForDowngrade(filepath.Join(t.TempDir(), "absent"), "v0.1.9"); err != nil {
		t.Fatal(err)
	}
}
