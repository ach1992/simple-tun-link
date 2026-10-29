package linux

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is the real renderer, unlike old tests that treated any copied marker
// as owned. Historical officially published v0.1.8-v0.1.12 units use exactly
// this template, including their complete systemd directive inventory.
func ownedRestoreUnitFixture(t *testing.T, executable string) []byte {
	t.Helper()
	contents, err := renderRestoreSystemdUnit(executable)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(contents)
}

// Simulate a root-owned, protected /etc/systemd/system inode in a disposable
// user-owned fixture. Production has NO trust override; the test-only path
// verifier supplies root UID=0 for every real canonical chain component.
func fixtureRootOwnedUnitTrust(t *testing.T, path string) func(string) error {
	t.Helper()
	tree := map[string]fakeInstallInfo{
		path: {path: path, mode: 0o644},
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		tree[parent] = fakeInstallInfo{path: parent, mode: fs.ModeDir | 0o755}
		if parent == "/" {
			break
		}
	}
	return func(unit string) error {
		return verifyTrustedSystemdUnitPath(unit, func(name string) (fs.FileInfo, error) {
			info, ok := tree[name]
			if !ok {
				return nil, os.ErrNotExist
			}
			return info, nil
		})
	}
}

// Previously, IsRestoreInstalled and RemoveRestore accepted any root-owned
// marker-prefixed text and could disable a foreign service. In particular,
// the marker plus extra independent systemd directives was wrongly accepted.
// No systemctl call whatsoever is permitted after this ambiguous admission.
func TestForeignMarkerPrefixedRestoreUnitCannotBeAdoptedOrRemoved(t *testing.T) {
	canonical := string(ownedRestoreUnitFixture(t, "/usr/local/bin/stl"))
	for _, tc := range []struct {
		name, unit string
	}{
		{"marker with independently authored ExecStart",
			strings.Replace(canonical, "ExecStart=/usr/local/bin/stl link restore --all", "ExecStart=/usr/bin/false", 1)},
		{"marker with independently authored service directives",
			strings.Replace(canonical, "[Install]", "ExecStartPost=/usr/bin/true\n[Install]", 1)},
		{"marker with alternative service privileges",
			strings.Replace(canonical, "Type=oneshot", "Type=oneshot\nUser=nobody", 1)},
		{"marker with duplicate ExecStart",
			strings.Replace(canonical, "[Install]", "ExecStart=/usr/bin/true\n[Install]", 1)},
		{"marker with different systemd boot ordering",
			strings.Replace(canonical, "WantedBy=multi-user.target", "WantedBy=default.target", 1)},
		{"marker only with no valid template",
			managedSystemdMarker + "\n[Unit]\nDescription=unrelated service\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, restoreSystemdUnitName)
			if err := os.WriteFile(path, []byte(tc.unit), 0o644); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
			manager := SystemdPersistence{
				Runner: runner, UnitDir: dir,
				VerifyExecutable: func(string) error { return nil },
				VerifyUnitPath:   fixtureRootOwnedUnitTrust(t, path),
			}
			if accepted, err := manager.IsRestoreInstalled(context.Background()); err == nil || accepted {
				t.Fatalf("foreign marker accepted for orphan retirement: %t %v", accepted, err)
			}
			if err := manager.RemoveRestore(context.Background()); err == nil {
				t.Fatal("foreign marker authorized systemd disable/removal")
			}
			if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
				t.Fatal("foreign marker authorized overwrite during EnsureRestore")
			}
			if len(runner.commands) != 0 || !runner.enabled[restoreSystemdUnitName] {
				t.Fatalf("foreign unit reached systemctl or lost enablement: %v", runner.commands)
			}
			now, err := os.Lstat(path)
			if err != nil || !os.SameFile(now, before) {
				t.Fatalf("foreign unit inode changed: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != tc.unit {
				t.Fatalf("foreign unit contents changed: %v", err)
			}
		})
	}
}

func TestProductionRestoreUnitMustMatchCanonicalInstalledExecutable(t *testing.T) {
	defaultManager := SystemdPersistence{}
	for _, alt := range []string{"/opt/stl/stl", "/usr/local/sbin/stl"} {
		other := ownedRestoreUnitFixture(t, alt)
		if !isOwnedSystemdUnit(other) {
			t.Fatalf("alternate exact renderer rejected in isolated fixture: %s", alt)
		}
		if defaultManager.trustsRestoreUnitContent(other) {
			t.Fatalf("production restore unit admitted noncanonical installed executable: %s", alt)
		}
	}
	official := ownedRestoreUnitFixture(t, "/usr/local/bin/stl")
	if !defaultManager.trustsRestoreUnitContent(official) {
		t.Fatal("exact official installed unit was rejected")
	}
}

func TestExactCanonicalOrphanUnitCanStillBeRetired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	content := ownedRestoreUnitFixture(t, "/usr/local/bin/stl")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyUnitPath: fixtureRootOwnedUnitTrust(t, path),
	}
	present, err := manager.IsRestoreInstalled(context.Background())
	if err != nil || !present {
		t.Fatalf("exact canonical unit was not recognized: %v", err)
	}
	if err := manager.RemoveRestore(context.Background()); err != nil {
		t.Fatalf("exact canonical owned orphan removal failed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned unit was not removed: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("owned unit enablement remains enabled")
	}
	expectSystemdOperations(t, runner.commands,
		"systemctl is-enabled ", "systemctl disable ", "systemctl is-enabled ",
		"systemctl daemon-reload", "systemctl is-enabled ")
}

// systemctl may disable the exact owned unit and still return an error.
// The existing compensation path must restore prior enablement and retain
// the original inode rather than turning uncertain failure into deletion.
type partialDisableErrorRunner struct {
	recordingRunner
	failed bool
}

func (r *partialDisableErrorRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	out, err := r.recordingRunner.Run(ctx, name, args...)
	if len(args) == 2 && args[0] == "disable" && !r.failed {
		r.failed = true
		return out, errors.New("injected failure after disabling owned unit")
	}
	return out, err
}

func TestFailedDisableAfterSideEffectRestoresOriginalOwnedUnit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	content := ownedRestoreUnitFixture(t, "/usr/local/bin/stl")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	runner := &partialDisableErrorRunner{
		recordingRunner: recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}},
	}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyUnitPath: fixtureRootOwnedUnitTrust(t, path),
	}
	if err := manager.RemoveRestore(context.Background()); err == nil || !runner.failed {
		t.Fatalf("post-disable failure was ignored: %v", err)
	}
	got, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, got) {
		t.Fatalf("failed removal lost original owned inode: %v", err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("failed disable did not compensate original enablement")
	}
	readback, err := os.ReadFile(path)
	if err != nil || string(readback) != string(content) {
		t.Fatalf("failed disable changed original content: %v", err)
	}
	expectSystemdOperations(t, runner.commands,
		"systemctl is-enabled ", "systemctl disable ",
		"systemctl daemon-reload", "systemctl enable ", "systemctl is-enabled ")
}
