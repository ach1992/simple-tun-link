package linux

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An inode whose final pathname was removed must still be allocated while
// STL relies on its FileInfo. This checks the actual Linux fd table rather
// than hoping the allocator happens to recycle a particular inode number.
func requireOpenOriginFD(t *testing.T, original os.FileInfo) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, statErr := os.Stat(filepath.Join("/proc/self/fd", entry.Name()))
		if statErr == nil && sameUnitFile(info, original) {
			return
		}
	}
	t.Fatalf("original inode %s lost its final open descriptor before ownership-sensitive operation", original.Name())
}

type canonicalABAInspectionRunner struct {
	recordingRunner
	t        *testing.T
	path     string
	original os.FileInfo
	fired    bool
}

func (r *canonicalABAInspectionRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if !r.fired && len(args) == 2 && args[0] == "is-enabled" {
		r.fired = true
		identical, err := os.ReadFile(r.path)
		if err != nil {
			r.t.Fatal(err)
		}
		if err := os.Remove(r.path); err != nil {
			r.t.Fatal(err)
		}
		requireOpenOriginFD(r.t, r.original)
		if err := os.WriteFile(r.path, identical, 0o644); err != nil {
			r.t.Fatal(err)
		}
		replacement, err := os.Lstat(r.path)
		if err != nil || sameUnitFile(replacement, r.original) {
			r.t.Fatalf("original inode was recycled while still used by STL: %v", err)
		}
	}
	return r.recordingRunner.Run(ctx, name, args...)
}

func TestExistingCanonicalOriginRemainsPinnedAcrossSystemctlInspection(t *testing.T) {
	for _, action := range []string{"ensure", "remove"} {
		t.Run(action, func(t *testing.T) {
			_, path, originalBytes, _, manager := newCompensationFixture(t, true, true)
			original, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			runner := &canonicalABAInspectionRunner{
				t: t, path: path, original: original,
				recordingRunner: recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}},
			}
			manager.Runner = runner
			if action == "ensure" {
				_, _, err = manager.EnsureRestore(context.Background(), "/opt/stl/stl")
			} else {
				err = manager.RemoveRestore(context.Background())
			}
			if !runner.fired || !errors.Is(err, errUnitIdentityConflict) {
				t.Fatalf("%s accepted a different byte-identical canonical inode: %v", action, err)
			}
			actual, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(actual, originalBytes) {
				t.Fatalf("independent canonical unit lost: %v", readErr)
			}
			expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
			if !runner.enabled[restoreSystemdUnitName] {
				t.Fatal("enablement changed after ownership conflict")
			}
		})
	}
}

func TestExchangeOldOriginPinnedAfterDisplacedFileUnlinked(t *testing.T) {
	dir, path, priorBytes, runner, manager := newCompensationFixture(t, true, true)
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	var observed bool
	manager.afterUnitTransition = func(phase string) {
		if phase != "after-atomic-exchange" {
			return
		}
		observed = true
		matches, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("displaced staging not found: %v %v", matches, err)
		}
		if err := os.Remove(matches[0]); err != nil {
			t.Fatal(err)
		}
		requireOpenOriginFD(t, original)
		if err := os.WriteFile(matches[0], priorBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		newInfo, err := os.Lstat(matches[0])
		if err != nil || sameUnitFile(original, newInfo) {
			t.Fatalf("old inode recycled into changed staging: %v", err)
		}
	}
	_, _, err = manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if !observed || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("unverified OLD-side exchange accepted: %v", err)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
	stages, _ := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
	if len(stages) != 1 {
		t.Fatalf("independent staging identity lost: %v", stages)
	}
}

func TestRetirementPlaceholderPinnedUntilIdentitySensitiveUnlink(t *testing.T) {
	dir, path, priorBytes, runner, manager := newCompensationFixture(t, true, true)
	var substituted string
	manager.afterUnitTransition = func(phase string) {
		if phase != "before-retirement-placeholder-unlink" {
			return
		}
		matches, err := filepath.Glob(filepath.Join(dir, ".stl-retire-*.tmp"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("reserved retirement identity not found: %v %v", matches, err)
		}
		substituted = matches[0]
		previous, err := os.Lstat(substituted)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(substituted); err != nil {
			t.Fatal(err)
		}
		requireOpenOriginFD(t, previous)
		if err := os.WriteFile(substituted, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		current, err := os.Lstat(substituted)
		if err != nil || sameUnitFile(previous, current) {
			t.Fatalf("retirement placeholder ABA: %v", err)
		}
	}
	err := manager.RemoveRestore(context.Background())
	if substituted == "" || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("substituted retirement placeholder was deleted: %v", err)
	}
	if _, err := os.Stat(substituted); err != nil {
		t.Fatalf("independent retirement placeholder was removed: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, priorBytes) {
		t.Fatalf("canonical unit changed after placeholder conflict: %v", err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("owned prior enablement not restored")
	}
}

func TestFailedStagingCleanupRetainsOriginalDescriptorUntilSafeDecision(t *testing.T) {
	dir := t.TempDir()
	tmp, err := os.CreateTemp(dir, ".stl-unit-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(managedSystemdMarker + "\n[Unit]\nDescription=fixture\n")
	if _, err := tmp.Write(content); err != nil {
		t.Fatal(err)
	}
	origin, err := tmp.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tmp.Name()); err != nil {
		t.Fatal(err)
	}
	requireOpenOriginFD(t, origin)
	if err := os.WriteFile(tmp.Name(), content, 0o600); err != nil {
		t.Fatal(err)
	}
	external, err := os.Lstat(tmp.Name())
	if err != nil || sameUnitFile(origin, external) {
		t.Fatalf("independent replacement reused pinned inode: %v", err)
	}
	cleanupFailedOwnedStaging(tmp, origin, content)
	preserved, err := os.Lstat(tmp.Name())
	if err != nil || !sameUnitFile(preserved, external) {
		t.Fatalf("failure cleanup deleted independent stage: %v", err)
	}
	if _, err := tmp.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("failed staging descriptor not released: %v", err)
	}

	own, err := os.CreateTemp(dir, ".stl-unit-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := own.Write(content); err != nil {
		t.Fatal(err)
	}
	ownInfo, err := own.Stat()
	if err != nil {
		t.Fatal(err)
	}
	name := own.Name()
	cleanupFailedOwnedStaging(own, ownInfo, content)
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned failed stage was not cleaned up: %v", err)
	}
}

func TestPinnedCanonicalDescriptorRetainsInodeAfterUnlinkAndClosesOnRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	content := []byte(managedSystemdMarker + "\n[Unit]\nDescription=pinned existing\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, identity, err := readPinnedRegularUnit(path)
	if err != nil || !bytes.Equal(content, got) {
		t.Fatalf("cannot open pinned unit: %v", err)
	}
	pinned := identity.(*pinnedUnitIdentity)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	requireOpenOriginFD(t, identity)
	for i := 0; i < 32; i++ {
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		replacement, err := os.Lstat(path)
		if err != nil || sameUnitFile(replacement, identity) {
			t.Fatalf("recycled inode with live descriptor: %v", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	closePinnedUnit(identity)
	if _, err := pinned.origin.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("transaction-scoped descriptor not released: %v", err)
	}
}

func TestNoopEnsureReleasesShortLivedExistingUnitDescriptors(t *testing.T) {
	dir := t.TempDir()
	unit, err := renderRestoreSystemdUnit("/opt/stl/stl")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, restoreSystemdUnitName)
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		VerifyUnitPath:   func(string) error { return nil },
	}
	countFDs := func() int {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(fds)
	}
	before := countFDs()
	for i := 0; i < 40; i++ {
		_, changed, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
		if err != nil || changed {
			t.Fatalf("idempotent ensure failed: changed=%t err=%v", changed, err)
		}
	}
	if diff := countFDs() - before; diff > 1 {
		t.Fatalf("idempotent operation retained unnecessary origin descriptors: %d", diff)
	}
	if len(runner.commands) != 40 {
		t.Fatalf("unexpected systemctl calls: %s", strings.Join(runner.commands, ", "))
	}
}

type replacementAfterCompensationReloadRunner struct {
	recordingRunner
	t       *testing.T
	path    string
	changed bool
}

func (r *replacementAfterCompensationReloadRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	result, err := r.recordingRunner.Run(ctx, name, args...)
	if len(args) != 0 && args[0] == "daemon-reload" && !r.changed {
		r.changed = true
		previous, statErr := os.Lstat(r.path)
		if statErr != nil {
			r.t.Fatal(statErr)
		}
		identical, readErr := os.ReadFile(r.path)
		if readErr != nil {
			r.t.Fatal(readErr)
		}
		if removeErr := os.Remove(r.path); removeErr != nil {
			r.t.Fatal(removeErr)
		}
		requireOpenOriginFD(r.t, previous)
		if writeErr := os.WriteFile(r.path, identical, 0o644); writeErr != nil {
			r.t.Fatal(writeErr)
		}
		replacement, statErr := os.Lstat(r.path)
		if statErr != nil || sameUnitFile(previous, replacement) {
			r.t.Fatalf("restored inode was recycled while compensation still relied on it: %v", statErr)
		}
	}
	return result, err
}

func TestRestoredUnitOriginPinnedThroughCompensatingDaemonReload(t *testing.T) {
	_, path, _, _, manager := newCompensationFixture(t, true, true)
	runner := &replacementAfterCompensationReloadRunner{
		t: t, path: path,
		recordingRunner: recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}},
	}
	manager.Runner = runner
	manager.afterUnitPublish = func() error { return errUnitAfterRename }
	_, _, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if !runner.changed || !errors.Is(err, errUnitAfterRename) || !strings.Contains(err.Error(), "compensation incomplete after daemon-reload") {
		t.Fatalf("replacement of compensated inode was not identified: %v", err)
	}
	// The independent file has identical content but may never be asserted as
	// a verified restoration of STL's own newly published inode.
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl daemon-reload")
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("previous enablement changed")
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatal(statErr)
	}
}

func TestStaleUndoPinsUnlinkedPublishedOrigin(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, false, false)
	undo, changed, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if err != nil || !changed {
		t.Fatalf("initial install failed: %v", err)
	}
	origin, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := len(runner.commands)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	requireOpenOriginFD(t, origin)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Lstat(path)
	if err != nil || sameUnitFile(origin, replacement) {
		t.Fatalf("released Undo origin before invocation: %v", err)
	}
	if err := undo(context.Background()); !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("stale Undo accepted unrelated byte-identical file: %v", err)
	}
	present, err := os.Lstat(path)
	if err != nil || !sameUnitFile(present, replacement) || len(runner.commands) != before {
		t.Fatalf("Undo modified independent unit or systemctl: %v", err)
	}
}
