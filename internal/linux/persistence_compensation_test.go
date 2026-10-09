package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// A controlled systemctl runner which can fail once and/or allow an
// independent configuration manager to replace the unit during a command.
type compensationRunner struct {
	recordingRunner
	failOnce            string
	failPostEnableCheck bool
	checkedAfterEnable  bool
	changeOn            string
	unitPath            string
	foreign             []byte
}

func (r *compensationRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	command := name + " " + strings.Join(args, " ")
	if command == r.failOnce {
		r.failOnce = ""
		// Record the failed operation without applying the fake side effect.
		r.commands = append(r.commands, command)
		if command == r.changeOn {
			if err := os.WriteFile(r.unitPath, r.foreign, 0o644); err != nil {
				return CommandResult{}, err
			}
		}
		return CommandResult{}, errors.New("injected systemctl failure")
	}
	if len(args) == 2 && args[0] == "is-enabled" && r.failPostEnableCheck && r.enabled[args[1]] && !r.checkedAfterEnable {
		r.checkedAfterEnable = true
		r.commands = append(r.commands, command)
		return CommandResult{Stdout: []byte("enabled\n")}, &CommandError{Command: name, ExitCode: 1, TimedOut: true, Canceled: true}
	}
	result, err := r.recordingRunner.Run(ctx, name, args...)
	if command == r.changeOn {
		if e := os.WriteFile(r.unitPath, r.foreign, 0o644); e != nil {
			return result, e
		}
	}
	return result, err
}

func newCompensationFixture(t *testing.T, existing, enabled bool) (string, string, []byte, *compensationRunner, SystemdPersistence) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	prior := []byte(nil)
	if existing {
		prior = []byte(managedSystemdMarker + "\n[Unit]\nDescription=previous owned unit\n")
		if err := os.WriteFile(path, prior, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &compensationRunner{unitPath: path, foreign: []byte("[Unit]\nDescription=foreign operator file\n")}
	runner.enabled = map[string]bool{restoreSystemdUnitName: enabled}
	manager := SystemdPersistence{Runner: runner, UnitDir: dir, VerifyExecutable: func(string) error { return nil }, VerifyUnitPath: func(string) error { return nil }}
	return dir, path, prior, runner, manager
}

func TestGuardedDaemonReloadCompensationAfterPublishedUnit(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		existing, enabled, external bool
	}{
		{"first install restoration", false, false, false},
		{"previous enabled restoration", true, true, false},
		{"external replacement refused", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, path, prior, runner, manager := newCompensationFixture(t, tc.existing, tc.enabled)
			runner.failOnce = "systemctl daemon-reload"
			if tc.external {
				runner.changeOn = "systemctl daemon-reload"
			}
			_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
			if err == nil || !strings.Contains(err.Error(), "systemd daemon-reload") {
				t.Fatalf("failed reload not reported: %v", err)
			}
			if tc.external {
				got, readErr := os.ReadFile(path)
				if readErr != nil || string(got) != string(runner.foreign) {
					t.Fatalf("operator file overwritten: %q %v", got, readErr)
				}
				if len(runner.commands) != 2 {
					t.Fatalf("cleanup mutated foreign unit: %v", runner.commands)
				}
				return
			}
			if tc.existing {
				got, readErr := os.ReadFile(path)
				if readErr != nil || string(got) != string(prior) {
					t.Fatalf("prior owned unit missing: %q %v", got, readErr)
				}
				if !runner.enabled[restoreSystemdUnitName] {
					t.Fatal("previous enabled unit disabled")
				}
			} else {
				if _, readErr := os.Lstat(path); !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("failed new unit still installed: %v", readErr)
				}
				if runner.enabled[restoreSystemdUnitName] {
					t.Fatal("failure enabled new unit")
				}
			}
			if !strings.Contains(strings.Join(runner.commands, "/"), "daemon-reload") {
				t.Fatalf("reload never attempted: %v", runner.commands)
			}
		})
	}
}

func TestGuardedEnableFailureCompensation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		external      bool
		verifyFailure bool
	}{
		{"command failure restores", false, false},
		{"verification timeout restores", false, true},
		{"external change prevents disabling or overwrite", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, path, _, runner, manager := newCompensationFixture(t, false, false)
			if tc.verifyFailure {
				runner.failPostEnableCheck = true
			} else {
				runner.failOnce = "systemctl enable " + restoreSystemdUnitName
			}
			if tc.external {
				runner.changeOn = "systemctl enable " + restoreSystemdUnitName
			}
			_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
			if err == nil || !strings.Contains(err.Error(), "enable STL systemd unit") {
				t.Fatalf("failed enable not reported: %v", err)
			}
			if tc.verifyFailure && !runner.checkedAfterEnable {
				t.Fatal("post-enable verification failure was not exercised")
			}
			if tc.external {
				got, readErr := os.ReadFile(path)
				if readErr != nil || string(got) != string(runner.foreign) {
					t.Fatalf("operator file overwritten: %q %v", got, readErr)
				}
				for _, command := range runner.commands {
					if strings.HasPrefix(command, "systemctl disable ") {
						t.Fatalf("foreign identity disabled: %v", runner.commands)
					}
				}
				return
			}
			if _, readErr := os.Lstat(path); !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("published unit not restored after enable failure: %v", readErr)
			}
			if runner.enabled[restoreSystemdUnitName] {
				t.Fatal("failed enable left unit active")
			}
			if !strings.Contains(strings.Join(runner.commands, "/"), "systemctl disable ") {
				t.Fatalf("partial enablement not compensated: %v", runner.commands)
			}
		})
	}
}

func TestGuardedPersistenceUndoAndExternalIdentityChange(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary undo", true: "foreign replacement"}[external], func(t *testing.T) {
			_, path, _, runner, manager := newCompensationFixture(t, false, false)
			undo, changed, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
			if err != nil || !changed {
				t.Fatalf("cannot establish unit: %v", err)
			}
			beforeUndoCalls := len(runner.commands)
			if external {
				if err := os.WriteFile(path, runner.foreign, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err = undo(context.Background())
			if external {
				if err == nil || !strings.Contains(err.Error(), "uncertain") {
					t.Fatalf("foreign-unit undo incorrectly succeeded: %v", err)
				}
				got, e := os.ReadFile(path)
				if e != nil || string(got) != string(runner.foreign) {
					t.Fatalf("operator replacement overwritten: %q %v", got, e)
				}
				if len(runner.commands) != beforeUndoCalls {
					t.Fatalf("undo modified systemd after ownership changed: %v", runner.commands[beforeUndoCalls:])
				}
				return
			}
			if err != nil {
				t.Fatalf("owned undo failed: %v", err)
			}
			if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unit remained after successful undo: %v", statErr)
			}
			if runner.enabled[restoreSystemdUnitName] {
				t.Fatal("unit remained enabled after successful undo")
			}
		})
	}
}

type rejectUnitCommit struct {
	state.Store
	afterEnsureBeforeCommit func()
}

func (s rejectUnitCommit) Update(context.Context, func(*state.Snapshot) error) error {
	if s.afterEnsureBeforeCommit != nil {
		s.afterEnsureBeforeCommit()
	}
	return errors.New("simulated commit rejection")
}

func TestEngineCommitFailureUsesGuardedUnitUndo(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact owned unit", true: "external replacement"}[external], func(t *testing.T) {
			root := t.TempDir()
			unitDir, path, _, runner, manager := newCompensationFixture(t, false, false)
			manager.UnitDir = unitDir
			baseStore := state.NewFileStore(root)
			var mutated bool
			store := rejectUnitCommit{Store: baseStore}
			if external {
				store.afterEnsureBeforeCommit = func() {
					mutated = true
					if err := os.WriteFile(path, runner.foreign, 0o644); err != nil {
						t.Error(err)
					}
				}
			}
			b := &unitEngineBackend{}
			registry, err := backend.NewRegistry(b)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := app.NewWithRestorePersistence(registry, store, state.NewLockManager(root), &manager, "/usr/local/bin/stl")
			if err != nil {
				t.Fatal(err)
			}
			link := testUnitEngineLink(t)
			_, operationErr := engine.Ensure(context.Background(), link)
			expectedCode := stlerr.CodeState
			if external {
				expectedCode = stlerr.CodeRollback
			}
			if stlerr.CodeOf(operationErr) != expectedCode {
				t.Fatalf("incorrect rollback status: got=%v want=%v", operationErr, expectedCode)
			}
			if external && !mutated {
				t.Fatal("test did not inject external operator change before commit rollback")
			}
			snapshot, err := baseStore.Load(context.Background())
			if err != nil || len(snapshot.Links) != 0 {
				t.Fatalf("uncommitted state changed: %+v %v", snapshot, err)
			}
			if b.undos != 1 || b.live {
				t.Fatalf("backend rollback did not complete: undos=%d live=%t", b.undos, b.live)
			}
			if external {
				got, e := os.ReadFile(path)
				if e != nil || string(got) != string(runner.foreign) {
					t.Fatalf("operator unit overwritten by Engine compensation: %q %v", got, e)
				}
				if !runner.enabled[restoreSystemdUnitName] {
					t.Fatal("foreign identity was disabled by Engine rollback")
				}
			} else {
				if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("owned unit remained after Engine rollback: %v", e)
				}
				if runner.enabled[restoreSystemdUnitName] {
					t.Fatal("owned unit not disabled after Engine rollback")
				}
			}
		})
	}
}

// Failed removal must restore only its own previous identity. The restoration
// must never overwrite another process's replacement of the now-absent path.
func TestRemoveFailureCompensationPreservesOwnership(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "safe_owned_restore", true: "external_replacement_refused"}[external], func(t *testing.T) {
			_, path, prior, runner, manager := newCompensationFixture(t, true, true)
			runner.failOnce = "systemctl daemon-reload"
			if external {
				runner.changeOn = "systemctl daemon-reload"
			}
			err := manager.RemoveRestore(context.Background())
			if err == nil || !strings.Contains(err.Error(), "daemon-reload after remove") {
				t.Fatalf("original failed removal was lost: %v", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if external {
				if string(got) != string(runner.foreign) {
					t.Fatalf("foreign file overwritten: %q", got)
				}
				if runner.enabled[restoreSystemdUnitName] {
					t.Fatal("foreign unit re-enabled after external replacement")
				}
				if !strings.Contains(err.Error(), "uncertain") {
					t.Fatalf("missing explicit incomplete compensation: %v", err)
				}
			} else {
				if string(got) != string(prior) {
					t.Fatalf("prior owned unit was not restored: %q", got)
				}
				if !runner.enabled[restoreSystemdUnitName] {
					t.Fatal("prior enabled unit not restored")
				}
			}
		})
	}
}

func TestExclusiveUnitRestoreRefusesExistingForeignFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	foreign := []byte("[Unit]\nDescription=external\n")
	if err := os.WriteFile(path, foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	prior := []byte(managedSystemdMarker + "\n[Unit]\nDescription=previous\n")
	if err := writeOwnedUnitIfAbsent(dir, path, prior, 0o644); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive restore replaced existing file or returned unexpected error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(foreign) {
		t.Fatalf("operator unit overwritten: %q %v", got, err)
	}
}

// A unit symlink whose target carries STL's marker is not an owned regular
// unit file. The marker must never authorize rewriting, disabling or removing
// a link installed by a different administrator.
func TestSymlinkedOwnedMarkerUnitIsNotTrusted(t *testing.T) {
	dir := t.TempDir()
	external := filepath.Join(t.TempDir(), "external-unit.service")
	unit, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(external, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, restoreSystemdUnitName)
	if err := os.Symlink(external, path); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	manager := SystemdPersistence{Runner: runner, UnitDir: dir, VerifyExecutable: func(string) error { return nil }, VerifyUnitPath: func(string) error { return nil }}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
		t.Fatal("symlinked unit was accepted for activation")
	}
	if err := manager.RemoveRestore(context.Background()); err == nil {
		t.Fatal("symlinked unit was accepted for removal")
	}
	if _, err := manager.IsRestoreInstalled(context.Background()); err == nil {
		t.Fatal("symlinked unit was accepted as owned")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("symlink allowed command side effects: %v", runner.commands)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("external symlink was replaced: %v", err)
	}
	got, err := os.ReadFile(external)
	if err != nil || string(got) != unit {
		t.Fatalf("external file was mutated: %q %v", got, err)
	}
}
