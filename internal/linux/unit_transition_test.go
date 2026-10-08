package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicFirstInstallNeverClobbersInterveningUnit(t *testing.T) {
	for _, tc := range []string{"foreign-file", "foreign-symlink"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, restoreSystemdUnitName)
			runner := &recordingRunner{}
			manager := SystemdPersistence{
				Runner: runner, UnitDir: dir, VerifyExecutable: func(string) error { return nil },
				VerifyUnitPath: func(string) error { return nil },
			}
			foreign := []byte("[Unit]\nDescription=installed by another manager\n")
			external := filepath.Join(t.TempDir(), "external.unit")
			if tc == "foreign-symlink" {
				if err := os.WriteFile(external, foreign, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			manager.beforeUnitMutation = func(phase string) {
				if phase != "create" {
					return
				}
				if tc == "foreign-file" {
					if err := os.WriteFile(path, foreign, 0o644); err != nil {
						t.Error(err)
					}
				} else {
					if err := os.Symlink(external, path); err != nil {
						t.Error(err)
					}
				}
			}
			_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
			if err == nil || !errors.Is(err, os.ErrExist) {
				t.Fatalf("first-create race falsely succeeded: %v", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || string(got) != string(foreign) {
				t.Fatalf("external contents were overwritten: %q %v", got, readErr)
			}
			if tc == "foreign-symlink" {
				info, e := os.Lstat(path)
				if e != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("foreign symlink was replaced")
				}
			}
			if runner.enabled[restoreSystemdUnitName] || len(runner.commands) != 1 {
				t.Fatalf("unsafe first install enabled systemd: %v", runner.commands)
			}
		})
	}
}

func TestAtomicReplacementPreservesInterveningOwnedOrForeignIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		replaceInode bool
	}{
		{"same inode mutated text", false},
		{"foreign inode replaces owned unit", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, path, prior, runner, manager := newCompensationFixture(t, true, true)
			foreign := []byte("[Unit]\nDescription=independent administrator unit\n")
			var originalBackup string
			manager.beforeUnitMutation = func(phase string) {
				if phase != "replace" {
					return
				}
				if tc.replaceInode {
					originalBackup = path + ".operator-original"
					if err := os.Rename(path, originalBackup); err != nil {
						t.Error(err)
					}
				}
				if err := os.WriteFile(path, foreign, 0o644); err != nil {
					t.Error(err)
				}
			}
			_, _, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
			if !errors.Is(err, errUnitIdentityConflict) {
				t.Fatalf("last-moment replacement not rejected: %v", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || string(got) != string(foreign) {
				t.Fatalf("new independent unit replaced: %q %v", got, readErr)
			}
			if tc.replaceInode {
				got, e := os.ReadFile(originalBackup)
				if e != nil || string(got) != string(prior) {
					t.Fatalf("administrator's original file missing: %q %v", got, e)
				}
			}
			if !runner.enabled[restoreSystemdUnitName] || len(runner.commands) != 1 {
				t.Fatalf("failed replacement changed enablement: %v", runner.commands)
			}
		})
	}
}

func TestAtomicRestoreDoesNotOverwriteChangedUnitAfterFinalGuard(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=changed just before compensation exchange\n")
	runner.failOnce = "systemctl daemon-reload"
	manager.beforeUnitMutation = func(phase string) {
		if phase == "restore" {
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				t.Error(err)
			}
		}
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if err == nil || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("unsafe restore race was not reported: %v", err)
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != string(foreign) {
		t.Fatalf("external unit overwritten on compensation: %q %v", got, e)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("preexisting enabled state lost")
	}
}

func TestAtomicRemoveDoesNotDeleteChangedIdentityAfterLastGuard(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=changed just before retire\n")
	manager.beforeUnitMutation = func(phase string) {
		if phase == "delete" {
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				t.Error(err)
			}
		}
	}
	err := manager.RemoveRestore(context.Background())
	if err == nil || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("unsafe unit removal race was not reported: %v", err)
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != string(foreign) {
		t.Fatalf("foreign unit deleted after final guard: %q %v", got, e)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl disable ")
}

func TestAtomicRestoreDeleteDoesNotRemoveChangedIdentity(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, false, false)
	manager.afterUnitPublish = func() error { return errUnitAfterRename }
	foreign := []byte("[Unit]\nDescription=operator changed during rollback\n")
	manager.beforeUnitMutation = func(phase string) {
		if phase == "restore-delete" {
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				t.Error(err)
			}
		}
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "compensation incomplete") || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("unsafe restoration deletion race was not surfaced: %v", err)
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != string(foreign) {
		t.Fatalf("foreign unit deleted during compensation: %q %v", got, e)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}

func TestAtomicNewAndExistingOwnedUnitTransitionsSucceed(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, false, false)
	undo, changed, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err != nil || !changed {
		t.Fatalf("first no-clobber creation failed: changed=%t err=%v", changed, err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("first install did not enable unit")
	}
	updatedUndo, changed, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if err != nil || !changed {
		t.Fatalf("atomic replacement failed: changed=%t err=%v", changed, err)
	}
	got, e := os.ReadFile(path)
	if e != nil || !strings.Contains(string(got), "ExecStart=/opt/stl/stl") {
		t.Fatalf("atomic replacement did not install new bytes: %q %v", got, e)
	}
	if err := updatedUndo(context.Background()); err != nil {
		t.Fatalf("replacement undo failed: %v", err)
	}
	got, e = os.ReadFile(path)
	if e != nil || !strings.Contains(string(got), "ExecStart=/usr/local/bin/stl") {
		t.Fatalf("prior exact unit not restored: %q %v", got, e)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("replacement rollback lost enablement")
	}
	if err := undo(context.Background()); err != nil {
		t.Fatalf("original installation undo failed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first unit undo failed to remove own unit: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("initial install undo did not disable unit")
	}
}
