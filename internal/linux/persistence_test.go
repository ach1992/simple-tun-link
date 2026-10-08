package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingRunner struct {
	commands []string
	failOn   string
	enabled  map[string]bool
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	command := strings.Join(append([]string{name}, args...), " ")
	r.commands = append(r.commands, command)
	if command == r.failOn {
		return CommandResult{}, errors.New("command failed")
	}
	if len(args) == 2 && args[0] == "is-enabled" {
		if r.enabled != nil && r.enabled[args[1]] {
			return CommandResult{Stdout: []byte("enabled\n")}, nil
		}
		return CommandResult{Stdout: []byte("disabled\n")}, errors.New("disabled")
	}
	if len(args) == 2 && args[0] == "enable" {
		if r.enabled == nil {
			r.enabled = map[string]bool{}
		}
		r.enabled[args[1]] = true
	}
	if len(args) == 2 && args[0] == "disable" && r.enabled != nil {
		r.enabled[args[1]] = false
	}
	return CommandResult{}, nil
}

func TestSystemdPersistenceEnsureRestoreAndRollback(t *testing.T) {
	runner := &recordingRunner{}
	unitDir := t.TempDir()
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir}

	undo, changed, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("expected unit creation and enablement")
	}
	path := filepath.Join(unitDir, restoreSystemdUnitName)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isOwnedSystemdUnit(content) || !strings.Contains(string(content), "ExecStart=/usr/local/bin/stl link restore --all") {
		t.Fatalf("unexpected restore unit content: %s", content)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " --now") || strings.Contains(command, " start ") || strings.Contains(command, " restart ") {
			t.Fatalf("persistence mutated live service state: %q", command)
		}
	}
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("new unit remained enabled after rollback")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit remained after rollback: %v", err)
	}
}

func TestSystemdPersistenceRefusesUnownedRestoreUnit(t *testing.T) {
	unitDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(unitDir, restoreSystemdUnitName), []byte("[Unit]\nDescription=external\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manager := SystemdPersistence{Runner: &recordingRunner{}, UnitDir: unitDir}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
		t.Fatal("expected unowned unit overwrite to be rejected")
	}
	if err := manager.RemoveRestore(context.Background()); err == nil {
		t.Fatal("expected unowned unit removal to be rejected")
	}
}

func TestSystemdPersistenceRejectsArbitraryExecutable(t *testing.T) {
	manager := SystemdPersistence{Runner: &recordingRunner{}, UnitDir: t.TempDir()}
	for _, executable := range []string{"stl", "/usr/local/bin/bash", "/usr/local/bin/stl other"} {
		if _, _, err := manager.EnsureRestore(context.Background(), executable); err == nil {
			t.Fatalf("expected executable %q to be rejected", executable)
		}
	}
}

func TestSystemdPersistenceRefusesEnabledIdentityWithoutOwnedFile(t *testing.T) {
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	manager := SystemdPersistence{Runner: runner, UnitDir: t.TempDir()}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
		t.Fatal("expected ambiguous pre-enabled unit identity to be rejected")
	}
}

func TestSystemdPersistenceRollsBackFileWhenEnableFails(t *testing.T) {
	unitDir := t.TempDir()
	runner := &recordingRunner{failOn: "systemctl enable " + restoreSystemdUnitName}
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir}
	_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil {
		t.Fatal("expected enable failure")
	}
	if _, statErr := os.Stat(filepath.Join(unitDir, restoreSystemdUnitName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unit file remained after failed enable: %v", statErr)
	}
}

func TestSystemdPersistencePreservesPriorEnablementOnRollback(t *testing.T) {
	unitDir := t.TempDir()
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir}
	oldContent := managedSystemdMarker + "\n[Unit]\nDescription=old\n"
	if err := os.WriteFile(filepath.Join(unitDir, restoreSystemdUnitName), []byte(oldContent), 0o644); err != nil {
		t.Fatal(err)
	}
	undo, changed, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err != nil || !changed {
		t.Fatalf("EnsureRestore changed=%v err=%v", changed, err)
	}
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("previously enabled unit was disabled by rollback")
	}
	got, _ := os.ReadFile(filepath.Join(unitDir, restoreSystemdUnitName))
	if string(got) != oldContent {
		t.Fatal("prior owned unit content was not restored")
	}
}

func TestSystemdPersistenceInspectsOwnedRestoreIdentity(t *testing.T) {
	runner := &recordingRunner{}
	unitDir := t.TempDir()
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir}
	present, err := manager.IsRestoreInstalled(context.Background())
	if err != nil || present {
		t.Fatalf("fresh host was not recognized: %t %v", present, err)
	}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err != nil {
		t.Fatal(err)
	}
	present, err = manager.IsRestoreInstalled(context.Background())
	if err != nil || !present {
		t.Fatalf("owned unit not recognized: %t %v", present, err)
	}
}

func TestSystemdPersistenceDoesNotTrustUnownedOrOrphanedIdentity(t *testing.T) {
	unitDir := t.TempDir()
	path := filepath.Join(unitDir, restoreSystemdUnitName)
	runner := &recordingRunner{}
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir}
	if err := os.WriteFile(path, []byte("[Unit]\nDescription=foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.IsRestoreInstalled(context.Background()); err == nil {
		t.Fatal("foreign restore identity was not rejected")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	runner.enabled = map[string]bool{restoreSystemdUnitName: true}
	if _, err := manager.IsRestoreInstalled(context.Background()); err == nil {
		t.Fatal("orphaned enabled identity was accepted as absent")
	}
}
