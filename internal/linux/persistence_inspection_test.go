package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixedInspectionRunner struct {
	result   CommandResult
	err      error
	commands []string
}

func (r *fixedInspectionRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.commands = append(r.commands, name+" "+strings.Join(args, " "))
	if name != "systemctl" || len(args) != 2 || args[0] != "is-enabled" {
		return CommandResult{}, errors.New("unexpected systemctl mutation")
	}
	return r.result, r.err
}

func TestSystemdEnablementInspectionDoesNotTrustPartialStdout(t *testing.T) {
	cases := []struct {
		name, status string
		err          error
		allowed      bool
	}{
		{"disabled expected process status", "disabled", &CommandError{Command: "systemctl", ExitCode: 1}, true},
		{"not-found expected process status", "not-found", &CommandError{Command: "systemctl", ExitCode: 4}, true},
		{"disabled internal timeout", "disabled", &CommandError{Command: "systemctl", ExitCode: 1, TimedOut: true, Canceled: true}, false},
		{"not-found internal timeout", "not-found", &CommandError{Command: "systemctl", ExitCode: 4, TimedOut: true, Canceled: true}, false},
		{"disabled unexpected exit", "disabled", &CommandError{Command: "systemctl", ExitCode: 5}, false},
		{"not-found unexpected exit", "not-found", &CommandError{Command: "systemctl", ExitCode: 1}, false},
		{"disabled nonprocess error", "disabled", errors.New("transport failed"), false},
		{"not-found nonprocess error", "not-found", errors.New("runner failed"), false},
		{"disabled nil exit error", "disabled", nil, false},
		{"not-found nil exit error", "not-found", nil, false},
		{"enabled genuine process success", "enabled", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			runner := &fixedInspectionRunner{
				result: CommandResult{Stdout: []byte(tc.status + "\n")},
				err:    tc.err,
			}
			manager := SystemdPersistence{Runner: runner, UnitDir: dir}
			err := manager.RemoveRestore(context.Background())
			if (err == nil) != tc.allowed {
				t.Fatalf("accepted unverified inspection=%t expected=%t err=%v", err == nil, tc.allowed, err)
			}
			if len(runner.commands) != 1 || runner.commands[0] != "systemctl is-enabled "+restoreSystemdUnitName {
				t.Fatalf("unexpected mutation from inspection: %v", runner.commands)
			}
			if _, statErr := os.Stat(filepath.Join(dir, restoreSystemdUnitName)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("absent unit mutated: %v", statErr)
			}
		})
	}
}

type stuckEnabledCleanupRunner struct {
	recordingRunner
}

func (r *stuckEnabledCleanupRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if len(args) == 2 && args[0] == "is-enabled" {
		r.commands = append(r.commands, name+" "+strings.Join(args, " "))
		return CommandResult{Stdout: []byte("enabled\n")}, nil
	}
	return r.recordingRunner.Run(ctx, name, args...)
}
func TestRemoveVerifiesPostconditionRatherThanTrustingDisableSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	prior, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &stuckEnabledCleanupRunner{}
	manager := SystemdPersistence{Runner: runner, UnitDir: dir}
	err = manager.RemoveRestore(context.Background())
	if err == nil || !strings.Contains(err.Error(), "remains enabled") {
		t.Fatalf("successful disable without verified postcondition was accepted: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("test did not exercise fully published file deletion: %v", statErr)
	}
	expectSystemdOperations(t, runner.commands,
		"systemctl is-enabled ", "systemctl disable ", "systemctl daemon-reload", "systemctl is-enabled ")
}

type mutationDuringDisableRunner struct {
	recordingRunner
	unitPath    string
	replacement []byte
}

func (r *mutationDuringDisableRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	result, err := r.recordingRunner.Run(ctx, name, args...)
	if len(args) == 2 && args[0] == "disable" {
		if writeErr := os.WriteFile(r.unitPath, r.replacement, 0o644); writeErr != nil {
			return result, writeErr
		}
	}
	return result, err
}
func TestRemoveNeverDeletesExternallyChangedOwnedUnit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	prior, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("[Unit]\nDescription=operator replacement\n")
	runner := &mutationDuringDisableRunner{unitPath: path, replacement: foreign}
	runner.enabled = map[string]bool{restoreSystemdUnitName: true}
	manager := SystemdPersistence{Runner: runner, UnitDir: dir}
	if err := manager.RemoveRestore(context.Background()); err == nil {
		t.Fatal("external file change after disable was removed")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(foreign) {
		t.Fatalf("external file was overwritten: %q %v", got, err)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl disable ")
}
