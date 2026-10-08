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
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}

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
	manager := SystemdPersistence{Runner: &recordingRunner{}, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
		t.Fatal("expected unowned unit overwrite to be rejected")
	}
	if err := manager.RemoveRestore(context.Background()); err == nil {
		t.Fatal("expected unowned unit removal to be rejected")
	}
}

func TestSystemdPersistenceRejectsArbitraryExecutable(t *testing.T) {
	manager := SystemdPersistence{Runner: &recordingRunner{}, UnitDir: t.TempDir(), VerifyExecutable: func(string) error { return nil }}
	for _, executable := range []string{"stl", "/usr/local/bin/bash", "/usr/local/bin/stl other"} {
		if _, _, err := manager.EnsureRestore(context.Background(), executable); err == nil {
			t.Fatalf("expected executable %q to be rejected", executable)
		}
	}
}

func TestSystemdPersistenceRefusesEnabledIdentityWithoutOwnedFile(t *testing.T) {
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	unitDir := t.TempDir()
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}
	_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "without an STL-owned unit file") {
		t.Fatalf("expected actual enabled-without-owned-file branch, got %v", err)
	}
	if len(runner.commands) != 1 || !strings.HasPrefix(runner.commands[0], "systemctl is-enabled") {
		t.Fatalf("ambiguous identity was mutated: %v", runner.commands)
	}
	if _, err := os.Stat(filepath.Join(unitDir, restoreSystemdUnitName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected ambiguous identity installed a file: %v", err)
	}
}

func TestSystemdPersistenceRollsBackFileWhenEnableFails(t *testing.T) {
	unitDir := t.TempDir()
	runner := &recordingRunner{failOn: "systemctl enable " + restoreSystemdUnitName}
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}
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
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}
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
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}
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
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir, VerifyExecutable: func(string) error { return nil }}
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

type systemdStateRunner struct {
	before, after      string
	commands           []string
	enabledAttempted   bool
	disableCount       int
	failEnabledInspect bool
}

func (r *systemdStateRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	cmd := strings.Join(args, " ")
	r.commands = append(r.commands, cmd)
	if name != "systemctl" {
		return CommandResult{}, errors.New("unexpected command")
	}
	switch args[0] {
	case "is-enabled":
		state := r.before
		if r.enabledAttempted {
			state = r.after
		}
		if state == "disabled" || state == "not-found" || state == "enabled-runtime" {
			return CommandResult{Stdout: []byte(state + "\n")}, errors.New("not permanently enabled")
		}
		if state == "enabled" && r.failEnabledInspect {
			return CommandResult{Stdout: []byte("enabled\n")}, errors.New("systemctl failed despite stdout")
		}
		return CommandResult{Stdout: []byte(state + "\n")}, nil
	case "enable":
		r.enabledAttempted = true
	case "disable":
		r.disableCount++
	case "daemon-reload":
	default:
		return CommandResult{}, errors.New("unexpected systemctl invocation")
	}
	return CommandResult{}, nil
}

func TestSystemdEnablementStatesRequireDurableIdentity(t *testing.T) {
	cases := []struct {
		initial, final     string
		wantOK, wantEnable bool
	}{
		{"enabled", "", true, false},
		{"disabled", "enabled", true, true},
		{"not-found", "enabled", true, true},
		{"enabled-runtime", "enabled", false, false},
		{"linked", "enabled", false, false},
		{"linked-runtime", "enabled", false, false},
		{"alias", "enabled", false, false},
		{"masked", "enabled", false, false},
		{"masked-runtime", "enabled", false, false},
		{"indirect", "enabled", false, false},
		{"static", "enabled", false, false},
		{"generated", "enabled", false, false},
		{"transient", "enabled", false, false},
		{"mystery", "enabled", false, false},
		{"disabled", "enabled-runtime", false, true},
		{"not-found", "alias", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.initial+"_to_"+tc.final, func(t *testing.T) {
			dir := t.TempDir()
			runner := &systemdStateRunner{before: tc.initial, after: tc.final}
			if tc.initial == "enabled" {
				prior, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, restoreSystemdUnitName), []byte(prior), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			manager := SystemdPersistence{Runner: runner, UnitDir: dir, VerifyExecutable: func(string) error { return nil }}
			_, changed, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
			if (err == nil) != tc.wantOK {
				t.Fatalf("success=%t want=%t err=%v", err == nil, tc.wantOK, err)
			}
			if runner.enabledAttempted != tc.wantEnable {
				t.Fatalf("enable attempt=%t want=%t", runner.enabledAttempted, tc.wantEnable)
			}
			path := filepath.Join(dir, restoreSystemdUnitName)
			_, statErr := os.Stat(path)
			if tc.wantOK && (statErr != nil || (tc.initial != "enabled" && !changed)) {
				t.Fatalf("durable state missing: %v", statErr)
			}
			if !tc.wantOK && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed enable retained unit: %v", statErr)
			}
			if !tc.wantOK && tc.wantEnable && runner.disableCount == 0 {
				t.Fatal("ambiguous enablement not compensated")
			}
		})
	}
}

func TestSystemdRestoreUnitHasBoundedOneShotStartup(t *testing.T) {
	unit, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"Type=oneshot", "TimeoutStartSec=35min", "ExecStart=/usr/local/bin/stl link restore --all"} {
		if !strings.Contains(unit, fragment) {
			t.Fatalf("restore unit missing %s", fragment)
		}
	}
}

// A failing systemctl invocation must not become a successful durable
// identity observation merely by printing an expected stdout token.
func TestSystemdFailedEnabledInspectionDoesNotClaimPersistence(t *testing.T) {
	dir := t.TempDir()
	unit, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, restoreSystemdUnitName), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &systemdStateRunner{before: "enabled", failEnabledInspect: true}
	manager := SystemdPersistence{Runner: runner, UnitDir: dir, VerifyExecutable: func(string) error { return nil }}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
		t.Fatal("failed systemctl inspection was mistaken for durable enablement")
	}
	if runner.enabledAttempted {
		t.Fatal("failed inspection caused unexpected enable mutation")
	}
}

// A missing owned unit file does not authorize disabling or overlooking
// enabled or ambiguously aliased systemd identities.
func TestRemoveRestoreMissingAndExistingIdentityPolicy(t *testing.T) {
	for _, tc := range []struct {
		name         string
		enabled      bool
		failInspect  bool
		existing     string
		wantError    string
		wantCommands int
	}{
		{name: "missing disabled", wantCommands: 1},
		{name: "missing enabled orphan", enabled: true, wantError: "lacks an STL-owned unit", wantCommands: 1},
		{name: "missing inspection fails", failInspect: true, wantError: "cannot verify absent", wantCommands: 1},
		{name: "existing owned enabled", existing: "owned", enabled: true, wantCommands: 3},
		{name: "existing foreign", existing: "foreign", enabled: true, wantError: "non-STL", wantCommands: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, restoreSystemdUnitName)
			switch tc.existing {
			case "owned":
				unit, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err := os.WriteFile(path, []byte("[Unit]\nDescription=foreign\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: tc.enabled}}
			if tc.failInspect {
				runner.failOn = "systemctl is-enabled " + restoreSystemdUnitName
			}
			manager := SystemdPersistence{Runner: runner, UnitDir: dir}
			err := manager.RemoveRestore(context.Background())
			if tc.wantError == "" && err != nil {
				t.Fatalf("unexpected failure: %v", err)
			}
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("wrong error: got %v, want %q", err, tc.wantError)
			}
			if len(runner.commands) != tc.wantCommands {
				t.Fatalf("unexpected systemctl calls: %v", runner.commands)
			}
			if tc.wantError != "" {
				if tc.existing == "foreign" {
					got, err := os.ReadFile(path)
					if err != nil || !strings.Contains(string(got), "foreign") {
						t.Fatalf("foreign unit mutated: %q %v", got, err)
					}
				} else if tc.existing == "" {
					if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("missing unit created: %v", statErr)
					}
				}
				if !runner.enabled[restoreSystemdUnitName] && tc.enabled {
					t.Fatal("foreign identity disabled")
				}
			}
			if tc.existing == "owned" && err == nil {
				if runner.enabled[restoreSystemdUnitName] {
					t.Fatal("owned unit remained enabled")
				}
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("owned unit remains: %v", statErr)
				}
			}
		})
	}
}

func TestRemoveRestoreCanceledEnablementInspectionNeverClaimsSafeNoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &recordingRunner{} // Intentionally ignores caller cancellation.
	manager := SystemdPersistence{Runner: runner, UnitDir: t.TempDir()}
	err := manager.RemoveRestore(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled inspection was accepted as a safe cleanup: %v", err)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}
