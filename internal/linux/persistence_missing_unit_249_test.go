package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// systemd 249 (Ubuntu 22.04) may report an absent unit as empty stdout,
// localized "No such file or directory" stderr, and exit 1. The first
// is-enabled call reproduces this Owner-observed case. All other calls
// retain the regular deterministic fake systemd lifecycle.
type systemd249MissingUnitRunner struct {
	recordingRunner
	initialSeen   bool
	initialResult CommandResult
	initialErr    error
	showResult    CommandResult
	showErr       error
}

func (r *systemd249MissingUnitRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "systemctl" && len(args) == 2 && args[0] == "is-enabled" && !r.initialSeen {
		r.initialSeen = true
		r.commands = append(r.commands, name+" "+strings.Join(args, " "))
		return r.initialResult, r.initialErr
	}
	if name == "systemctl" && len(args) > 0 && args[0] == "show" {
		r.commands = append(r.commands, name+" "+strings.Join(args, " "))
		want := []string{"show", restoreSystemdUnitName, "--no-pager", "--all",
			"-p", "LoadState", "-p", "UnitFileState", "-p", "FragmentPath"}
		if !reflect.DeepEqual(args, want) {
			return CommandResult{}, errors.New("unexpected systemctl show arguments")
		}
		return r.showResult, r.showErr
	}
	return r.recordingRunner.Run(ctx, name, args...)
}

func observedSystemd249Runner() *systemd249MissingUnitRunner {
	return &systemd249MissingUnitRunner{
		initialResult: CommandResult{Stderr: []byte("Failed to get unit file state for simple-tun-link-restore.service: No such file or directory\n")},
		initialErr:    &CommandError{Command: "systemctl", ExitCode: 1},
		showResult: CommandResult{Stdout: []byte(
			"LoadState=not-found\nFragmentPath=\nUnitFileState=\n")},
	}
}

func TestSystemd249MissingUnitRequiresIndependentCompleteAbsentIdentity(t *testing.T) {
	standard := func() *systemd249MissingUnitRunner { return observedSystemd249Runner() }
	cases := []struct {
		name    string
		change  func(*systemd249MissingUnitRunner)
		ok      bool
		queries int
	}{
		{"Owner observed missing-unit output", func(*systemd249MissingUnitRunner) {}, true, 2},
		{"different property ordering", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("UnitFileState=\nLoadState=not-found\nFragmentPath=\n")
		}, true, 2},
		{"loaded and disabled is not absent", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("LoadState=loaded\nUnitFileState=disabled\nFragmentPath=/etc/systemd/system/simple-tun-link-restore.service\n")
		}, false, 2},
		{"masked is not absent", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("LoadState=masked\nUnitFileState=masked\nFragmentPath=/dev/null\n")
		}, false, 2},
		{"ambiguous file state", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("LoadState=not-found\nUnitFileState=enabled\nFragmentPath=\n")
		}, false, 2},
		{"ambiguous fragment path", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("LoadState=not-found\nUnitFileState=\nFragmentPath=/etc/systemd/system/other.service\n")
		}, false, 2},
		{"incomplete stdout", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("LoadState=not-found\nUnitFileState=\n")
		}, false, 2},
		{"duplicate key", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("LoadState=not-found\nLoadState=not-found\nUnitFileState=\nFragmentPath=\n")
		}, false, 2},
		{"unrequested property", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte("LoadState=not-found\nUnitFileState=\nFragmentPath=\nResult=success\n")
		}, false, 2},
		{"oversized stdout", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stdout = []byte(strings.Repeat("a", 1025))
		}, false, 2},
		{"stderr from show", func(r *systemd249MissingUnitRunner) {
			r.showResult.Stderr = []byte("PRIVATE_OUTPUT")
		}, false, 2},
		{"show invocation error", func(r *systemd249MissingUnitRunner) {
			r.showErr = errors.New("systemctl unavailable")
		}, false, 2},
		{"show timeout", func(r *systemd249MissingUnitRunner) {
			r.showErr = &CommandError{Command: "systemctl", TimedOut: true, Canceled: true, ExitCode: 1}
		}, false, 2},
		{"original is-enabled timed out", func(r *systemd249MissingUnitRunner) {
			r.initialErr = &CommandError{Command: "systemctl", TimedOut: true, Canceled: true, ExitCode: 1}
		}, false, 1},
		{"original wrong exit code", func(r *systemd249MissingUnitRunner) {
			r.initialErr = &CommandError{Command: "systemctl", ExitCode: 4}
		}, false, 1},
		{"original transport error", func(r *systemd249MissingUnitRunner) {
			r.initialErr = errors.New("remote systemctl transport failed")
		}, false, 1},
		{"original no error despite blank output", func(r *systemd249MissingUnitRunner) {
			r.initialErr = nil
		}, false, 1},
		{"unknown nonempty stdout", func(r *systemd249MissingUnitRunner) {
			r.initialResult.Stdout = []byte("masked\n")
		}, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := standard()
			tc.change(runner)
			p := SystemdPersistence{Runner: runner}
			enabled, err := p.isEnabled(context.Background(), "systemctl", restoreSystemdUnitName)
			if enabled || (err == nil) != tc.ok {
				t.Fatalf("wrong fail-closed result: enabled=%t err=%v want-success=%t", enabled, err, tc.ok)
			}
			if len(runner.commands) != tc.queries {
				t.Fatalf("unexpected systemctl calls: %v", runner.commands)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, " enable ") || strings.Contains(command, " disable ") ||
					strings.Contains(command, "daemon-reload") {
					t.Fatalf("missing-unit inspection mutated host: %v", runner.commands)
				}
			}
		})
	}
}

func TestSystemd249FirstTunnelPublishesVerifiedOwnedRestore(t *testing.T) {
	runner := observedSystemd249Runner()
	dir := t.TempDir()
	p := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		VerifyUnitPath:   func(string) error { return nil },
	}
	undo, changed, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err != nil || !changed || undo == nil {
		t.Fatalf("missing unit could not be safely created after explicit proof: changed=%t err=%v", changed, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, restoreSystemdUnitName))
	if err != nil || !isOwnedSystemdUnit(content) {
		t.Fatalf("wrong newly published systemd unit identity: %v", err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("reboot restore unit not durably enabled")
	}
	expectSystemdOperations(t, runner.commands,
		"systemctl is-enabled ", "systemctl show ", "systemctl daemon-reload",
		"systemctl enable ", "systemctl is-enabled ")
	if err := undo(context.Background()); err != nil {
		t.Fatalf("owned rollback failed: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("owned rollback failed to restore initial absent enablement")
	}
}

func TestSystemd249AmbiguousInspectionPreventsAnyHostMutation(t *testing.T) {
	runner := observedSystemd249Runner()
	runner.showResult.Stdout = []byte("LoadState=not-found\nUnitFileState=masked\nFragmentPath=\n")
	dir := t.TempDir()
	p := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		VerifyUnitPath:   func(string) error { return nil },
	}
	_, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	kind, ok := RestoreFailureOf(err)
	if !ok || kind != RestoreEnablementUnknown {
		t.Fatalf("ambiguous systemd identity was not fail-closed with typed operator reason: %v", err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("ambiguous systemd identity triggered mutation: %v", runner.commands)
	}
	if _, err := os.Lstat(filepath.Join(dir, restoreSystemdUnitName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ambiguous systemd identity published an unsafe unit: %v", err)
	}
}

func TestSystemd249ReadOnlyMissingUnitAndUninstallPrecheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(SystemdPersistence) (bool, error)
	}{
		{"inspect restore installed", func(p SystemdPersistence) (bool, error) {
			return p.IsRestoreInstalled(context.Background())
		}},
		{"idempotent missing-unit removal", func(p SystemdPersistence) (bool, error) {
			return false, p.RemoveRestore(context.Background())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := observedSystemd249Runner()
			p := SystemdPersistence{Runner: runner, UnitDir: t.TempDir(),
				VerifyUnitPath: func(string) error { return nil }}
			installed, err := tc.call(p)
			if err != nil || installed || len(runner.commands) != 2 {
				t.Fatalf("read-only absent-unit verification failed: installed=%t err=%v calls=%v",
					installed, err, runner.commands)
			}
		})
	}
}
