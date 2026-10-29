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

var effectiveSystemdShowArgs = []string{
	"show", restoreSystemdUnitName, "--no-pager", "--all",
	"-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths",
	"-p", "NeedDaemonReload", "-p", "ExecStart",
}
var absentSystemdShowArgs = []string{
	"show", restoreSystemdUnitName, "--no-pager", "--all",
	"-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths",
	"-p", "NeedDaemonReload",
}

// A fully isolated, read-only systemctl show witness, with the same Runner
// boundary used by production. No real systemd unit, root filesystem or
// network resource is modified. The root-owned unit path is simulated by the
// existing test-only trusted-path verifier.
type effectiveLoadedUnitRunner struct {
	recordingRunner
	fragment, dropIns, needReload, loadState, execStart string
	showErr                                             error
	showStdout, showStderr                              []byte
	showCount                                           int
	addDropInAfterIsEnabled                             bool
	addDropInAfterDisable                               bool
	addDropInAfterDaemonReload                          bool
}

func (r *effectiveLoadedUnitRunner) showText() string {
	load, need, command := r.loadState, r.needReload, r.execStart
	if load == "" {
		load = "loaded"
	}
	if need == "" {
		need = "no"
	}
	if command == "" {
		command = "{ path=/usr/local/bin/stl ; argv[]=/usr/local/bin/stl link restore --all ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
	}
	return "ExecStart=" + command + "\n" +
		"LoadState=" + load + "\n" +
		"FragmentPath=" + r.fragment + "\n" +
		"DropInPaths=" + r.dropIns + "\n" +
		"NeedDaemonReload=" + need + "\n"
}

func (r *effectiveLoadedUnitRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if len(args) > 0 && args[0] == "show" {
		r.commands = append(r.commands, name+" "+strings.Join(args, " "))
		r.showCount++
		absentQuery := reflect.DeepEqual(args, absentSystemdShowArgs)
		if name != "systemctl" || (!reflect.DeepEqual(args, effectiveSystemdShowArgs) && !absentQuery) {
			return CommandResult{}, errors.New("unexpected effective systemd show query")
		}
		text := r.showText()
		if absentQuery {
			if _, err := os.Lstat(r.fragment); errors.Is(err, os.ErrNotExist) {
				need := r.needReload
				if need == "" {
					need = "no"
				}
				text = "LoadState=not-found\nFragmentPath=\nDropInPaths=" + r.dropIns +
					"\nNeedDaemonReload=" + need + "\n"
			}
		}
		result := CommandResult{Stdout: []byte(text), Stderr: r.showStderr}
		if r.showStdout != nil {
			result.Stdout = r.showStdout
		}
		return result, r.showErr
	}
	result, err := r.recordingRunner.Run(ctx, name, args...)
	if len(args) == 2 && args[0] == "is-enabled" && r.addDropInAfterIsEnabled {
		r.dropIns = "/run/systemd/system/simple-tun-link-restore.service.d/foreign.conf"
	}
	if len(args) == 2 && args[0] == "disable" && r.addDropInAfterDisable {
		r.dropIns = "/run/systemd/system/simple-tun-link-restore.service.d/foreign.conf"
	}
	if len(args) == 1 && args[0] == "daemon-reload" && r.addDropInAfterDaemonReload {
		r.dropIns = "/run/systemd/system/simple-tun-link-restore.service.d/foreign.conf"
	}
	return result, err
}

func effectiveUnitFixture(t *testing.T) (path string, runner *effectiveLoadedUnitRunner, manager SystemdPersistence) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, restoreSystemdUnitName)
	if err := os.WriteFile(path, ownedRestoreUnitFixture(t, "/usr/local/bin/stl"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner = &effectiveLoadedUnitRunner{fragment: path}
	runner.enabled = map[string]bool{restoreSystemdUnitName: true}
	manager = SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyUnitPath:                  fixtureRootOwnedUnitTrust(t, path),
		VerifyExecutable:                func(string) error { return nil },
		forceEffectiveInspectionForTest: true,
	}
	return
}

func TestForeignEffectiveSystemdDropInsPreventAnyAdoptionOrRetirement(t *testing.T) {
	for _, tc := range []struct {
		name, dropIn string
	}{
		{"foreign drop-in overriding ExecStart",
			"[Service]\nExecStart=\nExecStart=/usr/bin/false\n"},
		{"foreign service directives in type-wide drop-in",
			"[Service]\nExecStartPost=/usr/bin/true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, runner, p := effectiveUnitFixture(t)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			dropin := filepath.Join(t.TempDir(), "foreign.conf")
			if err := os.WriteFile(dropin, []byte(tc.dropIn), 0o600); err != nil {
				t.Fatal(err)
			}
			// Simulate the real manager's effective DropInPaths, including
			// the prefix-wide and service-type directories that direct
			// filesystem checks of the main file would overlook.
			runner.dropIns = dropin
			owned, err := p.IsRestoreInstalled(context.Background())
			if err == nil || owned {
				t.Fatalf("foreign effective unit accepted: %t %v", owned, err)
			}
			if err := p.RemoveRestore(context.Background()); err == nil {
				t.Fatal("foreign effective unit was retired")
			}
			if _, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
				t.Fatal("foreign effective unit was adopted on EnsureRestore")
			}
			for _, cmd := range runner.commands {
				if strings.Contains(cmd, " disable ") ||
					strings.Contains(cmd, " enable ") ||
					strings.Contains(cmd, "daemon-reload") {
					t.Fatalf("foreign effective unit caused mutation: %v", runner.commands)
				}
			}
			if !runner.enabled[restoreSystemdUnitName] || runner.showCount != 3 {
				t.Fatalf("foreign unit enablement changed or inspection omitted: %v", runner.commands)
			}
			now, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, now) {
				t.Fatalf("foreign effective unit's canonical inode changed: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != string(ownedRestoreUnitFixture(t, "/usr/local/bin/stl")) {
				t.Fatalf("canonical main unit modified: %v", err)
			}
			got, err := os.ReadFile(dropin)
			if err != nil || string(got) != tc.dropIn {
				t.Fatalf("foreign drop-in modified: %v", err)
			}
		})
	}
}

func TestLoadedSystemdIdentityMustBeCompleteFreshAndUnambiguous(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*effectiveLoadedUnitRunner)
	}{
		{"wrong canonical fragment", func(r *effectiveLoadedUnitRunner) {
			r.fragment = "/usr/lib/systemd/system/simple-tun-link-restore.service"
		}},
		{"stale manager configuration", func(r *effectiveLoadedUnitRunner) { r.needReload = "yes" }},
		{"masked instead of loaded", func(r *effectiveLoadedUnitRunner) { r.loadState = "masked" }},
		{"different effective ExecStart", func(r *effectiveLoadedUnitRunner) {
			r.execStart = "{ path=/usr/bin/false ; argv[]=/usr/bin/false ; ignore_errors=no ; pid=0 }"
		}},
		{"extra effective ExecStart", func(r *effectiveLoadedUnitRunner) {
			r.execStart = "{ path=/usr/local/bin/stl ; argv[]=/usr/local/bin/stl link restore --all ; ignore_errors=no ; argv[]=/usr/bin/true }"
		}},
		{"duplicate property", func(r *effectiveLoadedUnitRunner) { r.showStdout = []byte(r.showText() + "DropInPaths=\n") }},
		{"missing property", func(r *effectiveLoadedUnitRunner) {
			r.showStdout = []byte(strings.Replace(r.showText(), "NeedDaemonReload=no\n", "", 1))
		}},
		{"extra unknown property", func(r *effectiveLoadedUnitRunner) { r.showStdout = []byte(r.showText() + "Description=foreign\n") }},
		{"truncated manager output", func(r *effectiveLoadedUnitRunner) { r.showStdout = []byte("FragmentPath=" + r.fragment) }},
		{"oversized manager output", func(r *effectiveLoadedUnitRunner) { r.showStdout = []byte(strings.Repeat("X", 5000)) }},
		{"stderr despite success", func(r *effectiveLoadedUnitRunner) { r.showStderr = []byte("foreign") }},
		{"failed systemctl show", func(r *effectiveLoadedUnitRunner) { r.showErr = errors.New("show unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, runner, p := effectiveUnitFixture(t)
			tc.alter(runner)
			err := p.RemoveRestore(context.Background())
			if err == nil {
				t.Fatal("ambiguous manager evidence authorized retirement")
			}
			if len(runner.commands) != 1 || runner.showCount != 1 || !strings.Contains(runner.commands[0], " show ") {
				t.Fatalf("untrusted metadata reached mutating systemctl: %v", runner.commands)
			}
			if !runner.enabled[restoreSystemdUnitName] {
				t.Fatal("ambiguous metadata disabled original unit")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("ambiguous metadata deleted original unit: %v", err)
			}
		})
	}
}

func TestExactEffectiveUnitWithoutDropInsCanRetireOrphan(t *testing.T) {
	path, runner, p := effectiveUnitFixture(t)
	owned, err := p.IsRestoreInstalled(context.Background())
	if err != nil || !owned {
		t.Fatalf("canonical full effective unit rejected: %t %v", owned, err)
	}
	if err := p.RemoveRestore(context.Background()); err != nil {
		t.Fatalf("canonical effective orphan retirement failed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical main unit not retired: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("confirmed owned orphan remains enabled")
	}
	if runner.showCount < 3 {
		t.Fatalf("effective unit not rechecked across external systemctl operations: %v", runner.commands)
	}
}

func TestDropInAppearingDuringSystemdInspectionBlocksDisable(t *testing.T) {
	path, runner, p := effectiveUnitFixture(t)
	runner.addDropInAfterIsEnabled = true
	if err := p.RemoveRestore(context.Background()); err == nil {
		t.Fatal("new drop-in during is-enabled was not detected")
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("foreign effective unit was disabled")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("canonical main unit retired after observed foreign drop-in: %v", err)
	}
	for _, cmd := range runner.commands {
		if strings.Contains(cmd, " disable ") {
			t.Fatalf("foreign effective unit disabled: %v", runner.commands)
		}
	}
}

func TestDropInAppearingAfterDisableBlocksCanonicalDeletion(t *testing.T) {
	path, runner, p := effectiveUnitFixture(t)
	runner.addDropInAfterDisable = true
	err := p.RemoveRestore(context.Background())
	if err == nil || !strings.Contains(err.Error(), "effective systemd unit changed") {
		t.Fatalf("late effective mutation not reported: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("canonical main unit deleted after a foreign drop-in appeared: %v", err)
	}
	if len(runner.commands) == 0 || runner.showCount < 3 {
		t.Fatalf("no post-systemctl read-only inspection: %v", runner.commands)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "daemon-reload") {
			t.Fatalf("foreign effective unit reached destructive retirement: %v", runner.commands)
		}
	}
}

func absentEffectiveUnitFixture(t *testing.T) (string, *effectiveLoadedUnitRunner, SystemdPersistence) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName) // intentionally absent
	runner := &effectiveLoadedUnitRunner{fragment: path}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyUnitPath:                  func(string) error { return nil },
		VerifyExecutable:                func(string) error { return nil },
		forceEffectiveInspectionForTest: true,
	}
	return path, runner, manager
}

func TestMissingMainUnitWithForeignEffectiveDropInIsNotClean(t *testing.T) {
	for _, tc := range []struct{ name, dropIns, needReload string }{
		{"foreign runtime drop-in", "/run/systemd/system/simple-tun-link-restore.service.d/foreign.conf", ""},
		{"foreign type-wide drop-in", "/etc/systemd/system/service.d/site.conf", ""},
		{"stale manager without main unit", "", "yes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, runner, p := absentEffectiveUnitFixture(t)
			runner.dropIns, runner.needReload = tc.dropIns, tc.needReload
			installed, err := p.IsRestoreInstalled(context.Background())
			if err == nil || installed {
				t.Fatalf("foreign effective absence treated as clean: %t %v", installed, err)
			}
			if err := p.RemoveRestore(context.Background()); err == nil {
				t.Fatal("missing canonical unit with foreign effective configuration was retired")
			}
			if _, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
				t.Fatal("missing canonical unit with foreign effective configuration was adopted")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe first install published canonical main file: %v", err)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, " enable ") || strings.Contains(command, " disable ") ||
					strings.Contains(command, "daemon-reload") {
					t.Fatalf("foreign effective unit reached systemctl mutation: %v", runner.commands)
				}
			}
			if runner.showCount != 3 {
				t.Fatalf("absence inspection omitted: %v", runner.commands)
			}
		})
	}
}

// A foreign drop-in appearing during the daemon-reload after STL publishes
// its new unit must not strand that main fragment or enable any foreign
// configuration. Existing guarded compensation retires only the newly
// published and positively pinned STL-origin inode.
func TestNewUnitPublicationCompensatesWhenForeignDropInAppears(t *testing.T) {
	path, runner, p := absentEffectiveUnitFixture(t)
	runner.addDropInAfterDaemonReload = true
	undo, changed, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || changed || undo != nil {
		t.Fatalf("foreign drop-in after reload was accepted: changed=%t err=%v", changed, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("STL-owned incomplete publication was not safely compensated: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("foreign systemd service was unexpectedly enabled")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " enable ") || strings.Contains(command, " disable ") {
			t.Fatalf("failed new unit invoked service enable/disable: %v", runner.commands)
		}
	}
	if runner.dropIns == "" {
		t.Fatal("test lost foreign drop-in evidence")
	}
}

func TestFreshAbsentEffectiveUnitAllowsFirstInstallAndGuardedRetirement(t *testing.T) {
	path, runner, p := absentEffectiveUnitFixture(t)
	installed, err := p.IsRestoreInstalled(context.Background())
	if err != nil || installed {
		t.Fatalf("verified first-use empty host rejected: %t %v", installed, err)
	}
	if err := p.RemoveRestore(context.Background()); err != nil {
		t.Fatalf("idempotent fully absent restore removal failed: %v", err)
	}
	undo, changed, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err != nil || !changed || undo == nil {
		t.Fatalf("fresh install failed after strict manager proof: %t %v", changed, err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("fresh canonical unit not installed: %v", err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("fresh canonical unit not durably enabled")
	}
	if err := p.RemoveRestore(context.Background()); err != nil {
		t.Fatalf("strictly admitted first-install unit could not retire: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned canonical restore unit remains: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("owned restore unit still enabled after retirement")
	}
	if runner.showCount < 8 {
		t.Fatalf("first-install and retirement did not re-attest manager identity: %v", runner.commands)
	}
}
