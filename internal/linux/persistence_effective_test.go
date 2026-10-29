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
	// Test-only interleaving: independent privileged configuration
	// changes may become visible while a systemctl call is in flight.
	afterSystemctl func([]string, CommandResult, error) (CommandResult, error)
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
			} else {
				// A four-property query never returns an unrequested
				// ExecStart, even while the main file is present.
				text = strings.TrimPrefix(text, "ExecStart="+r.execStart+"\n")
				if r.execStart == "" {
					text = strings.Join(strings.Split(text, "\n")[1:], "\n")
				}
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
	if r.afterSystemctl != nil {
		return r.afterSystemctl(args, result, err)
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

// These tests execute the actual recovery entrypoints, not only the effective
// inspector. In every case the canonical main-file inode initially passes
// ownership admission; the independent change occurs INSIDE an external
// systemctl operation that runs after the initial admission.
func foreignEffectiveCompensationFixture(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "independent-override.conf")
	contents := "[Service]\nExecStart=\nExecStart=/usr/bin/false\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, contents
}

func assertForeignDropInUntouched(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("foreign drop-in modified: %v %q", err, got)
	}
}

func countRunnerSystemctl(commands []string, verb string) int {
	count := 0
	for _, command := range commands {
		if strings.HasPrefix(command, "systemctl "+verb+" ") || command == "systemctl "+verb {
			count++
		}
	}
	return count
}

// Review A-N1-C1 scenario 1: successful disable, followed by a FAILED
// enablement query that also races with an independent drop-in publication.
// The recovery path must not re-enable the newly foreign effective service.
func TestCompensationRefusesForeignDropInDuringFailedPostDisableInspection(t *testing.T) {
	path, runner, p := effectiveUnitFixture(t)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	foreign, foreignContents := foreignEffectiveCompensationFixture(t)
	disabled := false
	runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
		if len(args) == 2 && args[0] == "disable" {
			disabled = true
		}
		if disabled && len(args) == 2 && args[0] == "is-enabled" {
			runner.dropIns = foreign
			return CommandResult{Stdout: []byte("disabled\n")},
				&CommandError{Command: "systemctl", ExitCode: 1, TimedOut: true}
		}
		return result, err
	}
	err = p.RemoveRestore(context.Background())
	if err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("late foreign drift did not report uncertain recovery: %v", err)
	}
	now, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(before, now) {
		t.Fatalf("late drift deleted or replaced original canonical inode: %v", statErr)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("test did not exercise successful disable")
	}
	if countRunnerSystemctl(runner.commands, "disable") != 1 ||
		countRunnerSystemctl(runner.commands, "enable") != 0 ||
		countRunnerSystemctl(runner.commands, "daemon-reload") != 0 {
		t.Fatalf("foreign service was mutated during compensation: %v", runner.commands)
	}
	assertForeignDropInUntouched(t, foreign, foreignContents)
}

// Review A-N1-C1 scenario 2: enable partially succeeds on a newly published
// STL inode, but the command returns error after independent DropInPaths drift.
// No compensation disable OR unproven deletion of the still-present source
// can be authorized by the earlier pinned-file admission.
func TestCompensationRefusesForeignDropInDuringPartialEnableFailure(t *testing.T) {
	path, runner, p := absentEffectiveUnitFixture(t)
	foreign, foreignContents := foreignEffectiveCompensationFixture(t)
	runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
		if len(args) == 2 && args[0] == "enable" {
			runner.dropIns = foreign
			return result, errors.New("injected enable failure after partial enablement")
		}
		return result, err
	}
	undo, changed, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	kind, typed := RestoreFailureOf(err)
	if err == nil || !typed || kind != RestoreEnableFailed || errors.Unwrap(err) == nil ||
		!strings.Contains(errors.Unwrap(err).Error(), "uncertain") || undo != nil || changed {
		t.Fatalf("foreign partial enable unexpectedly reconciled: changed=%t err=%v detail=%v", changed, err, errors.Unwrap(err))
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(ownedRestoreUnitFixture(t, "/usr/local/bin/stl")) {
		t.Fatalf("unproven recovery overwrote/deleted published canonical file: %v", readErr)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("test did not exercise partial enablement")
	}
	if countRunnerSystemctl(runner.commands, "disable") != 0 ||
		countRunnerSystemctl(runner.commands, "enable") != 1 ||
		countRunnerSystemctl(runner.commands, "daemon-reload") != 1 {
		t.Fatalf("foreign unit reached compensation systemctl operations: %v", runner.commands)
	}
	assertForeignDropInUntouched(t, foreign, foreignContents)
}

// Review A-N1-C1 scenario 3: canonical removal happened, but daemon-reload
// failed while an independent drop-in appeared. Source-file restoration is
// allowed only through the positively pinned STL template. It must not be
// followed by another reload or re-enable of the now-foreign effective unit.
func TestCompensationRestoresOnlyOwnedFileAfterRetireReloadDrift(t *testing.T) {
	path, runner, p := effectiveUnitFixture(t)
	foreign, foreignContents := foreignEffectiveCompensationFixture(t)
	runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
		if len(args) == 1 && args[0] == "daemon-reload" {
			runner.dropIns = foreign
			return result, errors.New("injected reload failure after external config change")
		}
		return result, err
	}
	err := p.RemoveRestore(context.Background())
	if err == nil || !strings.Contains(err.Error(), "daemon-reload after remove") ||
		!strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("removal race not reported as incomplete: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(ownedRestoreUnitFixture(t, "/usr/local/bin/stl")) {
		t.Fatalf("owned source file not safely restored: %v", readErr)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("foreign effective configuration re-enabled during recovery")
	}
	if countRunnerSystemctl(runner.commands, "disable") != 1 ||
		countRunnerSystemctl(runner.commands, "enable") != 0 ||
		countRunnerSystemctl(runner.commands, "daemon-reload") != 1 {
		t.Fatalf("foreign unit was mutated by compensating systemctl: %v", runner.commands)
	}
	assertForeignDropInUntouched(t, foreign, foreignContents)
}

// Another critical window: disable has already partially succeeded and
// reported an error, compensating daemon-reload succeeds but introduces an
// independently authored drop-in. A new effective inspection must stop
// re-enable, preserving the original proven canonical inode.
func TestCompensationReattestsAfterReloadBeforeReenable(t *testing.T) {
	path, runner, p := effectiveUnitFixture(t)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	foreign, foreignContents := foreignEffectiveCompensationFixture(t)
	runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
		if len(args) == 2 && args[0] == "disable" {
			return result, errors.New("disable reported error after side effect")
		}
		if len(args) == 1 && args[0] == "daemon-reload" {
			runner.dropIns = foreign
		}
		return result, err
	}
	err = p.RemoveRestore(context.Background())
	if err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("unverified post-reload identity re-enabled: %v", err)
	}
	now, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(before, now) {
		t.Fatalf("owned original canonical file was replaced: %v", statErr)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("foreign effective unit was re-enabled")
	}
	if countRunnerSystemctl(runner.commands, "enable") != 0 ||
		countRunnerSystemctl(runner.commands, "disable") != 1 ||
		countRunnerSystemctl(runner.commands, "daemon-reload") != 1 {
		t.Fatalf("foreign effective unit reached compensation enable: %v", runner.commands)
	}
	assertForeignDropInUntouched(t, foreign, foreignContents)
}

// Confirm the shared compensation boundary is also used by an Engine Undo,
// not just synchronous failure paths. The original successful install must
// remain intact when a foreign drop-in is introduced before Undo.
func TestEngineUndoRefusesForeignDropInWithoutDisablingUnit(t *testing.T) {
	path, runner, p := absentEffectiveUnitFixture(t)
	undo, changed, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err != nil || !changed || undo == nil {
		t.Fatalf("cannot establish canonical unit for rollback test: %v", err)
	}
	foreign, contents := foreignEffectiveCompensationFixture(t)
	runner.dropIns = foreign
	commandsBefore := len(runner.commands)
	err = undo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("undo of now-foreign effective unit did not fail closed: %v", err)
	}
	if len(runner.commands) != commandsBefore+1 || !strings.Contains(runner.commands[commandsBefore], " show ") {
		t.Fatalf("foreign Undo attempted systemctl mutation: %v", runner.commands[commandsBefore:])
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("foreign effective unit's canonical main inode disappeared: %v", err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("foreign effective unit was disabled by Undo")
	}
	assertForeignDropInUntouched(t, foreign, contents)
}

// Positive control: the same partially failed enable/disable operations
// must preserve the previously accepted rollback when the effective unit
// remains canonical and has no foreign drop-ins.
// The compensation disable can succeed, yet its subsequent is-enabled
// observation can race with a new foreign drop-in. Even a valid "disabled"
// status cannot authorize source removal without another effective-unit
// attestation.
func TestPublishedCompensationRefusesDriftDuringPostDisableStatus(t *testing.T) {
	path, runner, p := absentEffectiveUnitFixture(t)
	undo, changed, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err != nil || !changed || undo == nil {
		t.Fatalf("cannot establish owned unit: %v", err)
	}
	foreign, contents := foreignEffectiveCompensationFixture(t)
	disabled := false
	runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
		if len(args) == 2 && args[0] == "disable" {
			disabled = true
		}
		if disabled && len(args) == 2 && args[0] == "is-enabled" {
			runner.dropIns = foreign
		}
		return result, err
	}
	previous := countRunnerSystemctl(runner.commands, "daemon-reload")
	err = undo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("foreign effective unit was reconciled from stale status: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("source was removed after foreign drop-in: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("test did not exercise successful compensating disable")
	}
	if countRunnerSystemctl(runner.commands, "disable") != 1 ||
		countRunnerSystemctl(runner.commands, "daemon-reload") != previous {
		t.Fatalf("foreign drop-in reached unverified second compensation mutation: %v", runner.commands)
	}
	assertForeignDropInUntouched(t, foreign, contents)
}

// If independently authored configuration appears DURING a compensating
// enable itself, no preceding read-only proof can make that privileged race
// atomic. Detect the drift immediately afterward, leave the proven original
// main inode in place, and report recovery as unresolved, not successful.
func TestCompensationReportsDriftDuringReenable(t *testing.T) {
	path, runner, p := effectiveUnitFixture(t)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	foreign, contents := foreignEffectiveCompensationFixture(t)
	runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
		if len(args) == 2 && args[0] == "disable" {
			return result, errors.New("partial disable error")
		}
		if len(args) == 2 && args[0] == "enable" {
			runner.dropIns = foreign
		}
		return result, err
	}
	err = p.RemoveRestore(context.Background())
	if err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("post-enable foreign drift was not reported: %v", err)
	}
	now, statErr := os.Lstat(path)
	if statErr != nil || !os.SameFile(before, now) {
		t.Fatalf("previously owned canonical inode lost: %v", statErr)
	}
	if countRunnerSystemctl(runner.commands, "enable") != 1 ||
		countRunnerSystemctl(runner.commands, "disable") != 1 ||
		countRunnerSystemctl(runner.commands, "daemon-reload") != 1 {
		t.Fatalf("unexpected further systemd mutation after re-enable drift: %v", runner.commands)
	}
	assertForeignDropInUntouched(t, foreign, contents)
}

func TestEffectiveCompensationRetainsCanonicalRollback(t *testing.T) {
	t.Run("partially failed enable on new owned unit", func(t *testing.T) {
		path, runner, p := absentEffectiveUnitFixture(t)
		runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
			if len(args) == 2 && args[0] == "enable" {
				return result, errors.New("partial enable reported an error")
			}
			return result, err
		}
		_, changed, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
		kind, typed := RestoreFailureOf(err)
		if err == nil || changed || !typed || kind != RestoreEnableFailed {
			t.Fatalf("failed enable not reported: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canonical compensation did not retire published unit: %v", err)
		}
		if runner.enabled[restoreSystemdUnitName] {
			t.Fatal("canonical failed enablement not rolled back")
		}
		if countRunnerSystemctl(runner.commands, "disable") != 1 {
			t.Fatalf("canonical compensation did not undo partial enable: %v", runner.commands)
		}
	})
	t.Run("partially failed disable of canonical enabled unit", func(t *testing.T) {
		path, runner, p := effectiveUnitFixture(t)
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		runner.afterSystemctl = func(args []string, result CommandResult, err error) (CommandResult, error) {
			if len(args) == 2 && args[0] == "disable" {
				return result, errors.New("partial disable reported an error")
			}
			return result, err
		}
		err = p.RemoveRestore(context.Background())
		if err == nil || !strings.Contains(err.Error(), "disable STL systemd unit") {
			t.Fatalf("failed disable did not preserve initial error: %v", err)
		}
		now, statErr := os.Lstat(path)
		if statErr != nil || !os.SameFile(before, now) {
			t.Fatalf("original canonical inode not preserved: %v", statErr)
		}
		if !runner.enabled[restoreSystemdUnitName] {
			t.Fatal("canonical compensation did not restore prior enablement")
		}
		if countRunnerSystemctl(runner.commands, "enable") != 1 {
			t.Fatalf("canonical compensation did not re-enable prior unit: %v", runner.commands)
		}
	})
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
