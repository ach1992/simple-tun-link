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

// All cases use identical TEXT and valid STL markers. The only ownership
// difference is inode identity, which must defeat compensation/undo/control.
func replaceCanonicalWithByteIdenticalInode(t *testing.T, path, saved string) (os.FileInfo, os.FileInfo) {
	t.Helper()
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("test failed to create an independent inode")
	}
	return before, after
}

func TestPostPublicationErrorNeverCompensatesByteIdenticalForeignInode(t *testing.T) {
	for _, existed := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "replacement"}[existed], func(t *testing.T) {
			dir, path, _, runner, p := newCompensationFixture(t, existed, existed)
			saved := filepath.Join(dir, "owned-published-inode")
			var foreign os.FileInfo
			p.afterUnitPublish = func() error {
				_, foreign = replaceCanonicalWithByteIdenticalInode(t, path, saved)
				return errUnitAfterRename
			}
			_, _, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
			if !errors.Is(err, errUnitAfterRename) || !strings.Contains(err.Error(), "uncertain") {
				t.Fatalf("post-publication ownership conflict not surfaced: %v", err)
			}
			now, e := os.Lstat(path)
			if e != nil || !os.SameFile(now, foreign) {
				t.Fatalf("byte-identical independent canonical inode was removed: %v", e)
			}
			copy, e := os.ReadFile(saved)
			current, e2 := os.ReadFile(path)
			if e != nil || e2 != nil || !bytes.Equal(copy, current) {
				t.Fatalf("test did not retain both byte-identical files: %v %v", e, e2)
			}
			expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
			if runner.enabled[restoreSystemdUnitName] != existed {
				t.Fatal("enablement changed during ownership conflict")
			}
		})
	}
}

type replacingUnitRunner struct {
	recordingRunner
	t                      *testing.T
	path                   string
	saved                  string
	replaceAfter           string
	failReplacementCommand bool
	foreign                os.FileInfo
}

func (r *replacingUnitRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	out, err := r.recordingRunner.Run(ctx, name, args...)
	if len(args) > 0 && args[0] == r.replaceAfter {
		_, r.foreign = replaceCanonicalWithByteIdenticalInode(r.t, r.path, r.saved)
		if r.failReplacementCommand {
			return out, errors.New("injected systemctl failure following same-bytes replacement")
		}
	}
	return out, err
}

func TestSystemctlReloadFailureDoesNotRollbackByteIdenticalExternalReplacement(t *testing.T) {
	dir, path, _, _, p := newCompensationFixture(t, false, false)
	runner := &replacingUnitRunner{t: t, path: path, saved: filepath.Join(dir, "owned-before-runner"), replaceAfter: "daemon-reload", failReplacementCommand: true}
	p.Runner = runner
	_, _, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
	if err == nil || !strings.Contains(err.Error(), "compensation uncertain") {
		t.Fatalf("same-content replacement during reload was treated as owned: %v", err)
	}
	now, e := os.Lstat(path)
	if e != nil || !os.SameFile(now, runner.foreign) {
		t.Fatalf("runner's independent canonical file deleted: %v", e)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl daemon-reload")
}

func TestSameBytesNewInodeAfterReloadIsRejectedBeforeEnable(t *testing.T) {
	dir, path, _, _, p := newCompensationFixture(t, false, false)
	runner := &replacingUnitRunner{t: t, path: path, saved: filepath.Join(dir, "owned-before-enable"), replaceAfter: "daemon-reload"}
	p.Runner = runner
	_, _, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
	if !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("foreign inode accepted for enable: %v", err)
	}
	now, e := os.Lstat(path)
	if e != nil || !os.SameFile(now, runner.foreign) {
		t.Fatalf("foreign canonical inode removed: %v", e)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl daemon-reload")
}

func TestStaleUndoNeverDisablesByteIdenticalUnrelatedInode(t *testing.T) {
	dir, path, _, runner, p := newCompensationFixture(t, false, false)
	undo, changed, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
	if err != nil || !changed {
		t.Fatalf("fixture install failed: %v", err)
	}
	beforeCommands := len(runner.commands)
	_, foreign := replaceCanonicalWithByteIdenticalInode(t, path, filepath.Join(dir, "original-published"))
	if err = undo(context.Background()); !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("old rollback closure claimed identical foreign file: %v", err)
	}
	now, e := os.Lstat(path)
	if e != nil || !os.SameFile(now, foreign) {
		t.Fatalf("external canonical inode displaced: %v", e)
	}
	if !runner.enabled[restoreSystemdUnitName] || len(runner.commands) != beforeCommands {
		t.Fatalf("stale undo disabled independent unit: %v", runner.commands[beforeCommands:])
	}
}

func TestRemoveDoesNotDisableByteIdenticalForeignUnitAfterInspection(t *testing.T) {
	dir, path, _, _, p := newCompensationFixture(t, true, true)
	runner := &replacingUnitRunner{t: t, path: path, saved: filepath.Join(dir, "owned-before-inspect"), replaceAfter: "is-enabled"}
	runner.enabled = map[string]bool{restoreSystemdUnitName: true}
	p.Runner = runner
	err := p.RemoveRestore(context.Background())
	if !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("foreign unit not detected before disable: %v", err)
	}
	now, e := os.Lstat(path)
	if e != nil || !os.SameFile(now, runner.foreign) {
		t.Fatalf("byte-identical canonical foreign unit deleted: %v", e)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("independent unit unexpectedly disabled")
	}
}

func TestRemovalCompensationRefusesToReenableByteIdenticalForeignInode(t *testing.T) {
	dir, path, prior, runner, p := newCompensationFixture(t, true, true)
	original, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, foreign := replaceCanonicalWithByteIdenticalInode(t, path, filepath.Join(dir, "original-before-recovery"))
	err = p.compensateRemovedUnit(context.Background(), "systemctl", dir, path, prior, original, true)
	if !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("foreign recovery identity enabled by text alone: %v", err)
	}
	now, e := os.Lstat(path)
	if e != nil || !os.SameFile(now, foreign) {
		t.Fatalf("foreign canonical identity modified: %v", e)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("foreign unit reached systemctl: %v", runner.commands)
	}
}
