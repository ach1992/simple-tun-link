package linux

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These cases inject changes to the INCOMING staging name immediately before
// renameat2(RENAME_EXCHANGE). A successful OLD-side check alone is insufficient.
// The unchanged previous STL inode must survive and systemctl must not reload
// a substituted incoming systemd unit.
func TestAtomicExchangeRejectsUnverifiedIncomingIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, mutation string
	}{
		{"replaced inode, foreign text", "foreign"},
		{"replaced inode, identical text", "same-text-other-inode"},
		{"incoming contents changed in place", "edit-in-place"},
		{"staging replaced by symlink", "symlink"},
		{"staging replaced by unwritten FIFO", "fifo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, unitPath, previous, runner, p := newCompensationFixture(t, true, true)
			oldInfo, err := os.Lstat(unitPath)
			if err != nil {
				t.Fatal(err)
			}
			foreign := []byte("[Unit]\nDescription=independent incoming identity\n")
			var originalIncoming string
			var expectedForeign []byte
			var symlinkTarget string
			p.beforeUnitMutation = func(phase string) {
				if phase != "replace" {
					return
				}
				stages, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
				if err != nil || len(stages) != 1 {
					t.Fatalf("incoming stage not found: %v %v", stages, err)
				}
				stage := stages[0]
				incomingContent, err := os.ReadFile(stage)
				if err != nil {
					t.Fatal(err)
				}
				switch tc.mutation {
				case "edit-in-place":
					expectedForeign = foreign
					if err := os.WriteFile(stage, foreign, 0o644); err != nil {
						t.Fatal(err)
					}
				default:
					originalIncoming = filepath.Join(dir, "original-intended-incoming")
					if err := os.Rename(stage, originalIncoming); err != nil {
						t.Fatal(err)
					}
					switch tc.mutation {
					case "foreign":
						expectedForeign = foreign
						err = os.WriteFile(stage, foreign, 0o644)
					case "same-text-other-inode":
						expectedForeign = incomingContent
						err = os.WriteFile(stage, incomingContent, 0o644)
					case "symlink":
						symlinkTarget = filepath.Join(dir, "third-party-unit")
						if err := os.WriteFile(symlinkTarget, foreign, 0o644); err != nil {
							t.Fatal(err)
						}
						err = os.Symlink(symlinkTarget, stage)
					case "fifo":
						makeNoWriterFIFO(t, stage)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			done := make(chan error, 1)
			go func() {
				_, _, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
				done <- err
			}()
			var activationErr error
			select {
			case activationErr = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("untrusted FIFO/symlink incoming stage blocked guarded exchange")
			}
			if !errors.Is(activationErr, errUnitIdentityConflict) {
				t.Fatalf("incoming replacement not rejected as conflict: %v", activationErr)
			}
			if len(runner.commands) != 1 || !strings.HasPrefix(runner.commands[0], "systemctl is-enabled ") {
				t.Fatalf("unverified incoming unit reached systemctl mutation: %v", runner.commands)
			}
			if !runner.enabled[restoreSystemdUnitName] {
				t.Fatal("pre-existing enablement changed during rejected publication")
			}
			canonicalData, err := os.ReadFile(unitPath)
			if err != nil || !bytes.Equal(canonicalData, previous) {
				t.Fatalf("prior STL unit lost from canonical pathname: %q %v", canonicalData, err)
			}
			canonicalInfo, err := os.Lstat(unitPath)
			if err != nil || !os.SameFile(oldInfo, canonicalInfo) {
				t.Fatalf("previous legitimate inode was destroyed or replaced: %v", err)
			}
			if originalIncoming != "" {
				if _, err := os.Lstat(originalIncoming); err != nil {
					t.Fatalf("operator-preserved original incoming staging vanished: %v", err)
				}
			}
			stages, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
			if err != nil || len(stages) != 1 {
				t.Fatalf("displaced unexpected incoming identity not preserved at staging: %v %v", stages, err)
			}
			stage := stages[0]
			switch tc.mutation {
			case "fifo":
				info, err := os.Lstat(stage)
				if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
					t.Fatalf("incoming FIFO identity lost: %v %v", info, err)
				}
			case "symlink":
				target, err := os.Readlink(stage)
				if err != nil || target != symlinkTarget {
					t.Fatalf("incoming symlink identity lost: %q %v", target, err)
				}
			default:
				stageContents, err := os.ReadFile(stage)
				if err != nil || !bytes.Equal(stageContents, expectedForeign) {
					t.Fatalf("unexpected incoming unit was discarded: %q %v", stageContents, err)
				}
			}
		})
	}
}

// A late independent canonical replacement stays installed at its own
// pathname. The displaced prior STL inode remains privately recoverable;
// reversing would improperly relocate independent canonical configuration.
func TestLateCanonicalReplacementStillRetainsBothExchangeIdentities(t *testing.T) {
	dir, path, oldContent, runner, p := newCompensationFixture(t, true, true)
	oldInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	foreign := []byte("[Unit]\nDescription=late administrator replacement\n")
	savedIncoming := filepath.Join(dir, "original-intended-new-unit")
	var injected bool
	p.afterUnitTransition = func(phase string) {
		if phase != "before-verified-staging-retirement" || injected {
			return
		}
		injected = true
		if err := os.Rename(path, savedIncoming); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, foreign, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = p.EnsureRestore(context.Background(), "/opt/stl/stl")
	activationErr := err
	if !errors.Is(err, errUnitIdentityConflict) || !injected {
		t.Fatalf("late canonical replacement was not rejected: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || os.SameFile(info, oldInfo) {
		t.Fatalf("late independent canonical identity was displaced: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, foreign) {
		t.Fatalf("late independent canonical contents changed: %q %v", content, err)
	}
	stages, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
	if err != nil || len(stages) != 1 {
		t.Fatalf("prior STL recovery stage missing: %v %v", stages, err)
	}
	recoveryInfo, err := os.Lstat(stages[0])
	if err != nil || !os.SameFile(recoveryInfo, oldInfo) {
		t.Fatalf("previous STL inode not preserved in recovery: %v", err)
	}
	recovered, err := os.ReadFile(stages[0])
	if err != nil || !bytes.Equal(recovered, oldContent) {
		t.Fatalf("previous STL contents not preserved: %q %v", recovered, err)
	}
	if _, err := os.Stat(savedIncoming); err != nil {
		t.Fatal("original incoming staging not preserved")
	}
	if !strings.Contains(activationErr.Error(), stages[0]) || !strings.Contains(activationErr.Error(), "reversal=false") {
		t.Fatalf("error did not identify incomplete recovery: %v", activationErr)
	}
	if len(runner.commands) != 1 || runner.commands[0] != "systemctl is-enabled "+restoreSystemdUnitName {
		t.Fatalf("late external replacement reached systemctl: %v", runner.commands)
	}
}

func TestIncomingConflictRetainsRecoveryAfterDirectorySyncFailure(t *testing.T) {
	dir, path, prior, runner, p := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=unverified input staging\n")
	durabilityError := errors.New("simulated unit directory sync failure")
	p.syncUnitDirectory = func(string) error { return durabilityError }
	p.beforeUnitMutation = func(phase string) {
		if phase != "replace" {
			return
		}
		names, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
		if err != nil || len(names) != 1 {
			t.Fatalf("missing incoming stage: %v %v", names, err)
		}
		if err := os.WriteFile(names[0], foreign, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
	if !errors.Is(err, errUnitIdentityConflict) || !errors.Is(err, durabilityError) {
		t.Fatalf("incomplete conflict recovery was concealed: %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, prior) {
		t.Fatalf("previous unit lost: %q %v", current, err)
	}
	names, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
	if err != nil || len(names) != 1 {
		t.Fatalf("recoverable staging lost: %v %v", names, err)
	}
	displaced, err := os.ReadFile(names[0])
	if err != nil || !bytes.Equal(displaced, foreign) {
		t.Fatalf("incoming identity lost: %q %v", displaced, err)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}

// The old displaced inode may be changed in private staging AFTER the
// exchange. Restoring that later object to canonical would be equally unsafe
// as displacing a changed independent canonical unit.
func TestPostExchangeStagingReplacementCannotBecomeCanonical(t *testing.T) {
	dir, path, prior, runner, p := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=other actor inserted into private recovery\n")
	var savedOld string
	p.afterUnitTransition = func(phase string) {
		if phase != "after-atomic-exchange" {
			return
		}
		stages, err := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
		if err != nil || len(stages) != 1 {
			t.Fatalf("private displacement missing: %v %v", stages, err)
		}
		savedOld = filepath.Join(dir, "displaced-original-stl")
		if err := os.Rename(stages[0], savedOld); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stages[0], foreign, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
	if !errors.Is(err, errUnitIdentityConflict) || !strings.Contains(err.Error(), "reversal=false") {
		t.Fatalf("post-exchange staging swap was treated as safe reverse: %v", err)
	}
	got, e := os.ReadFile(path)
	if e != nil || !strings.Contains(string(got), "ExecStart=/opt/stl/stl") {
		t.Fatalf("unverified foreign stage was installed as canonical: %q %v", got, e)
	}
	got, e = os.ReadFile(savedOld)
	if e != nil || !bytes.Equal(got, prior) {
		t.Fatalf("previous owned inode not recoverable: %q %v", got, e)
	}
	stages, e := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
	if e != nil || len(stages) != 1 {
		t.Fatalf("foreign stage was unlinked: %v %v", stages, e)
	}
	got, e = os.ReadFile(stages[0])
	if e != nil || !bytes.Equal(got, foreign) || !strings.Contains(err.Error(), stages[0]) {
		t.Fatalf("foreign recovery material or error path was lost: %q %v err=%v", got, e, err)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}

// Byte-identical replacement is still a different canonical identity; the
// rollback cannot displace it merely because its contents resemble STL text.
func TestLateCanonicalByteIdenticalForeignInodeIsNotReversed(t *testing.T) {
	dir, path, _, runner, p := newCompensationFixture(t, true, true)
	var laterInfo os.FileInfo
	var laterBytes []byte
	p.afterUnitTransition = func(phase string) {
		if phase != "before-verified-staging-retirement" {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		laterBytes = b
		if err := os.Rename(path, path+".original-incoming"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		laterInfo, err = os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := p.EnsureRestore(context.Background(), "/opt/stl/stl")
	if !errors.Is(err, errUnitIdentityConflict) || !strings.Contains(err.Error(), "reversal=false") {
		t.Fatalf("different incoming canonical inode was silently accepted: %v", err)
	}
	now, e := os.Lstat(path)
	if e != nil || !os.SameFile(now, laterInfo) {
		t.Fatalf("independent byte-identical canonical inode was displaced: %v", e)
	}
	data, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(data, laterBytes) {
		t.Fatalf("new independent canonical contents changed: %q %v", data, e)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("unexpected systemctl mutation on canonical identity conflict: %v", runner.commands)
	}
	oldStages, e := filepath.Glob(filepath.Join(dir, ".stl-unit-*.tmp"))
	if e != nil || len(oldStages) != 1 {
		t.Fatalf("prior STL staging was lost: %v %v", oldStages, e)
	}
}
