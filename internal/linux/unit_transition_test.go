package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	// The newer replacement rollback reproduced identical old bytes but
	// published a DIFFERENT inode. A stale closure from the original create
	// must not claim ownership of that new inode merely by content equality.
	if err := undo(context.Background()); !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("stale first-install undo falsely claimed a different inode: %v", err)
	}
	if err := manager.RemoveRestore(context.Background()); err != nil {
		t.Fatalf("explicit owned unit removal after stale undo failed: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first unit undo failed to remove own unit: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("initial install undo did not disable unit")
	}
	for _, pattern := range []string{".stl-unit-*.tmp", ".stl-retire-*.tmp"} {
		leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), pattern))
		if err != nil || len(leftovers) != 0 {
			t.Fatalf("successful owned lifecycle leaked private staging: %v %v", leftovers, err)
		}
	}
}

// A second independently installed canonical unit must remain canonical
// even when the first external identity is recoverable in staging. Old-side
// correctness alone is never authorization to reverse/displace the second.
func TestConflictReverseNeverUnlinksSecondForeignIdentity(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, true, true)
	foreignFirst := []byte("[Unit]\nDescription=first external identity\n")
	foreignSecond := []byte("[Unit]\nDescription=second external identity\n")
	var preservedIncoming string
	preExchangeMutation := func(phase string) {
		if phase == "before-atomic-exchange" {
			if err := os.WriteFile(path, foreignFirst, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	manager.afterUnitTransition = func(phase string) {
		preExchangeMutation(phase)
		if phase == "after-atomic-exchange" {
			preservedIncoming = path + ".incoming-preserved"
			if err := os.Rename(path, preservedIncoming); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, foreignSecond, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if !errors.Is(err, errUnitIdentityConflict) || !strings.Contains(err.Error(), "retained at") {
		t.Fatalf("conflict reversal did not preserve recovery location: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(foreignSecond) {
		t.Fatalf("new independent canonical identity was displaced: %q %v", got, readErr)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-unit-*.tmp"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("second displaced identity not preserved: %v %v", matches, err)
	}
	got, readErr = os.ReadFile(matches[0])
	if readErr != nil || string(got) != string(foreignFirst) {
		t.Fatalf("first independently owned recovery identity was lost: %q %v", got, readErr)
	}
	incoming, readErr := os.ReadFile(preservedIncoming)
	if readErr != nil || !strings.Contains(string(incoming), "ExecStart=/opt/stl/stl") {
		t.Fatalf("STL's attempted unit not recoverable: %q %v", incoming, readErr)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("old enablement unexpectedly disabled")
	}
}

func TestProvenConflictReverseRetainsUnexpectedPostReversalStaging(t *testing.T) {
	dir, path, original, _, manager := newCompensationFixture(t, true, true)
	old, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("[Unit]\nDescription=first external canonical\n")
	later := []byte("[Unit]\nDescription=post-reversal external staging\n")
	// Model the syscall result in isolation: the current canonical pathname
	// is the EXACT incoming STL inode, while staging contains the original
	// canonical object independently captured immediately before exchange.
	installed, err := renderRestoreSystemdUnit("/opt/stl/stl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(installed), 0o644); err != nil {
		t.Fatal(err)
	}
	incoming, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(dir, ".stl-unit-post-reverse.tmp")
	if err := os.WriteFile(stage, first, 0o644); err != nil {
		t.Fatal(err)
	}
	preExchange, err := os.Lstat(stage)
	if err != nil {
		t.Fatal(err)
	}
	var incomingPreserved string
	manager.afterUnitTransition = func(phase string) {
		if phase != "after-conflict-reverse" {
			return
		}
		incomingPreserved = filepath.Join(dir, "reversed-original-incoming")
		if err := os.Rename(stage, incomingPreserved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stage, later, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err = manager.reconcileExchangeConflict(dir, path, stage, old, incoming, preExchange, original, []byte(installed), first)
	if !errors.Is(err, errUnitIdentityConflict) || !strings.Contains(err.Error(), "reversal=true") {
		t.Fatalf("proven reverse was unexpectedly rejected: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(first) {
		t.Fatalf("previous independent canonical unit not returned: %q %v", got, readErr)
	}
	got, readErr = os.ReadFile(stage)
	if readErr != nil || string(got) != string(later) {
		t.Fatalf("post-reversal independent staging deleted: %q %v", got, readErr)
	}
	got, readErr = os.ReadFile(incomingPreserved)
	if readErr != nil || string(got) != installed {
		t.Fatalf("STL's displaced publication lost: %q %v", got, readErr)
	}
}

func TestRetirementConflictRetainsRecoveryOnDirectorySyncFailure(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=foreign replaced canonical\n")
	syncFailure := errors.New("simulated directory sync failure")
	manager.beforeUnitMutation = func(phase string) {
		if phase == "delete" {
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var invoked int
	manager.syncUnitDirectory = func(string) error {
		invoked++
		return syncFailure
	}
	err := manager.RemoveRestore(context.Background())
	if !errors.Is(err, errUnitIdentityConflict) || !errors.Is(err, syncFailure) ||
		!strings.Contains(err.Error(), "retained at") {
		t.Fatalf("incomplete conflict durability concealed: %v", err)
	}
	if invoked != 1 {
		t.Fatalf("did not exercise foreign restoration directory sync: %d", invoked)
	}
	backups, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-retire-*.tmp"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("recovery material not retained: %v %v", backups, err)
	}
	canonical, err := os.Stat(path)
	if err != nil {
		t.Fatalf("exclusive canonical re-link did not occur: %v", err)
	}
	recovery, err := os.Stat(backups[0])
	if err != nil || !os.SameFile(canonical, recovery) {
		t.Fatalf("private backup not same displaced inode: canonical=%v backup=%v err=%v", canonical, recovery, err)
	}
	got, err := os.ReadFile(backups[0])
	if err != nil || string(got) != string(foreign) {
		t.Fatalf("recovery backup contents lost: %q %v", got, err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("failed removal unexpectedly reenabled external identity")
	}
}

func TestRetirementConflictRetainsBackupAfterSuccessfulExclusiveRestore(t *testing.T) {
	_, path, _, _, manager := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=independent\n")
	manager.beforeUnitMutation = func(phase string) {
		if phase == "delete" {
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	err := manager.RemoveRestore(context.Background())
	if !errors.Is(err, errUnitIdentityConflict) || !strings.Contains(err.Error(), "retained at") {
		t.Fatalf("normal foreign conflict not reported with recovery path: %v", err)
	}
	backups, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-retire-*.tmp"))
	if len(backups) != 1 {
		t.Fatalf("foreign backup absent after conflict restoration: %v", backups)
	}
	got, err := os.ReadFile(backups[0])
	if err != nil || string(got) != string(foreign) {
		t.Fatalf("recovery file lost: %q %v", got, err)
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != string(foreign) {
		t.Fatalf("foreign identity not restored: %q %v", got, err)
	}
}

func TestDisplacedNonregularFilesNeverReachBlockingContentReads(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
	}{
		{"exchange displaced FIFO", "replace"},
		{"restore exchange displaced FIFO", "restore"},
		{"retirement displaced FIFO", "delete"},
		{"new unit rollback displaced FIFO", "restore-delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existed := tc.phase != "restore-delete"
			_, path, _, runner, manager := newCompensationFixture(t, existed, existed)
			if tc.phase == "restore" {
				runner.failOnce = "systemctl daemon-reload"
			}
			if tc.phase == "restore-delete" {
				manager.afterUnitPublish = func() error { return errUnitAfterRename }
			}
			manager.beforeUnitMutation = func(phase string) {
				if phase == tc.phase {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					makeNoWriterFIFO(t, path)
				}
			}
			result := make(chan error, 1)
			go func() {
				switch tc.phase {
				case "delete":
					result <- manager.RemoveRestore(context.Background())
				default:
					_, _, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
					result <- err
				}
			}()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("unexpected FIFO transition accepted")
				}
				if !errors.Is(err, errUnitIdentityConflict) {
					t.Fatalf("FIFO displaced identity not reported as conflict: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("transition blocked reading displaced FIFO with no writer")
			}
			// Displaced FIFO should be either restored under the canonical name
			// or left at a protected recovery path; never read or silently lost.
			canonical, e := os.Lstat(path)
			if e == nil && canonical.Mode()&os.ModeNamedPipe != 0 {
				return
			}
			stage, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-*.tmp"))
			found := false
			for _, name := range stage {
				info, err := os.Lstat(name)
				if err == nil && info.Mode()&os.ModeNamedPipe != 0 {
					found = true
				}
			}
			if !found {
				t.Fatalf("displaced FIFO not recovered or preserved: canonical=%v err=%v stages=%v", canonical, e, stage)
			}
		})
	}
}

func TestVerifiedNormalExchangeDoesNotDeleteChangedStaging(t *testing.T) {
	_, path, prior, runner, manager := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=new external staging identity\n")
	var originalOld string
	var mutated bool
	manager.afterUnitTransition = func(phase string) {
		if phase != "before-verified-staging-retirement" || mutated {
			return
		}
		mutated = true
		matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-unit-*.tmp"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("expected one displaced stage: %v %v", matches, err)
		}
		originalOld = matches[0] + ".original-preserved"
		if err := os.Rename(matches[0], originalOld); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(matches[0], foreign, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if err == nil || !errors.Is(err, errUnitIdentityConflict) || !strings.Contains(err.Error(), "retained at") {
		t.Fatalf("external staging mutation was not detected: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-unit-*.tmp"))
	if len(matches) != 1 {
		t.Fatalf("unverified staging identity was not preserved: %v", matches)
	}
	got, readErr := os.ReadFile(matches[0])
	if readErr != nil || string(got) != string(foreign) {
		t.Fatalf("foreign staging deleted during normal exchange: %q %v", got, readErr)
	}
	old, readErr := os.ReadFile(originalOld)
	if readErr != nil || string(old) != string(prior) {
		t.Fatalf("displaced original owned unit unavailable: %q %v", old, readErr)
	}
	// The Engine-level compensation restores previously committed bytes but
	// must leave unrelated private staging alone.
	restored, readErr := os.ReadFile(path)
	if readErr != nil || string(restored) != string(prior) {
		t.Fatalf("published unit not safely compensated: %q %v", restored, readErr)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("previously enabled unit became disabled")
	}
}

func TestVerifiedNormalRetirementNeverDeletesChangedBackup(t *testing.T) {
	_, path, _, runner, manager := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=new external recovery identity\n")
	var savedOwned string
	manager.afterUnitTransition = func(phase string) {
		if phase != "before-verified-backup-retirement" {
			return
		}
		matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-retire-*.tmp"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("expected one private retiring unit: %v %v", matches, err)
		}
		savedOwned = matches[0] + ".owned-saved"
		if err := os.Rename(matches[0], savedOwned); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(matches[0], foreign, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := manager.RemoveRestore(context.Background())
	if err == nil || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("normal retirement staging change not detected: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-retire-*.tmp"))
	if len(matches) != 1 {
		t.Fatalf("new administrator recovery identity was deleted: %v", matches)
	}
	got, e := os.ReadFile(matches[0])
	if e != nil || string(got) != string(foreign) {
		t.Fatalf("foreign recovery object lost: %q %v", got, e)
	}
	if _, e := os.Lstat(savedOwned); e != nil {
		t.Fatalf("previous owned moved unit lost: %v", e)
	}
	got, e = os.ReadFile(path)
	if e != nil || !strings.Contains(string(got), managedSystemdMarker) {
		t.Fatalf("owned unit not restored after error: %q %v", got, e)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("previous enabled state not compensated")
	}
}

func TestConflictStagingDirectorySyncFailureRetainsRecoverableObjects(t *testing.T) {
	_, path, _, _, manager := newCompensationFixture(t, true, true)
	foreign := []byte("[Unit]\nDescription=independent\n")
	failedSync := errors.New("simulated fsync in conflict recovery")
	manager.afterUnitTransition = func(phase string) {
		if phase == "before-atomic-exchange" {
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	manager.syncUnitDirectory = func(string) error { return failedSync }
	_, _, err := manager.EnsureRestore(context.Background(), "/opt/stl/stl")
	if err == nil || !errors.Is(err, failedSync) || !errors.Is(err, errUnitIdentityConflict) {
		t.Fatalf("uncertain conflict durability hidden: %v", err)
	}
	stage, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".stl-unit-*.tmp"))
	if len(stage) != 1 {
		t.Fatalf("private staging deleted on fsync failure: %v", stage)
	}
	contents, e := os.ReadFile(stage[0])
	if e != nil || string(contents) != string(foreign) {
		t.Fatalf("untrusted displaced canonical material lost: %q %v", contents, e)
	}
	contents, e = os.ReadFile(path)
	if e != nil || !strings.Contains(string(contents), "ExecStart=/opt/stl/stl") {
		t.Fatalf("unverified but retained incoming STL unit lost: %q %v", contents, e)
	}
}

func TestRetireOwnedDirSyncFailureRetainsOwnedBackup(t *testing.T) {
	dir, path, prior, _, manager := newCompensationFixture(t, true, true)
	syncFail := errors.New("controlled retirement directory fsync failure")
	var calls int
	manager.syncUnitDirectory = func(string) error {
		calls++
		return syncFail
	}
	err := manager.retireOwnedUnit(dir, path, prior, "delete")
	if !errors.Is(err, syncFail) || !strings.Contains(err.Error(), "retained at") {
		t.Fatalf("uncertain owned retirement falsely succeeded: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected initial and best-effort restoration sync: %d", calls)
	}
	backup, _ := filepath.Glob(filepath.Join(dir, ".stl-retire-*.tmp"))
	if len(backup) != 1 {
		t.Fatalf("owned recovery material discarded: %v", backup)
	}
	contents, e := os.ReadFile(backup[0])
	if e != nil || string(contents) != string(prior) {
		t.Fatalf("owned unit not recoverable: %q %v", contents, e)
	}
	contents, e = os.ReadFile(path)
	if e != nil || string(contents) != string(prior) {
		t.Fatalf("canonical owned unit not relinked: %q %v", contents, e)
	}
}
