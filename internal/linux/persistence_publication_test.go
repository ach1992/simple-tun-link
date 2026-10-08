package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var errUnitAfterRename = errors.New("controlled failure after unit rename")

func TestAtomicUnitWriterDistinguishesPublishedFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	if err := writeAtomicFileWithHook(dir, path, []byte("visible"), 0o644, func() error {
		return errUnitAfterRename
	}); err == nil {
		t.Fatal("expected publication failure")
	} else {
		var published *unitPublicationError
		if !errors.As(err, &published) || !errors.Is(err, errUnitAfterRename) {
			t.Fatalf("post-publication failure was not distinguishable: %v", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "visible" {
		t.Fatalf("post-publication failure did not exercise a published file: %q %v", data, err)
	}

	missingParent := filepath.Join(t.TempDir(), "nonexistent")
	err = writeAtomicFile(filepath.Join(missingParent, "units"),
		filepath.Join(missingParent, "units", restoreSystemdUnitName), []byte("new"), 0o644)
	if err == nil {
		t.Fatal("expected pre-publication failure")
	}
	var published *unitPublicationError
	if errors.As(err, &published) {
		t.Fatalf("pre-publication failure was incorrectly labeled published: %v", err)
	}
}

func TestEnsureRestoresFirstPublishedUnitOnDurabilityFailure(t *testing.T) {
	dir := t.TempDir()
	runner := &recordingRunner{}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		afterUnitPublish: func() error { return errUnitAfterRename },
	}
	undo, changed, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || !errors.Is(err, errUnitAfterRename) || undo != nil || changed {
		t.Fatalf("failed publish was accepted: undo=%v changed=%t err=%v", undo != nil, changed, err)
	}
	_, err = os.Stat(filepath.Join(dir, restoreSystemdUnitName))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first install retained unit: %v", err)
	}
	if runner.enabled[restoreSystemdUnitName] {
		t.Fatal("failed install enabled the unit")
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl daemon-reload", "systemctl is-enabled ")
}

func TestEnsureRestoresPriorOwnedEnabledUnitAfterPublicationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	old := []byte(managedSystemdMarker + "\n[Unit]\nDescription=old owned restore\n")
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		afterUnitPublish: func() error { return errUnitAfterRename },
	}
	if _, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl"); !errors.Is(err, errUnitAfterRename) {
		t.Fatalf("expected original publication failure: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(old) {
		t.Fatalf("prior owned enabled unit was not restored: got=%q err=%v", got, err)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("previously enabled unit lost permanent enablement")
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl daemon-reload", "systemctl is-enabled ")
}

func TestEnsureDoesNotOverwriteForeignUnitOnUnknownPublicationOutcome(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	runner := &recordingRunner{}
	foreign := []byte("[Unit]\nDescription=an unrecognized unit\n")
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		afterUnitPublish: func() error {
			if err := os.WriteFile(path, foreign, 0o644); err != nil {
				return err
			}
			return errUnitAfterRename
		},
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("uncertain publication was concealed: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(foreign) {
		t.Fatalf("unknown/foreign unit was overwritten: %q %v", got, readErr)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}

func TestEnsureReportsFailedUnitPublicationCompensation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	runner := &recordingRunner{}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		afterUnitPublish: func() error { return errUnitAfterRename },
		restoreAfterFailure: func(string, string, []byte, bool) error {
			return errors.New("controlled restoration failure")
		},
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "compensation incomplete") || !errors.Is(err, errUnitAfterRename) {
		t.Fatalf("failed rollback was concealed: %v", err)
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || !isOwnedSystemdUnit(contents) {
		t.Fatalf("test did not leave behind the unreconciled published file: %v", readErr)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}

func TestEnsureReportsUnitReloadFailureAfterRestoringOwnedPrior(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	old := []byte(managedSystemdMarker + "\n[Unit]\nDescription=old\n")
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}, failOn: "systemctl daemon-reload"}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		afterUnitPublish: func() error { return errUnitAfterRename },
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "compensation incomplete") {
		t.Fatalf("failed systemd reload after publication was concealed: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(old) {
		t.Fatalf("file rollback failed despite successful atomic restoration: %q %v", got, readErr)
	}
	if !runner.enabled[restoreSystemdUnitName] {
		t.Fatal("prior permanent enablement was disabled after failure")
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl daemon-reload")
}

func expectSystemdOperations(t *testing.T, actual []string, fragments ...string) {
	t.Helper()
	if len(actual) != len(fragments) {
		t.Fatalf("unexpected systemctl operations: got %v, want sequence %v", actual, fragments)
	}
	for i, want := range fragments {
		if !strings.Contains(actual[i], want) {
			t.Fatalf("command %d got %q, expected %q", i, actual[i], want)
		}
	}
}

// Even if the request is canceled after the unit file is published, cleanup
// uses a separate bounded context for the post-compensation daemon reload.
func TestUnitPublicationCompensationAfterCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	runner := &recordingRunner{}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		afterUnitPublish: func() error {
			cancel()
			return errUnitAfterRename
		},
	}
	_, _, err := manager.EnsureRestore(ctx, "/usr/local/bin/stl")
	if err == nil || !errors.Is(err, errUnitAfterRename) {
		t.Fatalf("canceled post-publication failure not reported: %v", err)
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("test did not cancel original request")
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ", "systemctl daemon-reload", "systemctl is-enabled ")
	if _, err := os.Lstat(filepath.Join(dir, restoreSystemdUnitName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned unit was not compensated after caller cancellation: %v", err)
	}
}

// A restoration helper reporting nil does not prove that the prior exact
// content actually returned. The implementation must verify its filesystem
// result rather than trusting only the helper's return value.
func TestUnitPublicationRejectsUnprovenRestoration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	old := []byte(managedSystemdMarker + "\n[Unit]\nDescription=old\n")
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{enabled: map[string]bool{restoreSystemdUnitName: true}}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
		afterUnitPublish: func() error { return errUnitAfterRename },
		restoreAfterFailure: func(string, string, []byte, bool) error {
			return nil // Deliberately lies about restoring the prior content.
		},
	}
	_, _, err := manager.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "contents do not match") {
		t.Fatalf("unproven rollback was treated as successful: %v", err)
	}
	current, readErr := os.ReadFile(path)
	if readErr != nil || string(current) == string(old) {
		t.Fatalf("test did not retain newly published unit: %q %v", current, readErr)
	}
	expectSystemdOperations(t, runner.commands, "systemctl is-enabled ")
}
