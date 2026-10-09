package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func makeNoWriterFIFO(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// This test intentionally uses an actual unwritten FIFO. A pre-validation
// os.ReadFile would block indefinitely; type checking precedes all reading.
func TestUnitReadRejectsNonregularBeforeBlocking(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
	}{
		{"FIFO with no writer", "fifo"},
		{"symlink to no-writer FIFO", "symlink-fifo"},
		{"directory", "directory"},
		{"symlink to regular unit", "symlink-regular"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, restoreSystemdUnitName)
			switch tc.kind {
			case "fifo":
				makeNoWriterFIFO(t, path)
			case "symlink-fifo":
				fifo := filepath.Join(dir, "unopened-fifo")
				makeNoWriterFIFO(t, fifo)
				if err := os.Symlink(fifo, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink-regular":
				target := filepath.Join(dir, "regular")
				if err := os.WriteFile(target, []byte(managedSystemdMarker+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() {
				_, _, err := readRegularUnit(path)
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("nonregular unit accepted or wrong error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("nonregular unit inspection blocked before type validation")
			}
			runner := &recordingRunner{}
			p := SystemdPersistence{Runner: runner, UnitDir: dir,
				VerifyExecutable: func(string) error { return nil },
				VerifyUnitPath:   func(string) error { return nil }}
			if _, err := p.IsRestoreInstalled(context.Background()); err == nil {
				t.Fatal("nonregular installed identity accepted")
			}
			if err := p.RemoveRestore(context.Background()); err == nil {
				t.Fatal("nonregular unit accepted for deletion")
			}
			if _, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl"); err == nil {
				t.Fatal("nonregular unit accepted for activation")
			}
			if len(runner.commands) != 0 {
				t.Fatalf("nonregular unit caused systemctl side effects: %v", runner.commands)
			}
			if info, err := os.Lstat(path); err != nil || info.Mode().IsRegular() {
				t.Fatalf("nonregular identity was replaced: info=%v err=%v", info, err)
			}
		})
	}
}

func TestUnitReadRejectsOversizedContentsWithoutMutating(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	contents := append([]byte(managedSystemdMarker+"\n"), make([]byte, maxRestoreUnitBytes)...)
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := readRegularUnit(path)
	if err == nil || !strings.Contains(err.Error(), "bounded") {
		t.Fatalf("oversized unit accepted: %v", err)
	}
	runner := &recordingRunner{}
	p := SystemdPersistence{Runner: runner, UnitDir: dir, VerifyUnitPath: func(string) error { return nil }}
	if err := p.RemoveRestore(context.Background()); err == nil {
		t.Fatal("oversized unit accepted for removal")
	}
	if len(runner.commands) > 0 {
		t.Fatalf("oversized unit changed systemctl: %v", runner.commands)
	}
	got, err := os.Stat(path)
	if err != nil || got.Size() != int64(len(contents)) {
		t.Fatalf("oversized unit modified: %v %v", got, err)
	}
}

func TestReadUnitUsesOpenedInodeAndRejectsMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, restoreSystemdUnitName)
	_, _, err := readRegularUnit(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing unit should report not-exist: %v", err)
	}
	original := []byte(managedSystemdMarker + "\n[Unit]\n")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	data, info, err := readRegularUnit(path)
	if err != nil || string(data) != string(original) || !info.Mode().IsRegular() {
		t.Fatalf("regular unit not read safely: %q %v %v", data, info, err)
	}
}
