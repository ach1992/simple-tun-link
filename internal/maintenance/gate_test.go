package maintenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSharedMutationsAndExclusiveInstaller(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "stl")
	if err := os.Link(exe, target); err != nil {
		t.Skipf("hardlinking test executable unavailable: %v", err)
	}
	// Unlike test-only privilege configuration, the actual managed identity
	// must be proven by a persistent installation record.
	if err := os.WriteFile(filepath.Join(dir, RecordName), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := Gate{Directory: dir, Canonical: target, testOnlyUnprivilegedPath: true}
	first, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Join(dir, LockName), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("exclusive installation acquired during active shared Engine mutations: %v", err)
	}
	if err := second(); err != nil {
		t.Fatal(err)
	}
	if err := first(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("exclusive installer failed after both shared acquisitions: %v", err)
	}

	// A process which began before the exclusive update can be queued behind
	// it, but must inspect its *current* executable identity after admission.
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		release, err := g.Acquire(ctx)
		if err == nil {
			_ = release()
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("queued mutation passed exclusive maintenance: %v", err)
	case <-time.After(60 * time.Millisecond):
	}
	replacement := filepath.Join(dir, "next-stl")
	if err := os.WriteFile(replacement, []byte("replacement"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, target); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "relaunch") {
			t.Fatalf("stale admitted Engine must reject replaced executable: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("queued Engine remained blocked after exclusive release")
	}
}

// TestUninstallRejectsQueuedOldBinary reproduces the *real* successful
// uninstall transition: the running canonical executable is unlinked after a
// separate durable backup, both record and alias disappear, and a valid
// uninstall COMMITTED journal is left behind. No systemd verification or
// backend side effect can mask an incorrect maintenance admission.
func TestUninstallRejectsQueuedOldBinary(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	meta := filepath.Join(root, "lib", "simple-tun-link")
	for _, d := range []string{bin, meta} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runningBinary := filepath.Join(bin, "stl")
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(runningBinary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		_ = in.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, in)
	if err := errors.Join(copyErr, out.Close(), in.Close()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(runningBinary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	hash := fmt.Sprintf("%x", sum)
	record := filepath.Join(meta, RecordName)
	if err := os.WriteFile(record, []byte(ownedRecord(hash)), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(bin, "stlink")
	if err := os.Symlink("stl", alias); err != nil {
		t.Fatal(err)
	}
	lockfd, err := unix.Open(filepath.Join(meta, LockName), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(lockfd)
	if err := unix.Flock(lockfd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	exclusiveHeld := true
	defer func() {
		if exclusiveHeld {
			_ = unix.Flock(lockfd, unix.LOCK_UN)
		}
	}()

	readyPath := filepath.Join(root, "gate-ready")
	resultPath := filepath.Join(root, "gate-result")
	mutatedPath := filepath.Join(root, "backend-mutated")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runningBinary, "-test.run=^TestQueuedUninstallGateHelper$", "-test.v")
	cmd.Env = append(os.Environ(),
		"STL_GATE_HELPER=1",
		"STL_GATE_READY="+readyPath,
		"STL_GATE_RESULT="+resultPath,
		"STL_GATE_MUTATED="+mutatedPath,
		"STL_GATE_CANONICAL="+runningBinary)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start real canonical executable: %v", err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queued canonical Engine did not start: %s", output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The child signals its intent to take the shared lock while the
	// installer-exclusive lock remains held. Backend work must not begin.
	time.Sleep(70 * time.Millisecond)
	if _, err := os.Lstat(mutatedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Engine mutated before uninstall maintenance boundary: %v", err)
	}
	stage := filepath.Join(bin, ".stl-install.integration")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	// Same durable previous-stl copy + canonical unlink used by install.sh.
	if err := os.WriteFile(filepath.Join(stage, "previous-stl"), contents, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{alias, runningBinary, record} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, committedName), []byte(journalV1("uninstall", hash)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(lockfd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	exclusiveHeld = false
	if err := cmd.Wait(); err != nil {
		t.Fatalf("queued real Engine test process failed: %v\n%s", err, output.String())
	}
	result, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("missing queued-process verdict: %v\n%s", err, output.String())
	}
	if !strings.HasPrefix(string(result), "DENIED:") ||
		!strings.Contains(string(result), "installed STL executable is missing") ||
		!strings.Contains(string(result), " (deleted)") {
		t.Fatalf("stale Engine escaped actual uninstall pathname transition: %s\n%s", result, output.String())
	}
	if _, err := os.Lstat(mutatedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale process reached backend mutation after uninstall: %v", err)
	}
}

// Runs only as a separately executed Go test binary at <prefix>/bin/stl;
// normal package tests skip this helper without env. It deliberately does not
// configure systemd, proving admission is independent of persistence policy.
func TestQueuedUninstallGateHelper(t *testing.T) {
	if os.Getenv("STL_GATE_HELPER") != "1" {
		return
	}
	canonical := os.Getenv("STL_GATE_CANONICAL")
	resultPath := os.Getenv("STL_GATE_RESULT")
	writeResult := func(status string) {
		if err := os.WriteFile(resultPath, []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g := NewInstalledGate()
	if g.Canonical != canonical {
		writeResult("WRONG_GATE:" + g.Canonical)
		return
	}
	// Only bypass host-root ownership for this user-owned temporary prefix.
	// The managedRunning test itself is never bypassed.
	g.testOnlyUnprivilegedPath = true
	if err := os.WriteFile(os.Getenv("STL_GATE_READY"), []byte("queued"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := g.Acquire(ctx)
	if err == nil {
		_ = release()
		_ = os.WriteFile(os.Getenv("STL_GATE_MUTATED"), []byte("unexpected"), 0o600)
	}
	running, readErr := os.Readlink("/proc/self/exe")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err != nil {
		writeResult(fmt.Sprintf("DENIED:%s :: %v", running, err))
	} else {
		writeResult("ALLOWED:" + running)
	}
}

func installedJournalFixture(t *testing.T) (Gate, string, string) {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "stl")
	if err := os.Link(exe, target); err != nil {
		t.Skipf("hardlinking test executable unavailable: %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	hash := fmt.Sprintf("%x", sum)
	if err := os.WriteFile(filepath.Join(dir, RecordName), []byte(ownedRecord(hash)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("stl", filepath.Join(dir, "stlink")); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(dir, ".stl-install.fixture")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	return Gate{Directory: dir, Canonical: target, testOnlyUnprivilegedPath: true}, stage, hash
}

func ownedRecord(hash string) string {
	return "format=1\nproject=simple-tun-link\nversion=v0.1.0\nsha256=" + hash + "\n"
}

func journalV1(operation, hash string) string {
	return fmt.Sprintf("status=committed\noperation=%s\nsha256=%s\n", operation, hash)
}

func TestCommittedRecoveryRequiresExactStructureAndIdentity(t *testing.T) {
	const fakeHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name   string
		marker func(hash string) string
	}{
		{"empty", func(string) string { return "" }},
		{"status_only", func(string) string { return "status=committed\n" }},
		{"unknown_operation", func(h string) string { return journalV1("unknown", h) }},
		{"malformed_hash", func(string) string { return journalV1("update", "abc") }},
		{"uppercase_hash", func(string) string { return journalV1("update", strings.ToUpper(fakeHash)) }},
		{"correct_shape_wrong_hash", func(string) string { return journalV1("update", fakeHash) }},
		{"no_final_newline", func(h string) string { return strings.TrimSuffix(journalV1("update", h), "\n") }},
		{"extra_field", func(h string) string { return journalV1("install", h) + "extra=1\n" }},
		{"duplicate_status", func(h string) string { return "status=committed\n" + journalV1("install", h) }},
		{"uninstall_but_binary_exists", func(h string) string { return journalV1("uninstall", h) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, stage, hash := installedJournalFixture(t)
			if err := os.WriteFile(filepath.Join(stage, committedName), []byte(tc.marker(hash)), 0o600); err != nil {
				t.Fatal(err)
			}
			if release, err := g.Acquire(context.Background()); err == nil {
				_ = release()
				t.Fatal("ambiguous/corrupt committed journal admitted Engine mutation")
			}
		})
	}

	for _, tc := range []struct {
		name   string
		modify func(t *testing.T, g Gate)
	}{
		{"tampered_record", func(t *testing.T, g Gate) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(g.Directory, RecordName), []byte("format=1\nproject=wrong\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing_record", func(t *testing.T, g Gate) {
			t.Helper()
			if err := os.Remove(filepath.Join(g.Directory, RecordName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong_alias", func(t *testing.T, g Gate) {
			t.Helper()
			alias := filepath.Join(g.Directory, "stlink")
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("wrong", alias); err != nil {
				t.Fatal(err)
			}
		}},
		{"modified_executable", func(t *testing.T, g Gate) {
			t.Helper()
			replacement := filepath.Join(g.Directory, "incoming")
			if err := os.WriteFile(replacement, []byte("foreign executable"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, g.Canonical); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, stage, hash := installedJournalFixture(t)
			if err := os.WriteFile(filepath.Join(stage, committedName), []byte(journalV1("install", hash)), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.modify(t, g)
			if release, err := g.Acquire(context.Background()); err == nil {
				_ = release()
				t.Fatal("inconsistent committed install admitted Engine mutation")
			}
		})
	}
	for _, operation := range []string{"install", "update"} {
		t.Run("valid_"+operation, func(t *testing.T) {
			g, stage, hash := installedJournalFixture(t)
			if err := os.WriteFile(filepath.Join(stage, committedName), []byte(journalV1(operation, hash)), 0o600); err != nil {
				t.Fatal(err)
			}
			release, err := g.Acquire(context.Background())
			if err != nil {
				t.Fatalf("valid committed image unexpectedly refused: %v", err)
			}
			if err := release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUncommittedInstallerRecoveryBlocksEngine(t *testing.T) {
	g, stage, hash := installedJournalFixture(t)
	if release, err := g.Acquire(context.Background()); err == nil {
		_ = release()
		t.Fatal("Engine mutation was admitted while installer recovery lacks COMMITTED")
	}
	if err := os.WriteFile(filepath.Join(stage, committedName), []byte("status=committed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if release, err := g.Acquire(context.Background()); err == nil {
		_ = release()
		t.Fatal("incomplete COMMITTED incorrectly counted as a resolved transaction")
	}
	if err := os.WriteFile(filepath.Join(stage, committedName), []byte(journalV1("install", hash)), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("valid committed installation incorrectly blocked: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}
