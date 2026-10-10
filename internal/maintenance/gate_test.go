package maintenance

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

func TestUninstallRejectsQueuedOldBinary(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "stl")
	if err := os.Link(exe, target); err != nil {
		t.Skipf("hardlinking test executable unavailable: %v", err)
	}
	g := Gate{Directory: dir, Canonical: target, testOnlyUnprivilegedPath: true}
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	// Non-managed test binaries are intentionally allowed without an install
	// record. A queued managed binary with an absent executable is rejected:
	// force the record witness to model uninstall's retired canonical path.
	if err := os.WriteFile(filepath.Join(dir, RecordName), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if release, err := g.Acquire(context.Background()); err == nil {
		_ = release()
		t.Fatal("stale Engine admitted with absent canonical executable")
	}
}

func TestUncommittedInstallerRecoveryBlocksEngine(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "stl")
	if err := os.Link(exe, target); err != nil {
		t.Skipf("hardlinking test executable unavailable: %v", err)
	}
	g := Gate{Directory: dir, Canonical: target, testOnlyUnprivilegedPath: true}
	unsettled := filepath.Join(dir, ".stl-install.incomplete")
	if err := os.Mkdir(unsettled, 0o700); err != nil {
		t.Fatal(err)
	}
	if release, err := g.Acquire(context.Background()); err == nil {
		_ = release()
		t.Fatal("Engine mutation was admitted while installer recovery is uncertain")
	}
	if err := os.WriteFile(filepath.Join(unsettled, "COMMITTED"), []byte("status=committed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("verified-image Engine with committed journal should be allowed: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}
