// Package maintenance coordinates the installed executable with Link mutation.
// The installer holds an exclusive flock; ordinary Engine mutations hold shared
// flocks without serializing independent Links with each other.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultDirectory = "/usr/local/lib/simple-tun-link"
	CanonicalSTL     = "/usr/local/bin/stl"
	LockName         = ".maintenance.lock"
	RecordName       = "install-record"
)

type Gate struct {
	Directory string
	Canonical string
	// testOnlyUnprivilegedPath permits isolated package tests to use temp
	// paths; production must validate the full root-owned directory chain.
	testOnlyUnprivilegedPath bool
}

func NewInstalledGate() Gate {
	// A supported installer may use an explicit prefix. After an uninstall
	// unlinks the canonical inode, Linux reports that pathname as (deleted);
	// strip that suffix so a queued Engine keeps the original installer's gate.
	running, err := os.Readlink("/proc/self/exe")
	if err == nil {
		running = strings.TrimSuffix(running, " (deleted)")
		if filepath.Base(running) == "stl" && filepath.Base(filepath.Dir(running)) == "bin" {
			prefix := filepath.Dir(filepath.Dir(running))
			return Gate{Directory: filepath.Join(prefix, "lib", "simple-tun-link"), Canonical: filepath.Join(prefix, "bin", "stl")}
		}
	}
	return Gate{Directory: DefaultDirectory, Canonical: CanonicalSTL}
}

func (g Gate) Acquire(ctx context.Context) (func() error, error) {
	if ctx == nil {
		return nil, fmt.Errorf("maintenance context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir := g.Directory
	if dir == "" {
		dir = DefaultDirectory
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("maintenance directory must be an absolute canonical path")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create maintenance directory: %w", err)
	}
	if err := verifyDirectory(dir, g.testOnlyUnprivilegedPath); err != nil {
		return nil, fmt.Errorf("untrusted maintenance directory: %w", err)
	}
	lockPath := filepath.Join(dir, LockName)
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open maintenance lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), lockPath)
	closeWith := func(cause error) (func() error, error) {
		_ = f.Close()
		return nil, cause
	}
	if err := verifyLockFile(f, lockPath, g.testOnlyUnprivilegedPath); err != nil {
		return closeWith(err)
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return closeWith(fmt.Errorf("acquire shared maintenance lock: %w", err))
		}
		select {
		case <-ctx.Done():
			return closeWith(fmt.Errorf("maintenance wait canceled: %w", ctx.Err()))
		case <-ticker.C:
		}
	}
	// Executable identity MUST be rechecked *after* the wait. A process
	// started before an update/uninstall must not resume as the stale binary.
	if err := g.validateExecutableIdentity(dir); err != nil {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return closeWith(err)
	}
	return func() error {
		unlockErr := unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return errors.Join(unlockErr, f.Close())
	}, nil
}

func verifyDirectory(dir string, testPath bool) error {
	for path := dir; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("maintenance path is a symlink or not a directory")
		}
		if !testPath {
			if err := verifyProtected(info); err != nil {
				return err
			}
		}
		if path == "/" {
			return nil
		}
	}
}

func verifyProtected(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("maintenance path is not protected and root-owned")
	}
	return nil
}

func verifyLockFile(f *os.File, path string, testPath bool) error {
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !entry.Mode().IsRegular() || !os.SameFile(opened, entry) {
		return fmt.Errorf("maintenance lock has an untrusted inode")
	}
	if !testPath {
		if err := verifyProtected(opened); err != nil {
			return err
		}
		if opened.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("maintenance lock must be private")
		}
	}
	return nil
}

func (g Gate) validateExecutableIdentity(dir string) error {
	canonical := g.Canonical
	if canonical == "" {
		canonical = CanonicalSTL
	}
	if !filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return fmt.Errorf("maintenance executable path must be absolute and canonical")
	}
	// Only trust installer journals beneath a protected canonical bin
	// directory. A regular COMMITTED pathname alone is never commit proof.
	if err := verifyDirectory(filepath.Dir(canonical), g.testOnlyUnprivilegedPath); err != nil {
		return fmt.Errorf("untrusted executable directory: %w", err)
	}
	entries, err := os.ReadDir(filepath.Dir(canonical))
	if err != nil {
		return fmt.Errorf("cannot inspect installation recovery directories: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".stl-install.") {
			continue
		}
		recovery := filepath.Join(filepath.Dir(canonical), entry.Name())
		info, statErr := os.Lstat(recovery)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("untrusted installer recovery identity; reconcile before Link mutation")
		}
		if err := g.verifyRecoveryJournal(recovery, canonical, dir); err != nil {
			return fmt.Errorf("unresolved installer recovery requires reconciliation before Link mutation: %w", err)
		}
	}
	// For a checkout or manually run binary with no STL managed installation,
	// the lock still protects concurrent installs but there is no managed
	// executable identity to validate. A running managed binary that has been
	// retired after waiting must always fail.
	running, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("cannot resolve running STL executable: %w", err)
	}
	_, recordErr := os.Lstat(filepath.Join(dir, RecordName))
	recordExists := recordErr == nil
	if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
		return fmt.Errorf("cannot inspect installation record: %w", recordErr)
	}
	managedRunning := running == canonical || strings.HasPrefix(running, canonical+" (deleted)")
	if !recordExists && !managedRunning {
		return nil
	}
	installed, err := os.Lstat(canonical)
	if err != nil || !installed.Mode().IsRegular() {
		return fmt.Errorf("installed STL executable is missing or untrusted; restart/reconcile before Link mutation")
	}
	active, err := os.Stat("/proc/self/exe")
	if err != nil || !os.SameFile(installed, active) {
		return fmt.Errorf("STL executable was replaced while this process was pending; relaunch stl before Link mutation")
	}
	return nil
}
