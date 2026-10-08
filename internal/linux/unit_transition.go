package linux

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// An identity conflict is not a normal write failure: compensation must not
// try to restore or enable an independently managed unit.
var errUnitIdentityConflict = errors.New("systemd unit identity changed during an atomic transition")

// publishOwnedUnit uses a Linux atomic no-clobber create or an exchange of the
// new unit and the existing expected unit. Exchange never destroys the
// displaced file; after the syscall, the displaced inode/content must still
// match the one validated before it. A foreign last-moment replacement is
// swapped back when the target still refers to STL's new inode.
func (p SystemdPersistence) publishOwnedUnit(dir, path string, content, prior []byte, existed bool) error {
	if !existed {
		if p.beforeUnitMutation != nil {
			p.beforeUnitMutation("create")
		}
		return writeAtomicFileWithHook(dir, path, content, 0o644, p.afterUnitPublish)
	}
	return p.exchangeOwnedUnit(dir, path, prior, content, "replace", p.afterUnitPublish)
}

func (p SystemdPersistence) restorePublishedUnit(dir, path string, published, prior []byte, existed bool) error {
	if !existed {
		return p.retireOwnedUnit(dir, path, published, "restore-delete")
	}
	return p.exchangeOwnedUnit(dir, path, published, prior, "restore", nil)
}

func (p SystemdPersistence) exchangeOwnedUnit(dir, path string, expected, content []byte, phase string, afterPublish func() error) error {
	before, err := p.exactUnitIdentity(path, expected)
	if err != nil {
		return err
	}
	staged, err := createOwnedStagingUnit(dir, content, 0o644)
	if err != nil {
		return err
	}
	cleanupStaged := true
	defer func() {
		if cleanupStaged {
			_ = os.Remove(staged)
		}
	}()
	incoming, err := os.Lstat(staged)
	if err != nil {
		return err
	}
	if p.beforeUnitMutation != nil {
		p.beforeUnitMutation(phase)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, path, unix.RENAME_EXCHANGE); err != nil {
		// No fallback to ordinary rename: it could clobber an external file.
		return fmt.Errorf("atomic guarded unit exchange unavailable: %w", err)
	}
	// The displaced unit is now at the private staging name. Check both the
	// original inode and bytes, not only the marker or expected text.
	displaced, statErr := os.Lstat(staged)
	data, readErr := os.ReadFile(staged)
	matched := statErr == nil && readErr == nil && displaced.Mode().IsRegular() &&
		os.SameFile(before, displaced) && bytes.Equal(data, expected)
	if !matched {
		// Revert by exchange, never by overwriting/deleting the displaced
		// administrator file. If somebody also changed our new canonical
		// inode, keep the displaced inode at the staging path for recovery.
		if current, err := os.Lstat(path); err == nil && os.SameFile(current, incoming) {
			if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, path, unix.RENAME_EXCHANGE); err == nil {
				return fmt.Errorf("%w: external destination retained, guarded exchange reverted", errUnitIdentityConflict)
			}
		}
		// A temp name holding an unknown/foreign inode must not be deleted.
		// Preserve it for administrator-led recovery.
		cleanupStaged = false
		preserved, preserveErr := preserveUnitStaging(staged)
		return fmt.Errorf("%w: cannot safely reverse exchange; displaced unit preserved at %q: %v", errUnitIdentityConflict, preserved, preserveErr)
	}
	// The displaced inode was exactly STL's expected prior unit. Only now
	// is it safe to remove the private copy. The published canonical path is
	// still the new unit when no independent operator intervenes.
	if err := os.Remove(staged); err != nil {
		return &unitPublicationError{cause: fmt.Errorf("retire verified prior unit: %w", err)}
	}
	if err := syncOwnedDir(dir); err != nil {
		return &unitPublicationError{cause: err}
	}
	if afterPublish != nil {
		if err := afterPublish(); err != nil {
			return &unitPublicationError{cause: err}
		}
	}
	return nil
}

// retireOwnedUnit moves the canonical unit to a private recovery filename
// without clobbering an unrelated target. A final inode/content verification
// is performed on the moved object before unlinking the private backup.
// This closes the check-then-unlink window of os.Remove(canonical).
func (p SystemdPersistence) retireOwnedUnit(dir, path string, expected []byte, phase string) error {
	before, err := p.exactUnitIdentity(path, expected)
	if err != nil {
		return err
	}
	backupFile, err := os.CreateTemp(dir, ".stl-retire-*.tmp")
	if err != nil {
		return err
	}
	backup := backupFile.Name()
	_ = backupFile.Close()
	if err := os.Remove(backup); err != nil {
		return err
	}
	if p.beforeUnitMutation != nil {
		p.beforeUnitMutation(phase)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, backup, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("atomic no-replace unit retirement unavailable: %w", err)
	}
	moved, statErr := os.Lstat(backup)
	data, readErr := os.ReadFile(backup)
	matched := statErr == nil && readErr == nil && moved.Mode().IsRegular() &&
		os.SameFile(before, moved) && bytes.Equal(data, expected)
	if !matched {
		// Restore the displaced foreign identity only if canonical remains
		// absent. Never overwrite a newer unit installed concurrently.
		if err := os.Link(backup, path); err == nil {
			_ = syncOwnedDir(dir)
			_ = os.Remove(backup)
			return fmt.Errorf("%w: displaced unexpected identity restored without overwrite", errUnitIdentityConflict)
		}
		return fmt.Errorf("%w: displaced identity preserved for recovery at %q", errUnitIdentityConflict, backup)
	}
	if err := syncOwnedDir(dir); err != nil {
		// Retain a hardlink for safe repair of a partially durable removal.
		if restoreErr := os.Link(backup, path); restoreErr != nil {
			return fmt.Errorf("unit retirement directory sync failed; verified unit retained at %q: %w", backup, errors.Join(err, restoreErr))
		}
		_ = os.Remove(backup)
		return fmt.Errorf("unit retirement directory sync failed: %w", err)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("cannot release verified retired unit staging: %w", err)
	}
	return syncOwnedDir(dir)
}

func (p SystemdPersistence) exactUnitIdentity(path string, expected []byte) (os.FileInfo, error) {
	if err := p.guardExactPublishedUnit(path, expected); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected owned unit is not regular")
	}
	// Reconfirm contents after taking the inode snapshot; an in-place
	// change detected here is an identity conflict, not a reason to write.
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, expected) {
		return nil, fmt.Errorf("%w: expected unit changed during inspection", errUnitIdentityConflict)
	}
	return info, nil
}

func createOwnedStagingUnit(dir string, content []byte, mode os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(dir, ".stl-unit-*.tmp")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	fail := func(err error) (string, error) {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func preserveUnitStaging(name string) (string, error) {
	// The reserved filename itself is intentionally returned to the operator.
	// Caller must not remove it when the outcome cannot be proven safe.
	if _, err := os.Lstat(name); err != nil {
		return "", err
	}
	return filepath.Clean(name), nil
}
