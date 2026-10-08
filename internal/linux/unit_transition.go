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
	// The inode identity comes from the original opened staging descriptor,
	// not a later pathname Lstat that could have inspected a replacement.
	staged, incoming, err := createOwnedStagingUnit(dir, content, 0o644)
	if err != nil {
		return err
	}
	cleanupStaged := true
	defer func() {
		if !cleanupStaged {
			return
		}
		// Only dispose of this operation's own incoming staged inode.
		// If an administrator replaced the staging name, retain it.
		if current, err := os.Lstat(staged); err == nil && os.SameFile(current, incoming) {
			_ = os.Remove(staged)
		}
	}()
	if p.beforeUnitMutation != nil {
		p.beforeUnitMutation(phase)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, path, unix.RENAME_EXCHANGE); err != nil {
		// No fallback to ordinary rename: it could clobber an external file.
		return fmt.Errorf("atomic guarded unit exchange unavailable: %w", err)
	}
	// Verify both sides of the atomic exchange before retiring prior bytes.
	if !p.displacedUnitMatches(staged, before, expected) ||
		!p.incomingUnitMatches(path, incoming, content) {
		cleanupStaged = false
		return p.reconcileExchangeConflict(dir, path, staged, before, incoming, expected)
	}
	if p.afterUnitTransition != nil {
		p.afterUnitTransition("before-verified-staging-retirement")
	}
	// Recheck both path identities immediately before discarding staging.
	if !p.displacedUnitMatches(staged, before, expected) ||
		!p.incomingUnitMatches(path, incoming, content) {
		cleanupStaged = false
		if p.incomingUnitMatches(path, incoming, content) {
			// The just-published canonical inode is still provably ours:
			// return an explicit post-publication failure so EnsureRestore
			// can compensate it without touching the unrelated staging name.
			return &unitPublicationError{
				cause:        fmt.Errorf("%w: displaced staging changed before retirement", errUnitIdentityConflict),
				recoveryPath: staged,
			}
		}
		return p.reconcileExchangeConflict(dir, path, staged, before, incoming, expected)
	}
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

// Verify OLD by its original inode and bytes (the staged name is noncanonical).
func (p SystemdPersistence) displacedUnitMatches(path string, before os.FileInfo, expected []byte) bool {
	data, opened, err := readRegularUnit(path)
	if err != nil || !os.SameFile(before, opened) || !bytes.Equal(data, expected) {
		return false
	}
	return p.VerifyUnitPath != nil || protectedRootOwnership(opened) == nil
}

// Verify NEW by exact staging inode, bytes, and canonical path trust.
func (p SystemdPersistence) incomingUnitMatches(path string, incoming os.FileInfo, content []byte) bool {
	current, err := p.exactUnitIdentity(path, content)
	return err == nil && os.SameFile(current, incoming)
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
	data, moved, readErr := readRegularUnit(backup)
	matched := readErr == nil && os.SameFile(before, moved) && bytes.Equal(data, expected)
	if !matched {
		// Restore exclusively: a canonical unit installed in the meantime
		// must never be overwritten. Keep the private recovery name even
		// when link and directory sync succeed. It is the only independent
		// recovery material if the restored pathname later proves uncertain.
		if p.afterUnitTransition != nil {
			p.afterUnitTransition("before-retirement-conflict-restore")
		}
		if err := os.Link(backup, path); err != nil {
			// Even a failed canonical relink must not leave the newly moved
			// protected recovery filename without attempting directory sync.
			syncErr := p.syncRetirementDirectory(dir)
			return fmt.Errorf("%w: exclusive restoration unavailable; displaced identity retained at %q: %w", errUnitIdentityConflict, backup, errors.Join(err, syncErr))
		}
		if p.afterUnitTransition != nil {
			p.afterUnitTransition("after-retirement-conflict-link")
		}
		if err := p.syncRetirementDirectory(dir); err != nil {
			// Durability was not established. Do not discard the backup or
			// imply that the canonical hardlink will survive a crash.
			return fmt.Errorf("%w: restoration durability uncertain; displaced identity retained at %q: %w", errUnitIdentityConflict, backup, err)
		}
		return fmt.Errorf("%w: unexpected identity exclusively restored; protected recovery copy retained at %q", errUnitIdentityConflict, backup)
	}
	if err := p.syncRetirementDirectory(dir); err != nil {
		// Even for a verified owned inode, keep the backup if filesystem
		// durability cannot be proven. Exclusively re-link canonical when
		// possible and require the operator to reconcile the recovery name.
		restoreErr := os.Link(backup, path)
		// Do not unlink either name; if possible, sync the recovery links
		// with a second best-effort attempt and report the first failure.
		secondSyncErr := p.syncRetirementDirectory(dir)
		return fmt.Errorf("unit retirement directory sync failed; owned recovery copy retained at %q: %w", backup, errors.Join(err, restoreErr, secondSyncErr))
	}
	// Revalidate the moved inode immediately before deleting the private
	// recovery name. An unexpected replacement must be retained rather than
	// unlinked merely because an earlier check passed.
	if p.afterUnitTransition != nil {
		p.afterUnitTransition("before-verified-backup-retirement")
	}
	recheckData, recheckInfo, recheckErr := readRegularUnit(backup)
	if recheckErr != nil || !os.SameFile(before, recheckInfo) || !bytes.Equal(recheckData, expected) {
		return fmt.Errorf("%w: moved staging changed before final unlink; preserve %q: %v", errUnitIdentityConflict, backup, recheckErr)
	}
	if err := os.Remove(backup); err != nil {
		return fmt.Errorf("cannot release verified retired unit staging: %w", err)
	}
	return syncOwnedDir(dir)
}

func (p SystemdPersistence) syncRetirementDirectory(dir string) error {
	if p.syncUnitDirectory != nil {
		return p.syncUnitDirectory(dir)
	}
	return syncOwnedDir(dir)
}

func (p SystemdPersistence) exactUnitIdentity(path string, expected []byte) (os.FileInfo, error) {
	if err := p.guardExactPublishedUnit(path, expected); err != nil {
		return nil, err
	}
	current, info, err := readRegularUnit(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot safely inspect expected unit: %w", errUnitIdentityConflict, err)
	}
	if !bytes.Equal(current, expected) {
		return nil, fmt.Errorf("%w: expected unit contents changed during inspection", errUnitIdentityConflict)
	}
	return info, nil
}

func createOwnedStagingUnit(dir string, content []byte, mode os.FileMode) (string, os.FileInfo, error) {
	tmp, err := os.CreateTemp(dir, ".stl-unit-*.tmp")
	if err != nil {
		return "", nil, err
	}
	name := tmp.Name()
	// Capture the inode through our own descriptor, never a pathname that
	// may already point to a different privileged administrator's file.
	opened, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return "", nil, fmt.Errorf("cannot inspect created unit staging descriptor at %q: %w", name, err)
	}
	fail := func(cause error) (string, os.FileInfo, error) {
		_ = tmp.Close()
		// Cleanup only our original inode, never a substituted stage.
		if current, err := os.Lstat(name); err == nil && os.SameFile(current, opened) {
			_ = os.Remove(name)
		}
		return "", nil, cause
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
		return fail(err)
	}
	return name, opened, nil
}

func preserveUnitStaging(name string) (string, error) {
	// The reserved filename itself is intentionally returned to the operator.
	// Caller must not remove it when the outcome cannot be proven safe.
	if _, err := os.Lstat(name); err != nil {
		return "", err
	}
	return filepath.Clean(name), nil
}
