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
	incoming, err := os.Lstat(staged)
	if err != nil {
		// The freshly staged path already changed; never blindly unlink it.
		return fmt.Errorf("%w: cannot inspect incoming staging identity at %q: %v", errUnitIdentityConflict, staged, err)
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
	// The displaced unit is now at the private staging name. Check both the
	// original inode and bytes, not only the marker or expected text.
	data, displaced, readErr := readRegularUnit(staged)
	matched := readErr == nil && os.SameFile(before, displaced) && bytes.Equal(data, expected)
	if !matched {
		// From this point the staging path contains an unverified identity.
		// Never invoke the ordinary deferred unlink after a conflict, even
		// following successful reversal. Another root administrator could
		// change the canonical inode between the check and reverse exchange,
		// causing a second foreign identity to land at this staging path.
		// Retaining a recoverable staging file is better than destroying an
		// independent unit; operators can remove it after reconciliation.
		cleanupStaged = false
		reversed := false
		if current, err := os.Lstat(path); err == nil && os.SameFile(current, incoming) {
			if p.afterUnitTransition != nil {
				p.afterUnitTransition("before-conflict-reverse")
			}
			if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, path, unix.RENAME_EXCHANGE); err == nil {
				reversed = true
				if p.afterUnitTransition != nil {
					p.afterUnitTransition("after-conflict-reverse")
				}
			}
		}
		preserved, preserveErr := preserveUnitStaging(staged)
		if preserveErr != nil {
			return fmt.Errorf("%w: reversal=%t; cannot verify recovery staging %q: %w", errUnitIdentityConflict, reversed, staged, preserveErr)
		}
		// Attempt to make the recovery pathname durable; preserve it even
		// when fsync fails and explicitly report that uncertain durability.
		if err := p.syncRetirementDirectory(dir); err != nil {
			return fmt.Errorf("%w: reversal=%t; recovery staging retained at %q but durability is uncertain: %w", errUnitIdentityConflict, reversed, preserved, err)
		}
		return fmt.Errorf("%w: reversal=%t; displaced recovery identity retained at %q", errUnitIdentityConflict, reversed, preserved)
	}
	// The displaced inode was exactly STL's expected prior unit. Recheck
	// the private staging name immediately before retiring it: a different
	// root-operated manager may have moved another object there since the
	// first snapshot. A changed name is recovery evidence, not garbage.
	if p.afterUnitTransition != nil {
		p.afterUnitTransition("before-verified-staging-retirement")
	}
	recheckData, recheckInfo, recheckErr := readRegularUnit(staged)
	if recheckErr != nil || !os.SameFile(before, recheckInfo) || !bytes.Equal(recheckData, expected) {
		cleanupStaged = false
		return &unitPublicationError{
			cause:        fmt.Errorf("%w: prior staging changed before retirement: %v", errUnitIdentityConflict, recheckErr),
			recoveryPath: staged,
		}
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
