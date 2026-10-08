package linux

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// A failed exchange must keep its private displaced file until reconciliation.
func (p SystemdPersistence) reconcileExchangeConflict(dir, path, staged string, before, incoming os.FileInfo, expected []byte) error {
	oldSafe := p.displacedUnitMatches(staged, before, expected)
	reversed, restoredPrior := false, false
	current, err := os.Lstat(path)
	if err == nil && (oldSafe || os.SameFile(current, incoming)) {
		if p.afterUnitTransition != nil {
			p.afterUnitTransition("before-conflict-reverse")
		}
		if !oldSafe || p.displacedUnitMatches(staged, before, expected) {
			if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, path, unix.RENAME_EXCHANGE); err == nil {
				reversed = true
				if p.afterUnitTransition != nil {
					p.afterUnitTransition("after-conflict-reverse")
				}
				if oldSafe {
					restoredPrior = p.displacedUnitMatches(path, before, expected) && p.verifyUnitPath(path) == nil
				}
			}
		}
	}
	preserved, err := preserveUnitStaging(staged)
	if err != nil {
		return fmt.Errorf("%w: reversal=%t restored-prior=%t; recovery staging uncertain at %q: %w",
			errUnitIdentityConflict, reversed, restoredPrior, staged, err)
	}
	if err := p.syncRetirementDirectory(dir); err != nil {
		return fmt.Errorf("%w: reversal=%t restored-prior=%t; recovery staging retained at %q but durability uncertain: %w",
			errUnitIdentityConflict, reversed, restoredPrior, preserved, err)
	}
	return fmt.Errorf("%w: reversal=%t restored-prior=%t; protected recovery identity retained at %q",
		errUnitIdentityConflict, reversed, restoredPrior, preserved)
}
