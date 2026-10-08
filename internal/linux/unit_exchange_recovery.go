package linux

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// A failed exchange must keep its private displaced file until reconciliation.
// preserveUnverifiedStaging retains a potentially independent staging file
// rather than deleting or installing it; fsync makes the recovery pathname
// durable where the filesystem supports it.
func (p SystemdPersistence) preserveUnverifiedStaging(dir, staged, description string) error {
	path, err := preserveUnitStaging(staged)
	if err != nil {
		return fmt.Errorf("%w: %s; recovery identity uncertain at %q: %w", errUnitIdentityConflict, description, staged, err)
	}
	if err := p.syncRetirementDirectory(dir); err != nil {
		return fmt.Errorf("%w: %s; recovery retained at %q but directory durability uncertain: %w", errUnitIdentityConflict, description, path, err)
	}
	return fmt.Errorf("%w: %s; protected recovery identity retained at %q", errUnitIdentityConflict, description, path)
}

func (p SystemdPersistence) reconcileExchangeConflict(dir, path, staged string, before, incoming, priorAtExchange os.FileInfo, expected, installed, priorAtExchangeBytes []byte) error {
	// Ownership of the OLD staging identity alone never authorizes
	// displacement of an independently installed canonical systemd unit.
	// Only our original published incoming inode AND bytes may be displaced,
	// and only the actual canonical inode/content captured immediately before
	// the exchange may be restored to that pathname. This excludes late
	// independent mutations to the private staging identity.
	reversed, restoredPrior := false, false
	if p.incomingUnitMatches(path, incoming, installed) &&
		p.displacedUnitMatches(staged, priorAtExchange, priorAtExchangeBytes) {
		if p.afterUnitTransition != nil {
			p.afterUnitTransition("before-conflict-reverse")
		}
		// Recheck after the failure-injection boundary. A concurrent operator
		// may have installed another canonical unit in the meantime.
		if p.incomingUnitMatches(path, incoming, installed) &&
			p.displacedUnitMatches(staged, priorAtExchange, priorAtExchangeBytes) {
			if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, path, unix.RENAME_EXCHANGE); err == nil {
				reversed = true
				if p.afterUnitTransition != nil {
					p.afterUnitTransition("after-conflict-reverse")
				}
				restoredPrior = p.displacedUnitMatches(path, before, expected) && p.verifyUnitPath(path) == nil
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
