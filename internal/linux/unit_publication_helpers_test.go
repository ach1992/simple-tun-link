package linux

import (
	"os"
)

// The no-root-trust convenience wrappers exist ONLY in test source. Actual
// application publication must use SystemdPersistence.publishUnitIfAbsent,
// which checks trusted privileged paths and opened source ownership.
// writeOwnedUnitIfAbsent is retained only for isolated low-level tests.
// Production uses SystemdPersistence.publishUnitIfAbsent, which applies the
// strict canonical root-owned trust gate; test directories are unprivileged.
func writeOwnedUnitIfAbsent(dir, path string, contents []byte, mode os.FileMode) error {
	p := SystemdPersistence{VerifyUnitPath: func(string) error { return nil }}
	_, err := p.publishUnitIfAbsent(dir, path, contents, mode, "")
	return err
}

// The compatibility wrappers remain for isolated tests of publication
// failures. They only create *absent* units; production replacements and
// rollback use SystemdPersistence's guarded atomic transitions.
func writeAtomicFile(dir, path string, content []byte, mode os.FileMode) error {
	return writeAtomicFileWithHook(dir, path, content, mode, nil)
}

func writeAtomicFileWithHook(dir, path string, content []byte, mode os.FileMode, afterPublish func() error) error {
	if err := writeOwnedUnitIfAbsent(dir, path, content, mode); err != nil {
		return err
	}
	if afterPublish != nil {
		if err := afterPublish(); err != nil {
			return &unitPublicationError{cause: err}
		}
	}
	return nil
}
