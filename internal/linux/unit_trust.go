package linux

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// VerifyTrustedSystemdUnitPath is the production trust gate for the privileged
// STL restore unit. A text marker is not authority to run a root service:
// the file and every existing parent must be root-owned, non-symlinked, and
// inaccessible for modification by less-privileged users.
func VerifyTrustedSystemdUnitPath(path string) error {
	return verifyTrustedSystemdUnitPath(path, os.Lstat)
}

func verifyTrustedSystemdUnitPath(path string, lstat func(string) (fs.FileInfo, error)) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != restoreSystemdUnitName {
		return fmt.Errorf("restore unit must have a canonical absolute path and its exact STL-owned basename")
	}
	if err := verifyTrustedUnitDirectory(filepath.Dir(path), lstat, false); err != nil {
		return err
	}
	info, err := lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // Legitimate new installation; parent chain is already trusted.
	}
	if err != nil {
		return fmt.Errorf("inspect restore unit identity: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("restore unit must be a regular, non-symlinked file")
	}
	if err := protectedRootOwnership(info); err != nil {
		return fmt.Errorf("restore unit file identity is untrusted: %w", err)
	}
	return nil
}

func verifyTrustedUnitDirectory(dir string, lstat func(string) (fs.FileInfo, error), allowMissing bool) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("restore unit directory must be canonical and absolute")
	}
	for path := dir; ; path = filepath.Dir(path) {
		info, err := lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist) && allowMissing && path != string(filepath.Separator):
			// A new unit directory can be created only beneath an existing,
			// checked root-owned ancestor. The filesystem root must exist.
		case err != nil:
			return fmt.Errorf("inspect restore unit directory chain: %w", err)
		default:
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("restore unit directory chain contains a non-directory or symlink")
			}
			if err := protectedRootOwnership(info); err != nil {
				return fmt.Errorf("restore unit directory chain is untrusted: %w", err)
			}
			if info.Mode().Perm()&0o100 == 0 {
				return fmt.Errorf("restore unit directory chain cannot be traversed")
			}
		}
		if path == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func protectedRootOwnership(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("path is not proven root-owned")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("path is writable by a non-root account")
	}
	return nil
}

func (p SystemdPersistence) verifyUnitPath(path string) error {
	if p.VerifyUnitPath != nil {
		return p.VerifyUnitPath(path)
	}
	return VerifyTrustedSystemdUnitPath(path)
}

func (p SystemdPersistence) verifyUnitDirectoryForCreate(dir string) error {
	if p.VerifyUnitPath != nil {
		// Only unit tests opt out of privileged filesystem ownership while
		// running against isolated non-root-owned temporary directories.
		return nil
	}
	return verifyTrustedUnitDirectory(dir, os.Lstat, true)
}
