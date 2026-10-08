package linux

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// VerifyTrustedSTLExecutable establishes the identity of a root-operated boot
// program before STL installs its persistent system service. No part of the
// executable's path may be writable by a less-privileged user or a symlink.
// Symlinked stlink aliases are resolved to the canonical stl path by the CLI.
func VerifyTrustedSTLExecutable(path string) error {
	return verifyTrustedSTLExecutable(path, os.Lstat)
}

func verifyTrustedSTLExecutable(path string, lstat func(string) (fs.FileInfo, error)) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "stl" {
		return fmt.Errorf("restore requires an absolute canonical stl installation path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := lstat(current)
		if err != nil {
			return fmt.Errorf("inspect installed STL executable identity: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("installed STL executable identity contains a symlink")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("installed STL executable path is not root-owned and protected from non-root writes")
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				return fmt.Errorf("installed STL executable must be a regular executable file")
			}
		} else if !info.IsDir() || info.Mode().Perm()&0o100 == 0 {
			// The root-operated service must be able to traverse the path;
			// root-only directories remain valid if they are not writable by
			// less privileged users.
			return fmt.Errorf("installed STL executable has an inaccessible parent directory")
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	return nil
}
