// Package credentials owns the shared, descriptor-verified private directory
// for backend secrets. A Go caller must close the returned Unix FD.
package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenProtected uses descriptor-relative, no-symlink traversal.
// The state root and credentials directory must be owned by the effective
// user and inaccessible to group/other users. Existing unsafe paths fail
// closed; they are not silently chmodded or replaced.
func OpenProtected(root string, create bool) (int, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return -1, fmt.Errorf("private credential state root must be absolute and clean")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(root, "/"), "/")
	for i, component := range append(components, "credentials") {
		last := i == len(components)
		isRoot := i == len(components)-1
		next, openErr := unix.Openat(fd, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create && (isRoot || last) {
			if mkErr := unix.Mkdirat(fd, component, 0o700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				unix.Close(fd)
				return -1, fmt.Errorf("create private credential directory: %w", mkErr)
			}
			if syncErr := unix.Fsync(fd); syncErr != nil {
				unix.Close(fd)
				return -1, fmt.Errorf("sync private credential directory parent: %w", syncErr)
			}
			next, openErr = unix.Openat(fd, component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("open protected credential directory component: %w", openErr)
		}
		var info unix.Stat_t
		if err := unix.Fstat(next, &info); err != nil {
			unix.Close(next)
			unix.Close(fd)
			return -1, fmt.Errorf("inspect protected credential directory: %w", err)
		}
		if isRoot || last {
			if info.Uid != uint32(os.Geteuid()) || info.Mode&0o077 != 0 {
				unix.Close(next)
				unix.Close(fd)
				return -1, fmt.Errorf("credential directory is not private and owner-controlled")
			}
		} else if info.Mode&0o022 != 0 && info.Mode&unix.S_ISVTX == 0 {
			// A non-sticky writable ancestor would allow a different user
			// to swap the protected state directory between invocations.
			unix.Close(next)
			unix.Close(fd)
			return -1, fmt.Errorf("credential path has untrusted writable ancestor")
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}
