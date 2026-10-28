// Package pinnedexec provides a single low-level, descriptor-pinned
// read-only executable identity check without depending on Engine or Linux
// service adapters.
package pinnedexec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Identity is local read-only inode/hash evidence, not authority to launch a process after the inspected descriptor is closed.
type Identity struct {
	SHA256 string
	Device uint64
	Inode  uint64
}

// Inspect rejects substituted paths and all executable bytes except the exact caller-approved SHA-256. The caller must use a separately
// reviewed upstream digest and recheck the object at the actual spawn boundary.
func Inspect(binary, expectedSHA256 string) (Identity, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || binary == "/" ||
		len(expectedSHA256) != 64 || strings.Trim(expectedSHA256, "0123456789abcdef") != "" {
		return Identity{}, fmt.Errorf("pinned helper requires clean absolute path and lowercase SHA-256")
	}
	parts := strings.Split(strings.TrimPrefix(binary, "/"), "/")
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = unix.Close(parent) }()
	for _, component := range parts[:len(parts)-1] {
		fd, err := unix.Openat(parent, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return Identity{}, fmt.Errorf("helper path directory cannot be trusted")
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil ||
			st.Mode&unix.S_IFMT != unix.S_IFDIR ||
			(st.Uid != 0 && st.Uid != uint32(os.Geteuid())) ||
			(st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			unix.Close(fd)
			return Identity{}, fmt.Errorf("helper path directory is not owner-controlled")
		}
		unix.Close(parent)
		parent = fd
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1],
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return Identity{}, fmt.Errorf("trusted helper executable cannot be opened")
	}
	f := os.NewFile(uintptr(fd), "pinned-helper")
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != uint32(os.Geteuid()) ||
		st.Mode&0o022 != 0 || st.Mode&0o111 == 0 || st.Mode&0o6000 != 0 ||
		st.Nlink != 1 || st.Size <= 0 || st.Size > 100<<20 {
		return Identity{}, fmt.Errorf("helper executable owner/mode/inode invalid")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, 100<<20+1)); err != nil {
		return Identity{}, fmt.Errorf("helper executable fingerprint unavailable")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expectedSHA256 {
		return Identity{}, fmt.Errorf("pinned helper executable SHA-256 mismatch")
	}
	return Identity{SHA256: actual, Device: uint64(st.Dev), Inode: st.Ino}, nil
}
