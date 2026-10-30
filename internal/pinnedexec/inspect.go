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

// Inspect returns a point-in-time identity and closes its descriptor. A later
// process launch must independently verify the executable actually used.
func Inspect(binary, expectedSHA256 string) (Identity, error) {
	file, identity, err := Open(binary, expectedSHA256)
	if err != nil {
		return Identity{}, err
	}
	if err := file.Close(); err != nil {
		return Identity{}, fmt.Errorf("pinned helper descriptor close failed")
	}
	return identity, nil
}

// Open verifies the exact approved bytes and returns the original open file,
// rewound for its single owning caller. The caller MUST close it. Retaining
// this descriptor prevents the original inode from being recycled during a
// launch/readback transaction; it does not freeze file contents, force a
// pathname-based executor to use this file, or authorize service recovery.
// Callers still verify canonical-path and actual process identity at effect
// boundaries. A privileged in-place writer remains outside this read-only
// pin's integrity guarantee.
func Open(binary, expectedSHA256 string) (*os.File, Identity, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || binary == "/" ||
		len(expectedSHA256) != 64 || strings.Trim(expectedSHA256, "0123456789abcdef") != "" {
		return nil, Identity{}, fmt.Errorf("pinned helper requires clean absolute path and lowercase SHA-256")
	}
	parts := strings.Split(strings.TrimPrefix(binary, "/"), "/")
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, Identity{}, err
	}
	defer func() { _ = unix.Close(parent) }()
	for _, component := range parts[:len(parts)-1] {
		fd, err := unix.Openat(parent, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, Identity{}, fmt.Errorf("helper path directory cannot be trusted")
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil ||
			st.Mode&unix.S_IFMT != unix.S_IFDIR ||
			(st.Uid != 0 && st.Uid != uint32(os.Geteuid())) ||
			(st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			unix.Close(fd)
			return nil, Identity{}, fmt.Errorf("helper path directory is not owner-controlled")
		}
		unix.Close(parent)
		parent = fd
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1],
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, Identity{}, fmt.Errorf("trusted helper executable cannot be opened")
	}
	f := os.NewFile(uintptr(fd), "pinned-helper")
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != uint32(os.Geteuid()) ||
		st.Mode&0o022 != 0 || st.Mode&0o111 == 0 || st.Mode&0o6000 != 0 ||
		st.Nlink != 1 || st.Size <= 0 || st.Size > 100<<20 {
		return nil, Identity{}, fmt.Errorf("helper executable owner/mode/inode invalid")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, 100<<20+1))
	if err != nil || n != st.Size {
		return nil, Identity{}, fmt.Errorf("helper executable fingerprint unavailable")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expectedSHA256 {
		return nil, Identity{}, fmt.Errorf("pinned helper executable SHA-256 mismatch")
	}
	// Hashing can be a long observation window. Recheck the opened object
	// and its original parent entry before exporting a retained pin.
	var now, entry unix.Stat_t
	if unix.Fstat(fd, &now) != nil ||
		unix.Fstatat(parent, parts[len(parts)-1], &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!sameExecutableMetadata(st, now) || !sameExecutableMetadata(now, entry) {
		return nil, Identity{}, fmt.Errorf("helper executable changed during inspection")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, Identity{}, fmt.Errorf("pinned helper descriptor rewind failed")
	}
	keep = true
	return f, Identity{SHA256: actual, Device: uint64(st.Dev), Inode: st.Ino}, nil
}

func sameExecutableMetadata(a, b unix.Stat_t) bool {
	// Access time may legitimately change while reading the executable.
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink &&
		a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
