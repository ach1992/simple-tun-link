package ipsec

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// NativeConfigAssessment is evidence about ONE file at inspection time, not
// proof of an STL-created inode, effective daemon settings or an activation
// permit. No caller may treat an Exact result as VICI/service ownership.
type NativeConfigAssessment string

const (
	NativeConfigExact      NativeConfigAssessment = "exact_bytes_only"
	NativeConfigMissing    NativeConfigAssessment = "not_provisioned"
	NativeConfigConflict   NativeConfigAssessment = "untrusted"
	NativeConfigUnverified NativeConfigAssessment = "unverified"
)

// InspectNativeExclusiveConfig reads only STL's proposed canonical config
// path. It follows no symlinks, trusts only root-owned protected directories,
// and returns no file bytes, raw errors or host paths to callers.
func InspectNativeExclusiveConfig() NativeConfigAssessment {
	return inspectNativeConfigAt("/", strings.TrimPrefix(NativeExclusiveConfigPath, "/"), 0, nil)
}

// inspectNativeConfigAt allows a private-root fixture in package tests; the
// production entry point is permanently bound to "/" and UID 0.
// This is a snapshot, not a reservation: other privileged writers may act
// after inspection. A future owner-only service admission must bind a durable
// publication receipt and independently attest package/service/process state.
func inspectNativeConfigAt(root, relative string, owner uint32, afterRead func()) NativeConfigAssessment {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return NativeConfigUnverified
	}
	parts := strings.Split(relative, "/")
	if len(parts) < 2 {
		return NativeConfigUnverified
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return NativeConfigUnverified
		}
	}

	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return NativeConfigUnverified
	}
	fds := []int{rootFD}
	defer func() {
		for i := len(fds) - 1; i >= 0; i-- {
			_ = unix.Close(fds[i])
		}
	}()
	if !trustedNativeDirectory(rootFD, owner, false) {
		return NativeConfigConflict
	}

	for i, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fds[len(fds)-1], part,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nativeOpenStatus(err)
		}
		fds = append(fds, next)
		// /var and /var/lib need trusted ancestry; the state root and
		// its IPsec child MUST be private to root.
		if !trustedNativeDirectory(next, owner, i >= 2) {
			return NativeConfigConflict
		}
	}

	parent := fds[len(fds)-1]
	fd, err := unix.Openat(parent, parts[len(parts)-1],
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nativeOpenStatus(err)
	}
	fds = append(fds, fd)
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return NativeConfigUnverified
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != owner || before.Mode&0o777 != 0o600 ||
		before.Nlink != 1 || before.Size != int64(len(nativeExclusiveConfigV1)) {
		return NativeConfigConflict
	}

	// The descriptor is nonblocking and must be a regular, singly-linked
	// private inode before bytes are read. Bounded reads cannot hang on
	// FIFOs or emit untrusted daemon configuration in an error/log.
	data := make([]byte, len(nativeExclusiveConfigV1)+1)
	nread := 0
	for nread < len(data) {
		n, readErr := unix.Read(fd, data[nread:])
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			clear(data)
			return NativeConfigUnverified
		}
		if n == 0 {
			break
		}
		nread += n
	}
	equal := bytes.Equal(data[:nread], []byte(nativeExclusiveConfigV1))
	clear(data)
	if !equal {
		return NativeConfigConflict
	}
	if afterRead != nil {
		afterRead() // private test seam for post-read inode/path races
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return NativeConfigUnverified
	}
	if !sameNativeIdentity(before, after) {
		return NativeConfigConflict
	}

	// Verify the opened file and EVERY pinned ancestor still have the same
	// canonical directory-entry identities. Pathname lookup alone cannot
	// prove this; the entry may have been exchanged during the read.
	for i := len(fds) - 1; i > 0; i-- {
		var entry, opened unix.Stat_t
		name := parts[i-1]
		if err := unix.Fstatat(fds[i-1], name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return NativeConfigConflict
		}
		if err := unix.Fstat(fds[i], &opened); err != nil {
			return NativeConfigUnverified
		}
		if !sameNativeIdentity(entry, opened) {
			return NativeConfigConflict
		}
		if i < len(fds)-1 && !trustedNativeDirectory(fds[i], owner, i-1 >= 2) {
			// Directory mode/ownership may have changed since its
			// initial trusted traversal even if its inode is unchanged.
			return NativeConfigConflict
		}
	}
	if !trustedNativeDirectory(rootFD, owner, false) {
		return NativeConfigConflict
	}
	return NativeConfigExact
}

func trustedNativeDirectory(fd int, owner uint32, private bool) bool {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Uid != owner || st.Mode&0o022 != 0 || st.Mode&0o100 == 0 {
		return false
	}
	return !private || st.Mode&0o077 == 0
}

func nativeOpenStatus(err error) NativeConfigAssessment {
	switch {
	case errors.Is(err, unix.ENOENT):
		return NativeConfigMissing
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return NativeConfigConflict
	default:
		return NativeConfigUnverified
	}
}

func sameNativeIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino &&
		a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Nlink == b.Nlink && a.Size == b.Size &&
		a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
