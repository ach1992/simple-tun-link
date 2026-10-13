package ipsec

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// trustedNativeBootEnablementAt recognizes ONLY the canonical root-owned
// systemd wants edge for the otherwise static STL-native service. An
// administrator may deliberately schedule this already-published service at
// boot; this inspection never installs, starts, enables or adopts anything.
// It is not an operational permit on its own: Authorize also pins receipt,
// effective systemd settings, process, VICI, sockets and foreign inventory.
func trustedNativeBootEnablementAt(root string, owner uint32) bool {
	chain, err := openNativeUnitChain(root, owner)
	if err != nil {
		return false
	}
	defer chain.close()

	wants, err := unix.Openat(chain.parent(), "multi-user.target.wants",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(wants)
	if !trustedNativeDirectory(wants, owner, false) || !trustedNativeUnitChain(chain, owner) {
		return false
	}
	var before unix.Stat_t
	if unix.Fstatat(wants, nativeUnitName, &before, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		before.Mode&unix.S_IFMT != unix.S_IFLNK || before.Uid != owner || before.Nlink != 1 {
		return false
	}
	buf := make([]byte, len(NativeExclusiveServiceUnitPath)+1)
	n, err := unix.Readlinkat(wants, nativeUnitName, buf)
	if err != nil || n != len(NativeExclusiveServiceUnitPath) ||
		string(buf[:n]) != NativeExclusiveServiceUnitPath {
		return false
	}
	var after unix.Stat_t
	if unix.Fstatat(wants, nativeUnitName, &after, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!sameNativeIdentity(before, after) || !trustedNativeDirectory(wants, owner, false) ||
		!trustedNativeUnitChain(chain, owner) {
		return false
	}
	// The canonical target itself must remain a root-controlled exact file,
	// not a different symlink or a late substituted unit under the same name.
	target, err := os.Lstat(root + NativeExclusiveServiceUnitPath)
	return err == nil && rootControlledBootTarget(target, owner)
}

func rootControlledBootTarget(info os.FileInfo, owner uint32) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == owner
}
