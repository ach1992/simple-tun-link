package wss

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// RetireOwnedTLS removes only the selected Link's exact protected mTLS/auth
// files, after caller proves durable canonical Remove + absent live kernel,
// nft and service resources under the SAME Link lock. It is idempotent on
// missing files, never adopts different names, ownership, modes or symlinks.
func RetireOwnedTLS(root string, link domain.Link) error {
	if link.ID.Validate() != nil || link.Backend != domain.BackendWireGuardWSS {
		return fmt.Errorf("invalid retired WSS identity")
	}
	parent, err := credentials.OpenProtected(root, false)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	wssfd, err := openOwnedPrivateDir(parent, "wss")
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(wssfd)
	linkfd, err := openOwnedPrivateDir(wssfd, string(link.ID))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(linkfd)
	names := []string{"client-cert.pem", "client-key.pem", "server-ca.pem", "authorization-headers"}
	if link.WSS.Role == "listen" {
		names = []string{"server-cert.pem", "server-key.pem", "client-ca.pem", "authorization-token", "restrictions.yaml"}
	} else if link.WSS.Role != "dial" {
		return fmt.Errorf("invalid WSS retirement role")
	}
	// A surprise file in the protected directory could represent an
	// unrelated owner; do not recursively delete an uncontrolled directory.
	entries, err := os.ReadDir(filepath.Join(root, "credentials", "wss", string(link.ID)))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !slices.Contains(names, entry.Name()) {
			return fmt.Errorf("WSS credential directory contains unknown material")
		}
	}
	for _, name := range names {
		fd, err := unix.Openat(linkfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return fmt.Errorf("WSS private credential cannot be verified for retirement: %w", err)
		}
		var fromFD, fromName unix.Stat_t
		fdErr := unix.Fstat(fd, &fromFD)
		nameErr := unix.Fstatat(linkfd, name, &fromName, unix.AT_SYMLINK_NOFOLLOW)
		_ = unix.Close(fd)
		if fdErr != nil || nameErr != nil || fromFD.Mode&unix.S_IFMT != unix.S_IFREG ||
			fromFD.Uid != uint32(os.Geteuid()) || fromFD.Mode&0o777 != 0o600 ||
			fromFD.Nlink != 1 || fromFD.Dev != fromName.Dev || fromFD.Ino != fromName.Ino {
			return fmt.Errorf("WSS credential inode, permissions or identity changed")
		}
		if err := unix.Unlinkat(linkfd, name, 0); err != nil {
			return fmt.Errorf("cannot unlink verified WSS credential: %w", err)
		}
		if err := unix.Fsync(linkfd); err != nil {
			return fmt.Errorf("WSS private material deletion durability uncertain: %w", err)
		}
	}
	var before, fromName unix.Stat_t
	if err := unix.Fstat(linkfd, &before); err != nil {
		return err
	}
	if err := unix.Fstatat(wssfd, string(link.ID), &fromName, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if before.Ino != fromName.Ino || before.Dev != fromName.Dev || fromName.Mode&unix.S_IFMT != unix.S_IFDIR ||
		fromName.Uid != uint32(os.Geteuid()) || fromName.Mode&0o777 != 0o700 {
		return fmt.Errorf("WSS credential directory replaced during retirement")
	}
	if err := unix.Unlinkat(wssfd, string(link.ID), unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("WSS credential directory still contains unowned material: %w", err)
	}
	if err := unix.Fsync(wssfd); err != nil {
		return fmt.Errorf("WSS private directory deletion durability uncertain: %w", err)
	}
	return nil
}

// TLSAbsent provides a strictly read-only proof: a previously retired
// WSS Link cannot use its consumed receipt to delete reappearing material.
func TLSAbsent(root string, link domain.Link) (bool, error) {
	if link.ID.Validate() != nil || link.Backend != domain.BackendWireGuardWSS {
		return false, fmt.Errorf("invalid WSS identity")
	}
	rootFD, err := credentials.OpenProtected(root, false)
	if err != nil {
		return false, err
	}
	defer unix.Close(rootFD)
	wssFD, err := openOwnedPrivateDir(rootFD, "wss")
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(wssFD)
	linkFD, err := openOwnedPrivateDir(wssFD, string(link.ID))
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	unix.Close(linkFD)
	return false, nil
}
