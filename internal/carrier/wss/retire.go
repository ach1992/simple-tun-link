package wss

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

// RetireOwnedTLS removes only the selected Link's exact protected mTLS/auth
// files, after caller proves durable canonical Remove + absent live kernel,
// nft and service resources under the SAME Link lock. It is idempotent on
// missing files, never adopts different names, ownership, modes or symlinks.
func RetireOwnedTLS(root string, link domain.Link, expected state.WSSFileIdentity) error {
	if err := expected.VerifyLink(link); err != nil {
		return fmt.Errorf("WSS original retirement identity absent: %w", err)
	}
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
	roleNames, err := WSSRoleFiles(link)
	if err != nil {
		return err
	}
	names := make([]string, 0, 5)
	for _, name := range roleNames {
		if name != "" {
			names = append(names, name)
		}
	}
	fingerprints := []string{
		expected.Certificate, expected.TLSKey, expected.TrustCA,
		expected.Authorization, expected.Restrictions,
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
	// First check ALL existing authorized files before modifying any. This
	// also protects partial previous deletions: replaced content must be
	// preserved, even if other files are still the original issuance.
	for idx, name := range roleNames {
		if name == "" {
			continue
		}
		// readPrivateFile intentionally hides syscall details. Establish
		// missingness with an independent descriptor-relative stat; errors
		// other than ENOENT never authorize skipping an existing credential.
		var current unix.Stat_t
		if statErr := unix.Fstatat(linkfd, name, &current, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
			if errors.Is(statErr, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("cannot verify WSS original credential pathname")
		}
		raw, err := readPrivateFile(linkfd, name)
		if err != nil {
			return fmt.Errorf("cannot attest original WSS retirement material: %w", err)
		}
		digest := sha256.Sum256(raw)
		clear(raw)
		if hex.EncodeToString(digest[:]) != fingerprints[idx] {
			return fmt.Errorf("WSS original credential fingerprint differs; no material removed")
		}
	}
	for idx, name := range roleNames {
		if name == "" {
			continue
		}
		fd, err := unix.Openat(linkfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return fmt.Errorf("WSS private credential cannot be verified for retirement: %w", err)
		}
		// Verify the content, mode, original inode and current name all
		// against the SAME opened descriptor. Hashing by separately opening
		// the name after Fstat could race with a same-name replacement.
		file := os.NewFile(uintptr(fd), "WSS-retire-candidate")
		var fromFD, fromName unix.Stat_t
		fdErr := unix.Fstat(fd, &fromFD)
		nameErr := unix.Fstatat(linkfd, name, &fromName, unix.AT_SYMLINK_NOFOLLOW)
		if fdErr != nil || nameErr != nil || fromFD.Mode&unix.S_IFMT != unix.S_IFREG ||
			fromFD.Uid != uint32(os.Geteuid()) || fromFD.Mode&0o777 != 0o600 ||
			fromFD.Nlink != 1 || fromFD.Dev != fromName.Dev || fromFD.Ino != fromName.Ino ||
			fromFD.Size < 1 || fromFD.Size > maxPEMBytes {
			file.Close()
			return fmt.Errorf("WSS original credential inode, permissions or identity changed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, maxPEMBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(raw) != int(fromFD.Size) {
			clear(raw)
			return fmt.Errorf("WSS original credential content not fully readable")
		}
		digest := sha256.Sum256(raw)
		clear(raw)
		if hex.EncodeToString(digest[:]) != fingerprints[idx] {
			return fmt.Errorf("WSS original credential changed before unlink; preserve replacement")
		}
		var final unix.Stat_t
		if err := unix.Fstatat(linkfd, name, &final, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			final.Dev != fromFD.Dev || final.Ino != fromFD.Ino ||
			final.Mode != fromFD.Mode || final.Size != fromFD.Size {
			return fmt.Errorf("WSS original credential replaced during retirement")
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
