package linux

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Restore unit content is a small, generated systemd service. Fail closed on
// oversized files rather than allocating unbounded memory from a replaced
// unit identity or a device stream.
const maxRestoreUnitBytes = 64 * 1024

// readRegularUnit returns content and the identity of the *opened inode*.
// Reject a symlink, FIFO, device, socket or directory before any read. O_NONBLOCK
// prevents a last-instant swap to a FIFO from blocking inside open(2).
// O_NOFOLLOW keeps a last-instant symlink swap from following its target.
// f.Stat and os.SameFile tie the bytes to the object opened, not to a
// previously inspected path that could have changed in the meantime.
func readRegularUnit(path string) ([]byte, os.FileInfo, error) {
	return readUnitContents(path, false)
}

// readPinnedRegularUnit retains the descriptor for a long-lived inode identity.
// A metadata-only FileInfo becomes unsafe once the final link is removed:
// Linux may reuse that inode number before the caller finishes its operation.
func readPinnedRegularUnit(path string) ([]byte, os.FileInfo, error) {
	return readUnitContents(path, true)
}

func readUnitContents(path string, retainOrigin bool) ([]byte, os.FileInfo, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !entry.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("systemd unit identity is not a regular file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open systemd unit without following links: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	transferred := false
	defer func() {
		if !transferred {
			_ = f.Close()
		}
	}()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("inspect opened systemd unit: %w", err)
	}
	if !opened.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("opened systemd unit identity is not a regular file")
	}
	if !os.SameFile(entry, opened) {
		return nil, nil, fmt.Errorf("%w: unit identity changed before content read", errUnitIdentityConflict)
	}
	if opened.Size() < 0 || opened.Size() > maxRestoreUnitBytes {
		return nil, nil, fmt.Errorf("systemd unit exceeds bounded %d-byte size", maxRestoreUnitBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRestoreUnitBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read bounded systemd unit: %w", err)
	}
	if len(data) > maxRestoreUnitBytes {
		return nil, nil, fmt.Errorf("systemd unit changed to exceed bounded %d-byte size", maxRestoreUnitBytes)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cannot verify opened unit after read: %w", errUnitIdentityConflict, err)
	}
	if !os.SameFile(opened, after) || after.Size() != int64(len(data)) ||
		!after.ModTime().Equal(opened.ModTime()) {
		return nil, nil, fmt.Errorf("%w: unit inode contents changed during bounded read", errUnitIdentityConflict)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cannot verify unit pathname after read: %w", errUnitIdentityConflict, err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return nil, nil, fmt.Errorf("%w: unit pathname changed during bounded read", errUnitIdentityConflict)
	}
	if retainOrigin {
		transferred = true
		return data, &pinnedUnitIdentity{FileInfo: opened, origin: f}, nil
	}
	return data, opened, nil
}
