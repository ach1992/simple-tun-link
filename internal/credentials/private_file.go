package credentials

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const MaxPrivateFileBytes = 1 << 20

func safeChild(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\x00\r\n")
}

// OpenOwnedPrivateDir uses a held parent FD, never a path re-resolution, to
// open or create an exact owner-private directory. The parent is expected to
// come from OpenProtected (or an earlier OpenOwnedPrivateDir).
func OpenOwnedPrivateDir(parent int, name string, create bool) (int, error) {
	if !safeChild(name) {
		return -1, fmt.Errorf("invalid private directory component")
	}
	if create {
		if err := unix.Mkdirat(parent, name, 0o700); err != nil && err != unix.EEXIST {
			return -1, fmt.Errorf("cannot create private credential directory")
		}
		if err := unix.Fsync(parent); err != nil {
			return -1, fmt.Errorf("cannot sync private credential parent")
		}
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("private credential directory unavailable")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700 {
		unix.Close(fd)
		return -1, fmt.Errorf("private credential directory identity or permissions invalid")
	}
	return fd, nil
}

func requirePrivateFD(dirfd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(dirfd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700 {
		return fmt.Errorf("credential destination directory is not owner-private")
	}
	return nil
}

// ReadPrivateFile requires a singly linked, regular, bounded 0600 inode.
// Data belongs to the caller and must be cleared after use.
func ReadPrivateFile(dirfd int, name string) ([]byte, error) {
	f, raw, err := openCheckedPrivateFile(dirfd, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return raw, nil
}

// openCheckedPrivateFile keeps the validated file descriptor open with its
// read bytes. On an idempotent retry, synchronizing this very descriptor
// avoids looking up a possibly substituted pathname after comparison.
// The caller must close f and erase the returned bytes.
func openCheckedPrivateFile(dirfd int, name string) (*os.File, []byte, error) {
	if !safeChild(name) || requirePrivateFD(dirfd) != nil {
		return nil, nil, fmt.Errorf("invalid private credential reader")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("protected credential is not readable")
	}
	f := os.NewFile(uintptr(fd), "protected-credential")
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o600 ||
		st.Nlink != 1 || st.Size < 1 || st.Size > MaxPrivateFileBytes {
		f.Close()
		return nil, nil, fmt.Errorf("credential inode/mode/size invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxPrivateFileBytes+1))
	if err != nil || len(raw) < 1 || len(raw) > MaxPrivateFileBytes {
		clear(raw)
		f.Close()
		return nil, nil, fmt.Errorf("cannot read bounded private credential")
	}
	return f, raw, nil
}

// CreatedPrivateIdentity is the inode actually opened with O_EXCL, not a
// later path readback. A caller may use it to prove that one generation
// exclusively created each of its private files.
type CreatedPrivateIdentity struct {
	Device uint64
	Inode  uint64
}

// WritePrivateCreateOnly is intentionally stricter than WritePrivateNoReplace:
// EEXIST always fails, including for byte-identical contents. The original
// created descriptor stays pinned through write, fsync and pathname identity
// checks. An uncertain result leaves the file in place for owner reconciliation.
func WritePrivateCreateOnly(dirfd int, name string, raw []byte) (CreatedPrivateIdentity, error) {
	if !safeChild(name) || len(raw) == 0 || len(raw) > MaxPrivateFileBytes ||
		requirePrivateFD(dirfd) != nil {
		return CreatedPrivateIdentity{}, fmt.Errorf("invalid create-only private publication")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return CreatedPrivateIdentity{}, fmt.Errorf("private create-only file already exists or cannot be opened")
	}
	f := os.NewFile(uintptr(fd), "created-private-file")
	defer f.Close()
	var created, current, child unix.Stat_t
	if err := unix.Fstat(fd, &created); err != nil ||
		created.Mode&unix.S_IFMT != unix.S_IFREG || created.Mode&0o777 != 0o600 ||
		created.Uid != uint32(os.Geteuid()) || created.Nlink != 1 {
		return CreatedPrivateIdentity{}, fmt.Errorf("new private file has untrusted creation identity")
	}
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		return CreatedPrivateIdentity{}, fmt.Errorf("new private file write incomplete")
	}
	if err := f.Sync(); err != nil {
		return CreatedPrivateIdentity{}, fmt.Errorf("new private file durability uncertain")
	}
	if err := unix.Fstat(fd, &current); err != nil ||
		current.Dev != created.Dev || current.Ino != created.Ino ||
		current.Mode != created.Mode || current.Nlink != 1 ||
		current.Size != int64(len(raw)) {
		return CreatedPrivateIdentity{}, fmt.Errorf("new private inode changed after write")
	}
	if err := unix.Fsync(dirfd); err != nil {
		return CreatedPrivateIdentity{}, fmt.Errorf("new private file directory durability uncertain")
	}
	if err := unix.Fstatat(dirfd, name, &child, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		child.Dev != created.Dev || child.Ino != created.Ino ||
		child.Mode != current.Mode || child.Nlink != 1 || child.Size != current.Size {
		return CreatedPrivateIdentity{}, fmt.Errorf("new private file path changed after creation")
	}
	return CreatedPrivateIdentity{Device: uint64(created.Dev), Inode: created.Ino}, nil
}

// WritePrivateNoReplace publishes only to an already verified private
// directory using O_EXCL; an existing file is accepted only when its exact
// content and inode are trustworthy AND the same inode has been synced.
// Never remove a partial file on failure: the eventual Engine owner must
// journal and reconcile it first.
func WritePrivateNoReplace(dirfd int, name string, raw []byte) error {
	return writePrivateNoReplaceWithSync(dirfd, name, raw, unix.Fsync, unix.Fsync)
}

// The non-exported sync seams permit deterministic failure/order tests.
// Production always uses real Linux fsync for both the file and parent.
func writePrivateNoReplaceWithSync(dirfd int, name string, raw []byte,
	syncFile, syncDirectory func(int) error) error {
	if !safeChild(name) || len(raw) == 0 || len(raw) > MaxPrivateFileBytes ||
		requirePrivateFD(dirfd) != nil || syncFile == nil || syncDirectory == nil {
		return fmt.Errorf("invalid private credential publication")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err == unix.EEXIST {
		existingFile, existing, readErr := openCheckedPrivateFile(dirfd, name)
		if readErr != nil {
			return readErr
		}
		defer existingFile.Close()
		defer clear(existing)
		if !bytes.Equal(existing, raw) {
			return fmt.Errorf("different protected credential already exists")
		}
		// An interrupted previous write can have the correct cached bytes
		// despite failed/missing file-data fsync. Sync the exact checked
		// inode, not a newly resolved path, before the parent directory.
		if err := syncFile(int(existingFile.Fd())); err != nil {
			return fmt.Errorf("existing private credential sync failed; preserve for reconciliation: %w", err)
		}
		if err := syncDirectory(dirfd); err != nil {
			return fmt.Errorf("private credential directory sync failed; preserve for reconciliation: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("private credential no-replace creation failed")
	}
	f := os.NewFile(uintptr(fd), "private-credential")
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		f.Close()
		return fmt.Errorf("private credential write incomplete; preserve for reconciliation")
	}
	if err := syncFile(fd); err != nil {
		f.Close()
		return fmt.Errorf("private credential sync failed; preserve for reconciliation: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("private credential close failed; preserve for reconciliation")
	}
	if err := syncDirectory(dirfd); err != nil {
		return fmt.Errorf("private credential directory sync failed; preserve for reconciliation: %w", err)
	}
	return nil
}
