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
	if !safeChild(name) || requirePrivateFD(dirfd) != nil {
		return nil, fmt.Errorf("invalid private credential reader")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("protected credential is not readable")
	}
	f := os.NewFile(uintptr(fd), "protected-credential")
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o600 ||
		st.Nlink != 1 || st.Size < 1 || st.Size > MaxPrivateFileBytes {
		return nil, fmt.Errorf("credential inode/mode/size invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxPrivateFileBytes+1))
	if err != nil || len(raw) < 1 || len(raw) > MaxPrivateFileBytes {
		clear(raw)
		return nil, fmt.Errorf("cannot read bounded private credential")
	}
	return raw, nil
}

// WritePrivateNoReplace publishes only to an already verified private
// directory using O_EXCL; an existing file is accepted only when its exact
// content and inode are trustworthy. Never remove a partial file on failure:
// the eventual Engine owner must journal and reconcile it first.
func WritePrivateNoReplace(dirfd int, name string, raw []byte) error {
	if !safeChild(name) || len(raw) == 0 || len(raw) > MaxPrivateFileBytes ||
		requirePrivateFD(dirfd) != nil {
		return fmt.Errorf("invalid private credential publication")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err == unix.EEXIST {
		existing, readErr := ReadPrivateFile(dirfd, name)
		if readErr != nil {
			return readErr
		}
		defer clear(existing)
		if !bytes.Equal(existing, raw) {
			return fmt.Errorf("different protected credential already exists")
		}
		return unix.Fsync(dirfd)
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
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("private credential sync failed; preserve for reconciliation")
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("private credential close failed; preserve for reconciliation")
	}
	if err := unix.Fsync(dirfd); err != nil {
		return fmt.Errorf("private credential directory sync failed; preserve for reconciliation")
	}
	return nil
}
