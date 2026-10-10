package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// writeSensitiveHandoff creates an explicitly requested SENSITIVE export in
// a private, same-owner parent directory. It never overwrites an existing
// file, traverses a symlink, or writes secret bytes to normal stdout/JSON.
// A successful return means the complete file and parent directory synced.
// Post-publication failure is uncertain and must be reconciled manually.
func writeSensitiveHandoff(path string, body []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		len(body) == 0 || len(body) > 32*1024 {
		return fmt.Errorf("invalid sensitive handoff destination")
	}
	parent, filename := filepath.Dir(path), filepath.Base(path)
	if filename == "." || filename == ".." || filename == "" {
		return fmt.Errorf("invalid sensitive handoff name")
	}
	dir, err := openPrivateHandoffParent(parent)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate private handoff file identity: %w", err)
	}
	temporary := ".stl-handoff-" + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create protected handoff temporary file: %w", err)
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), "stl-sensitive-handoff")
	if _, err = file.Write(body); err != nil {
		file.Close()
		return fmt.Errorf("write protected handoff")
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync protected handoff")
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close protected handoff")
	}
	if err = unix.Linkat(dir, temporary, dir, filename, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("sensitive handoff destination already exists; choose another path")
		}
		return fmt.Errorf("publish protected handoff file: %w", err)
	}
	if err = unix.Unlinkat(dir, temporary, 0); err != nil {
		return fmt.Errorf("protected handoff published but cleanup uncertain")
	}
	if err = unix.Fsync(dir); err != nil {
		return fmt.Errorf("protected handoff published but durability uncertain")
	}
	return nil
}

// Walk ancestors by dirfd to reject symlink replacement, and ensure that the
// final parent is controlled by this effective user and is private (0700).
func openPrivateHandoffParent(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("invalid protected handoff parent")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if path == "/" {
		unix.Close(fd)
		return -1, fmt.Errorf("a private handoff directory is required")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("cannot open protected handoff directory component: %w", e)
		}
		var st unix.Stat_t
		if e = unix.Fstat(next, &st); e != nil {
			unix.Close(next)
			unix.Close(fd)
			return -1, fmt.Errorf("cannot inspect handoff directory")
		}
		if i == len(parts)-1 {
			if st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
				unix.Close(next)
				unix.Close(fd)
				return -1, fmt.Errorf("handoff parent must be owned and private")
			}
		} else if st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			unix.Close(next)
			unix.Close(fd)
			return -1, fmt.Errorf("handoff parent has an unsafe writable ancestor")
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}
