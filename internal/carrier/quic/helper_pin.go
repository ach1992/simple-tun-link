package quic

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// WithPinnedJournalGeneration retains the original protected directory chain
// and every role/config/receipt file descriptor across one original helper
// effect. This prevents inode recycling during the operation; it does not
// freeze bytes against privileged in-place writers or authorize recovery.
// The canonical Engine caller must already hold its journal admission locks.
// No file or process is created, modified, removed or adopted by this API.
func WithPinnedJournalGeneration(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity, perform func() error) error {
	return withPinnedJournalGeneration(ctx, root, plan, port, binary, nonce, expected, perform, InspectPinnedHysteria)
}

func withPinnedJournalGeneration(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity, perform func() error, verify helperVerifier) error {
	if ctx == nil || perform == nil || verify == nil || !validGenerationNonce(nonce) || helperConfigPreflight(root, plan, port, binary) != nil {
		return fmt.Errorf("invalid pinned QUIC material operation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return withPinnedGenerationDir(root, plan.LinkID, func(dir int) error {
		if err := inspectGenerationReceiptFD(dir, plan, nonce, expected); err != nil {
			return err
		}
		names, err := generationFiles(plan.Role)
		if err != nil {
			return err
		}
		names = append(names, generationReceiptName)
		type heldFile struct {
			name     string
			file     *os.File
			original unix.Stat_t
		}
		pins := make([]heldFile, 0, len(names))
		defer func() {
			for _, p := range pins {
				_ = p.file.Close()
			}
		}()
		for _, name := range names {
			witness, err := privateFileWitness(dir, name)
			if err != nil {
				return err
			}
			fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("QUIC generation pin unavailable")
			}
			f := os.NewFile(uintptr(fd), "quic-generation-pin")
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != witness.Device || st.Ino != witness.Inode {
				f.Close()
				return fmt.Errorf("QUIC generation changed before pin")
			}
			pins = append(pins, heldFile{name: name, file: f, original: st})
		}
		check := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, pin := range pins {
				var fd, path unix.Stat_t
				if unix.Fstat(int(pin.file.Fd()), &fd) != nil || unix.Fstatat(dir, pin.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePinnedMaterial(pin.original, fd) || !samePinnedMaterial(fd, path) {
					return fmt.Errorf("QUIC original material inode changed")
				}
			}
			if err := inspectGenerationReceiptFD(dir, plan, nonce, expected); err != nil {
				return err
			}
			actual, err := inspectHelperConfigFD(dir, root, plan, port, binary, verify)
			if err != nil || actual != expected {
				return fmt.Errorf("QUIC pinned generation semantic drift")
			}
			return nil
		}
		if err := check(); err != nil {
			return err
		}
		if err := perform(); err != nil {
			return err
		}
		return check()
	})
}

func samePinnedMaterial(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
