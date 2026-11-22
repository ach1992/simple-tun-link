package spoofhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

// RetireAfterRemove is called by the canonical Engine after the SAME atomic
// state update both deletes the Link and records its irreversible receipt.
func (h *Host) RetireAfterRemove(ctx context.Context, link domain.Link) error {
	return h.retireAfterRemove(ctx, link, nil)
}

// The phase callback is nil in production. Isolated privileged tests inject
// interruption exactly after durable boundaries and partial file unlinks,
// without changing the canonical Engine or weakening original ownership.
func (h *Host) retireAfterRemove(ctx context.Context, link domain.Link, phase func(string) error) error {
	checkpoint := func(stage string) error {
		if phase != nil {
			return phase(stage)
		}
		return nil
	}
	if h == nil || ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 ||
		link.Backend != domain.BackendSpoof || link.Validate() != nil {
		return errors.New("Spoof retirement requires original valid Link and privileged Engine")
	}
	store := state.NewFileStore(h.root)
	snapshot, err := store.Load(ctx)
	if err != nil {
		return err
	}
	receipt, ok := snapshot.FindSpoofRemovalReceipt(link.ID)
	if !ok || receipt.Link != link {
		return errors.New("Spoof protected retirement lacks exact committed receipt")
	}
	if _, still := snapshot.Find(link.ID); still {
		return errors.New("Spoof Link still committed; cannot delete protected material")
	}
	unit, _, _, _, err := h.unitStatus(ctx, link)
	if err != nil || unit {
		return errors.New("Spoof original service not proven absent")
	}
	tun, _, _, _, err := h.inspectTUN(ctx, link)
	if err != nil || tun {
		return errors.New("Spoof original TUN not proven absent")
	}
	dir, err := MaterialFile(h.root, link.ID)
	if err != nil {
		return err
	}
	orig := filepath.Dir(dir)
	parent := filepath.Dir(orig)
	quarantine := filepath.Join(parent, ".retired-"+string(link.ID)+"-"+link.Spoof.MaterialSHA256)
	if err := requirePrivateDirectory(h.root); err != nil {
		return err
	}
	if err := requirePrivateDirectory(parent); err != nil {
		return err
	}
	originalInfo, originalErr := os.Lstat(orig)
	targetInfo, targetErr := os.Lstat(quarantine)
	if originalErr == nil {
		if targetErr == nil {
			return errors.New("Spoof original and quarantine both exist; refusing unsafe cleanup")
		}
		if !errors.Is(targetErr, fs.ErrNotExist) {
			return errors.New("Spoof retirement quarantine cannot be inspected")
		}
		if !originalInfo.IsDir() || requirePrivateDirectory(orig) != nil {
			return errors.New("Spoof original directory owner invalid")
		}
		if err := h.verifyMaterialConfig(link); err != nil {
			return fmt.Errorf("Spoof original material not proven identical: %w", err)
		}
		// An exact original receipt marker survives crashes after rename,
		// including after the original material/config have been unlinked.
		// Never adopt a competing directory on pathname alone.
		if err := stampSpoofRetirement(orig, link); err != nil {
			return err
		}
		parentfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		err = unix.Renameat2(parentfd, filepath.Base(orig), parentfd, filepath.Base(quarantine), unix.RENAME_NOREPLACE)
		if err == nil {
			err = checkpoint("renamed_before_parent_sync")
		}
		if err == nil {
			err = unix.Fsync(parentfd)
		}
		closeErr := unix.Close(parentfd)
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("Spoof retirement rename/parent durability: %w", err)
		}
		if err := checkpoint("renamed_parent_durable"); err != nil {
			return err
		}
		targetInfo, targetErr = os.Lstat(quarantine)
	} else if !errors.Is(originalErr, fs.ErrNotExist) {
		return errors.New("Spoof original directory cannot be verified")
	}
	if targetErr == nil {
		// An interrupted prior process might have renamed the directory
		// without syncing its parent. Make the original quarantine rename
		// durable before unlinking *any* protected material on this retry.
		parentDir, err := os.Open(parent)
		if err != nil {
			return err
		}
		err = parentDir.Sync()
		closeErr := parentDir.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("Spoof retirement parent directory durability: %w", err)
		}
		if !targetInfo.IsDir() || requirePrivateDirectory(quarantine) != nil {
			return errors.New("Spoof retirement directory identity invalid")
		}
		folder, err := os.Open(quarantine)
		if err != nil {
			return err
		}
		names, err := folder.Readdirnames(-1)
		if err != nil {
			folder.Close()
			return err
		}
		allowed := map[string]bool{"material.json": true, "link.json": true, "status.json": true, "history.json": true, spoofRetireMarker: true}
		// Empty exact quarantine is the last safe crash window: all files
		// were already removed, just before rmdir. Nonempty quarantine
		// MUST have an exact original marker, never just a familiar name.
		if len(names) != 0 {
			if err := verifySpoofRetirementMarker(quarantine, link); err != nil {
				folder.Close()
				return err
			}
		}
		for _, name := range names {
			if !allowed[name] {
				folder.Close()
				return fmt.Errorf("Spoof quarantine has unexpected file %q; preserve all", name)
			}
			info, err := os.Lstat(filepath.Join(quarantine, name))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || (name != "history.json" && info.Size() > 8192) ||
				info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
				folder.Close()
				return errors.New("Spoof quarantine file identity unverified")
			}
		}
		// Retire the receipt marker last, after all original resources.
		// Retrying after any partial unlink verifies it again.
		for _, name := range names {
			if name == spoofRetireMarker {
				continue
			}
			if err = unix.Unlinkat(int(folder.Fd()), name, 0); err != nil {
				folder.Close()
				return fmt.Errorf("Spoof exact quarantine cleanup: %w", err)
			}
			if err = checkpoint("payload_unlinked:" + name); err != nil {
				folder.Close()
				return err
			}
		}
		// The exact receipt marker must remain durable until all payload
		// unlinks have been fsynced. A power-loss replay must never observe
		// surviving protected files with an absent original marker.
		if err = folder.Sync(); err != nil {
			folder.Close()
			return err
		}
		if err = checkpoint("payloads_durable_marker_present"); err != nil {
			folder.Close()
			return err
		}
		if len(names) != 0 {
			if err = unix.Unlinkat(int(folder.Fd()), spoofRetireMarker, 0); err != nil {
				folder.Close()
				return fmt.Errorf("Spoof exact retirement marker cleanup: %w", err)
			}
			if err = checkpoint("marker_unlinked_before_sync"); err != nil {
				folder.Close()
				return err
			}
		}
		if err = folder.Sync(); err != nil {
			folder.Close()
			return err
		}
		if err = checkpoint("marker_unlink_durable"); err != nil {
			folder.Close()
			return err
		}
		folder.Close()
		if err = os.Remove(quarantine); err != nil {
			return err
		}
		if err = checkpoint("quarantine_removed_before_parent_sync"); err != nil {
			return err
		}
	} else if !errors.Is(originalErr, fs.ErrNotExist) || !errors.Is(targetErr, fs.ErrNotExist) {
		return errors.New("Spoof protected retirement directory disappeared unexpectedly")
	}
	p, err := os.Open(parent)
	if err != nil {
		return err
	}
	err = p.Sync()
	p.Close()
	if err != nil {
		return err
	}
	if err := checkpoint("quarantine_parent_durable"); err != nil {
		return err
	}
	if receipt.Retired {
		return nil
	}
	return store.Update(ctx, func(s *state.Snapshot) error {
		r, ok := s.FindSpoofRemovalReceipt(link.ID)
		if !ok || r.Link != link {
			return errors.New("Spoof retirement authorization changed")
		}
		for i := range s.SpoofRemovalReceipts {
			if s.SpoofRemovalReceipts[i].Link.ID == link.ID {
				s.SpoofRemovalReceipts[i].Retired = true
				return nil
			}
		}
		return errors.New("Spoof retirement receipt missing")
	})
}

// spoofRetireMarker is an Engine-receipt-derived owned inode written and
// fsynced BEFORE quarantine. It must never contain the secret itself.
const spoofRetireMarker = ".original-retirement-receipt"

func spoofRetireDigest(link domain.Link) (string, error) {
	raw, err := json.Marshal(link)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]) + "\n", nil
}

func verifySpoofRetirementMarker(dir string, link domain.Link) error {
	path := filepath.Join(dir, spoofRetireMarker)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("Spoof quarantine lacks original receipt marker; preserve foreign/uncertain resources: %w", err)
	}
	f := os.NewFile(uintptr(fd), "spoof-retirement-marker")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 65 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("Spoof quarantine original marker inode is untrusted")
	}
	raw := make([]byte, 65)
	if _, err := f.Read(raw); err != nil {
		return err
	}
	expected, err := spoofRetireDigest(link)
	if err != nil || string(raw) != expected {
		return errors.New("Spoof quarantine marker differs from exact committed removal receipt")
	}
	return nil
}

func stampSpoofRetirement(dir string, link domain.Link) error {
	allowed := map[string]bool{"material.json": true, "link.json": true, "status.json": true, "history.json": true, spoofRetireMarker: true}
	items, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, item := range items {
		if !allowed[item.Name()] || !item.Type().IsRegular() && item.Type() != 0 {
			return fmt.Errorf("original Spoof retirement directory contains foreign/uncertain resource %q", item.Name())
		}
	}
	marker := filepath.Join(dir, spoofRetireMarker)
	if _, err := os.Lstat(marker); err == nil {
		return verifySpoofRetirementMarker(dir, link)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	digest, err := spoofRetireDigest(link)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write([]byte(digest)); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	return err
}
