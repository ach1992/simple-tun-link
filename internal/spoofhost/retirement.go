package spoofhost

import (
	"context"
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
		parentfd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		err = unix.Renameat2(parentfd, filepath.Base(orig), parentfd, filepath.Base(quarantine), unix.RENAME_NOREPLACE)
		_ = unix.Close(parentfd)
		if err != nil {
			return fmt.Errorf("Spoof original retirement rename: %w", err)
		}
		targetInfo, targetErr = os.Lstat(quarantine)
	} else if !errors.Is(originalErr, fs.ErrNotExist) {
		return errors.New("Spoof original directory cannot be verified")
	}
	if targetErr == nil {
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
		allowed := map[string]bool{"material.json": true, "link.json": true, "status.json": true}
		for _, name := range names {
			if !allowed[name] {
				folder.Close()
				return fmt.Errorf("Spoof quarantine has unexpected file %q; preserve all", name)
			}
			info, err := os.Lstat(filepath.Join(quarantine, name))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 ||
				info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
				folder.Close()
				return errors.New("Spoof quarantine file identity unverified")
			}
		}
		for _, name := range names {
			if err = unix.Unlinkat(int(folder.Fd()), name, 0); err != nil {
				folder.Close()
				return fmt.Errorf("Spoof exact quarantine cleanup: %w", err)
			}
		}
		if err = folder.Sync(); err != nil {
			folder.Close()
			return err
		}
		folder.Close()
		if err = os.Remove(quarantine); err != nil {
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
