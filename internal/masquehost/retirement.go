package masquehost

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

// RetireMatching deletes only an exact original material generation after
// Engine committed Remove and published a durable receipt. The original
// generation is atomically renamed into one deterministic protected quarantine
// before removing individual files; interruption is safely retryable.
func (h *Host) RetireMatching(ctx context.Context, link domain.Link) error {
	if h == nil || ctx == nil || ctx.Err() != nil ||
		link.Backend != domain.BackendMASQUE || link.Validate() != nil || os.Geteuid() != 0 {
		return errors.New("MASQUE material retirement requires a validated original Link")
	}
	snapshot, err := state.NewFileStore(h.root).Load(ctx)
	if err != nil {
		return errors.New("MASQUE retirement State cannot be loaded")
	}
	receipt, ok := snapshot.FindMASQUERemovalReceipt(link.ID)
	if !ok || receipt.Link != link || receipt.MaterialSHA256 != link.MASQUE.MaterialSHA256 {
		return errors.New("MASQUE retirement receipt does not authorize this original material")
	}
	if _, present := snapshot.Find(link.ID); present {
		return errors.New("MASQUE committed Link still exists")
	}
	if _, pending := snapshot.FindMASQUEOperation(link.ID); pending {
		return errors.New("MASQUE incomplete host effect blocks credential retirement")
	}
	// Even a stopped-but-loaded owned service is an uncleared host resource.
	unitExists, _, _, err := h.unitStatus(ctx, link)
	if err != nil || unitExists {
		return errors.New("MASQUE original service must be verified absent before retiring credentials")
	}
	tunExists, _, _, _, _, err := h.inspectTun(ctx, link)
	if err != nil || tunExists {
		return errors.New("MASQUE original TUN must be verified absent before retiring credentials")
	}
	parent := filepath.Join(h.root, materialDir)
	for _, dir := range []string{h.root, parent} {
		if err := safeRootDirectory(dir); err != nil {
			return err
		}
	}
	orig, err := h.materialPath(link.ID)
	if err != nil {
		return err
	}
	// Prefix is bound to the exact Link AND entire material generation.
	quarantine := filepath.Join(parent, ".masque-retire-"+string(link.ID)+"-"+link.MASQUE.MaterialSHA256)
	origInfo, originalErr := os.Lstat(orig)
	targetInfo, targetErr := os.Lstat(quarantine)
	if originalErr == nil && targetErr == nil {
		return errors.New("MASQUE original and retirement quarantine simultaneously exist")
	}
	if originalErr == nil {
		if !errors.Is(targetErr, fs.ErrNotExist) {
			return errors.New("MASQUE retirement quarantine path is unavailable")
		}
		if !origInfo.IsDir() || safeRootDirectory(orig) != nil {
			return errors.New("MASQUE original material directory ownership invalid")
		}
		// All bytes must match original State before moving. A mismatch
		// cannot be reissued, adopted, or deleted by this retirement.
		if _, _, err := h.inspectMaterial(link); err != nil {
			return err
		}
		dirFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		err = unix.Renameat2(dirFD, string(link.ID), dirFD, filepath.Base(quarantine), unix.RENAME_NOREPLACE)
		closeErr := unix.Close(dirFD)
		if err != nil || closeErr != nil {
			return errors.New("MASQUE protected original material retirement rename failed")
		}
		targetInfo, targetErr = os.Lstat(quarantine)
	}
	if !errors.Is(originalErr, fs.ErrNotExist) && originalErr != nil {
		return errors.New("MASQUE material identity unreadable")
	}
	if targetErr != nil {
		if errors.Is(targetErr, fs.ErrNotExist) && errors.Is(originalErr, fs.ErrNotExist) {
			return nil // A prior cleanup completed before receipt finalization.
		}
		return errors.New("MASQUE retirement quarantine unreadable")
	}
	if !targetInfo.IsDir() || safeRootDirectory(quarantine) != nil {
		return errors.New("MASQUE retirement quarantine is not an owned private directory")
	}
	dir, err := os.Open(quarantine)
	if err != nil {
		return err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	allowed := make(map[string]struct{})
	for _, name := range materialNames(link) {
		allowed[name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("unexpected entry in MASQUE quarantine; preserving all contents")
		}
		if strings.ContainsAny(name, "/\\\x00") {
			return errors.New("MASQUE quarantine entry name invalid")
		}
		raw, err := trustedFile(filepath.Join(quarantine, name), 1<<20)
		if err != nil {
			return errors.New("MASQUE quarantine file identity unavailable")
		}
		clear(raw)
	}
	// File identity is verified from the opened, isolated one-Link
	// directory; partial deletion leaves only trusted named files for retry.
	for _, name := range names {
		if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
			return errors.New("MASQUE quarantine file retirement incomplete")
		}
	}
	if err := dir.Sync(); err != nil {
		return errors.New("MASQUE retirement directory fsync failed")
	}
	if err := os.Remove(quarantine); err != nil {
		return errors.New("MASQUE retirement quarantine directory cleanup incomplete")
	}
	parentFile, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer parentFile.Close()
	if err := parentFile.Sync(); err != nil {
		return errors.New("MASQUE material parent retirement fsync failed")
	}
	return nil
}
