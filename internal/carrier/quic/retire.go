package quic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// RetireOwnedGeneration is called only under canonical Link/resource locks
// after a durable positive managed Remove receipt and complete host vacancy.
// It removes the original protected generation, preserving any replacement,
// unknown entry or uncertain read. The original receipt is removed last, so
// interruption can resume exact remaining file checks without adopting bytes.
// Expired certificates are eligible for retirement, never for a new launch.
func RetireOwnedGeneration(ctx context.Context, root string, plan Plan, nonce string,
	expected HelperConfigIdentity, identity MaterialIdentity) error {
	if ctx == nil || validMaterialScope(plan) != nil || !validGenerationNonce(nonce) || !validMaterialIdentity(identity) ||
		identity.CertificateSHA256 != expected.Credentials.CertificateSHA256 || identity.TrustCASHA256 != expected.Credentials.TrustCASHA256 ||
		identity.AuthorizationSHA256 != expected.Credentials.AuthorizationSHA256 || identity.HelperConfigSHA256 != expected.ConfigSHA256 {
		return fmt.Errorf("original managed QUIC retirement identity missing")
	}
	if identity.ObfuscationSHA256 != expected.Credentials.ObfuscationSHA256 ||
		(plan.Obfuscation == domain.QUICObfuscationPlain && identity.ObfuscationSHA256 != "") ||
		(plan.Obfuscation == domain.QUICObfuscationSalamander && (!validSHA256(identity.ObfuscationSHA256) || identity.ObfuscationSHA256 == identity.AuthorizationSHA256)) {
		return fmt.Errorf("QUIC retirement obfuscation identity differs from selected mode")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	creds, err := credentials.OpenProtected(root, false)
	if err != nil {
		return err
	}
	defer unix.Close(creds)
	parent, missing, err := maybePrivateDirectory(creds, "quic")
	if err != nil {
		return err
	}
	if missing {
		if err := unix.Fsync(creds); err != nil {
			return fmt.Errorf("QUIC private-parent absence durability uncertain: %w", err)
		}
		return nil
	}
	defer unix.Close(parent)
	dir, missing, err := maybePrivateDirectory(parent, string(plan.LinkID))
	if err != nil {
		return err
	}
	// A prior unlink may have returned an fsync error. Observing the name
	// absent on retry is insufficient to report durable retirement: sync
	// the same protected parent before the Engine consumes its receipt.
	if missing {
		if err := unix.Fsync(parent); err != nil {
			return fmt.Errorf("QUIC original directory absence durability uncertain: %w", err)
		}
		return nil
	}
	defer unix.Close(dir)
	var original unix.Stat_t
	if unix.Fstat(dir, &original) != nil || uint64(original.Dev) != identity.DirectoryDevice || original.Ino != identity.DirectoryInode ||
		generationDirectoryPinned(parent, dir, string(plan.LinkID), original) != nil {
		return fmt.Errorf("QUIC retirement directory is not the recorded original")
	}
	names, err := generationFiles(plan)
	if err != nil {
		return err
	}
	entries, err := retirementInventory(dir)
	if err != nil {
		return err
	}
	for _, name := range entries {
		if name != generationReceiptName && !slices.Contains(names, name) {
			return fmt.Errorf("QUIC retirement directory contains unknown material")
		}
	}
	if !slices.Contains(entries, generationReceiptName) {
		if len(entries) != 0 {
			return fmt.Errorf("QUIC retirement receipt missing while material remains")
		}
		return removeRetiredDirectory(ctx, root, creds, parent, dir, plan.LinkID, original)
	}
	receiptWitness, err := privateFileWitness(dir, generationReceiptName)
	if err != nil || receiptWitness.Device != identity.ReceiptDevice || receiptWitness.Inode != identity.ReceiptInode {
		return fmt.Errorf("QUIC retirement receipt identity differs")
	}
	raw, err := credentials.ReadPrivateFile(dir, generationReceiptName)
	if err != nil {
		return err
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var recorded generationReceipt
	if decoder.Decode(&recorded) != nil || decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("QUIC retirement receipt is malformed")
	}
	canonical, err := json.Marshal(recorded)
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(canonical)
		return fmt.Errorf("QUIC retirement receipt is noncanonical")
	}
	clear(canonical)
	if recorded.SchemaVersion != 1 || recorded.LinkID != plan.LinkID || recorded.Role != plan.Role || recorded.Obfuscation != plan.Obfuscation || recorded.Nonce != nonce ||
		recorded.DirectoryDevice != identity.DirectoryDevice || recorded.DirectoryInode != identity.DirectoryInode || recorded.Expected != expected || len(recorded.Files) != len(names) {
		return fmt.Errorf("QUIC retirement receipt differs from original managed generation")
	}
	role, _ := roleFiles(plan.Role)
	if recorded.Files[role[1]].SHA256 != identity.TLSKeySHA256 {
		return fmt.Errorf("QUIC original TLS private key identity differs")
	}
	for _, name := range names {
		w, ok := recorded.Files[name]
		if !ok || w.Device == 0 || w.Inode == 0 || !validSHA256(w.SHA256) {
			return fmt.Errorf("QUIC retirement receipt has incomplete original file witnesses")
		}
	}
	// Pin and validate every remaining original file before the first unlink.
	// Keep receipt last even though the other names are sorted for stability.
	ordered := append(append([]string(nil), names...), generationReceiptName)
	type retirePin struct {
		name    string
		file    *os.File
		stat    unix.Stat_t
		witness fileWitness
	}
	var pins []retirePin
	defer func() {
		for _, pin := range pins {
			_ = pin.file.Close()
		}
	}()
	for _, name := range ordered {
		if !slices.Contains(entries, name) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		want := recorded.Files[name]
		if name == generationReceiptName {
			want = receiptWitness
		}
		got, err := privateFileWitness(dir, name)
		if err != nil || got != want {
			return fmt.Errorf("QUIC original retirement file differs; no material removed")
		}
		fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("QUIC original retirement descriptor unavailable")
		}
		file := os.NewFile(uintptr(fd), "quic-retirement-pin")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != want.Device || st.Ino != want.Inode {
			_ = file.Close()
			return fmt.Errorf("QUIC original retirement inode changed")
		}
		pins = append(pins, retirePin{name, file, st, want})
	}
	for _, pin := range pins {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyRetirementParents(root, creds, parent, dir, plan.LinkID, original); err != nil {
			return err
		}
		var held, path unix.Stat_t
		if unix.Fstat(int(pin.file.Fd()), &held) != nil || unix.Fstatat(dir, pin.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			!samePinnedMaterial(pin.stat, held) || !samePinnedMaterial(held, path) {
			return fmt.Errorf("QUIC original retirement file changed before deletion")
		}
		got, err := privateFileWitness(dir, pin.name)
		if err != nil || got != pin.witness {
			return fmt.Errorf("QUIC retirement content changed before deletion")
		}
		// The retained inode cannot be recycled; compare the final pathname
		// again immediately before its descriptor-relative unlink.
		if unix.Fstatat(dir, pin.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || !samePinnedMaterial(held, path) {
			return fmt.Errorf("QUIC retirement pathname was replaced")
		}
		if err := unix.Unlinkat(dir, pin.name, 0); err != nil {
			return fmt.Errorf("QUIC original private file removal failed: %w", err)
		}
		if err := unix.Fsync(dir); err != nil {
			return fmt.Errorf("QUIC private file removal durability uncertain: %w", err)
		}
	}
	return removeRetiredDirectory(ctx, root, creds, parent, dir, plan.LinkID, original)
}

func validMaterialIdentity(i MaterialIdentity) bool {
	if i.ObfuscationSHA256 != "" && !validSHA256(i.ObfuscationSHA256) {
		return false
	}
	for _, digest := range []string{i.CertificateSHA256, i.TLSKeySHA256, i.TrustCASHA256, i.AuthorizationSHA256, i.HelperConfigSHA256} {
		if !validSHA256(digest) {
			return false
		}
	}
	return i.DirectoryDevice != 0 && i.DirectoryInode != 0 && i.ReceiptDevice != 0 && i.ReceiptInode != 0
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func maybePrivateDirectory(parent int, name string) (int, bool, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == unix.ENOENT {
		return -1, true, nil
	} else if err != nil {
		return -1, false, fmt.Errorf("QUIC private directory cannot be inspected")
	}
	fd, err := credentials.OpenOwnedPrivateDir(parent, name, false)
	return fd, false, err
}

func retirementInventory(dir int) ([]string, error) {
	fd, err := unix.Openat(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("QUIC retirement inventory unavailable")
	}
	f := os.NewFile(uintptr(fd), "quic-retirement-inventory")
	defer f.Close()
	// The largest admitted generation has six role/config files and receipt.
	// The caller separately checks the selected mode's exact file inventory.
	entries, err := f.ReadDir(8)
	if err != nil && err != io.EOF || len(entries) > 7 {
		return nil, fmt.Errorf("QUIC retirement inventory differs")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func verifyRetirementParents(root string, creds, parent, dir int, id domain.LinkID, original unix.Stat_t) error {
	fresh, err := credentials.OpenProtected(root, false)
	if err != nil {
		return err
	}
	defer unix.Close(fresh)
	if !sameGenerationDirectoryFD(creds, fresh) {
		return fmt.Errorf("QUIC retirement canonical credential parent changed")
	}
	q, err := credentials.OpenOwnedPrivateDir(fresh, "quic", false)
	if err != nil {
		return err
	}
	defer unix.Close(q)
	if !sameGenerationDirectoryFD(parent, q) {
		return fmt.Errorf("QUIC retirement canonical QUIC parent changed")
	}
	return generationDirectoryPinned(q, dir, string(id), original)
}

func removeRetiredDirectory(ctx context.Context, root string, creds, parent, dir int, id domain.LinkID, original unix.Stat_t) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyRetirementParents(root, creds, parent, dir, id, original); err != nil {
		return err
	}
	entries, err := retirementInventory(dir)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("QUIC retired generation still contains material")
	}
	if err := unix.Fsync(dir); err != nil {
		return fmt.Errorf("QUIC empty generation durability uncertain")
	}
	if err := unix.Unlinkat(parent, string(id), unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("QUIC original empty directory removal failed: %w", err)
	}
	if err := unix.Fsync(parent); err != nil {
		return fmt.Errorf("QUIC original directory removal durability uncertain: %w", err)
	}
	return nil
}

// GenerationAbsent is read-only. A consumed retirement receipt never grants
// permission to delete files that have subsequently appeared under the name.
func GenerationAbsent(root string, id domain.LinkID) (bool, error) {
	if id.Validate() != nil {
		return false, fmt.Errorf("invalid QUIC retirement Link")
	}
	creds, err := credentials.OpenProtected(root, false)
	if err != nil {
		return false, err
	}
	defer unix.Close(creds)
	parent, missing, err := maybePrivateDirectory(creds, "quic")
	if err != nil || missing {
		return missing, err
	}
	defer unix.Close(parent)
	var st unix.Stat_t
	err = unix.Fstatat(parent, string(id), &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("QUIC retired generation absence is unverified")
	}
	return false, nil
}
