package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

const generationReceiptName = "generation-owner.json"

// fileWitness records exact descriptor-observed, private inode identity.
// A digest is readback evidence, not sufficient ownership without the
// exclusive directory create and durable generation receipt.
type fileWitness struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	SHA256 string `json:"sha256"`
}

type generationReceipt struct {
	SchemaVersion   int                    `json:"schema_version"`
	LinkID          domain.LinkID          `json:"link_id"`
	Nonce           string                 `json:"nonce"`
	Role            Role                   `json:"role"`
	DirectoryDevice uint64                 `json:"directory_device"`
	DirectoryInode  uint64                 `json:"directory_inode"`
	Expected        HelperConfigIdentity   `json:"expected"`
	Files           map[string]fileWitness `json:"files"`
}

func validGenerationNonce(nonce string) bool {
	raw, err := hex.DecodeString(nonce)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == nonce
}

func generationFiles(role Role) ([]string, error) {
	names, err := roleFiles(role)
	if err != nil {
		return nil, err
	}
	files := []string{names[0], names[1], names[2], names[3], "helper.json"}
	sort.Strings(files)
	return files, nil
}

func directoryInventory(fd int, expected []string, receiptPresent bool) error {
	dup, err := unix.Dup(fd)
	if err != nil {
		return fmt.Errorf("cannot inspect protected generation inventory")
	}
	view := os.NewFile(uintptr(dup), "quic-generation-inventory")
	defer view.Close()
	entries, err := view.ReadDir(-1)
	if err != nil || len(entries) != len(expected)+btoi(receiptPresent) {
		return fmt.Errorf("QUIC generation has unexpected or incomplete file inventory")
	}
	wanted := make(map[string]bool, len(expected)+1)
	for _, name := range expected {
		wanted[name] = true
	}
	if receiptPresent {
		wanted[generationReceiptName] = true
	}
	for _, entry := range entries {
		if !wanted[entry.Name()] || entry.IsDir() {
			return fmt.Errorf("QUIC generation contains an unrecognized artifact")
		}
		delete(wanted, entry.Name())
	}
	if len(wanted) != 0 {
		return fmt.Errorf("QUIC generation inventory is incomplete")
	}
	return nil
}

func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func privateFileWitness(dirfd int, name string) (fileWitness, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fileWitness{}, fmt.Errorf("QUIC generation file unavailable")
	}
	f := os.NewFile(uintptr(fd), "quic-generation-material")
	defer f.Close()
	var st, path unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Mode&0o777 != 0o600 ||
		st.Uid != uint32(os.Geteuid()) ||
		st.Nlink != 1 || st.Size < 1 ||
		st.Size > credentials.MaxPrivateFileBytes {
		return fileWitness{}, fmt.Errorf("QUIC generation file identity is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(f, credentials.MaxPrivateFileBytes+1))
	if err != nil || len(raw) != int(st.Size) {
		clear(raw)
		return fileWitness{}, fmt.Errorf("QUIC generation file readback is incomplete")
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	if err := unix.Fstatat(dirfd, name, &path, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		path.Dev != st.Dev || path.Ino != st.Ino || path.Mode != st.Mode || path.Nlink != st.Nlink {
		return fileWitness{}, fmt.Errorf("QUIC generation file identity changed during inspection")
	}
	return fileWitness{Device: uint64(st.Dev), Inode: st.Ino, SHA256: hex.EncodeToString(digest[:])}, nil
}

func captureGenerationReceipt(root string, plan Plan, nonce string, expected HelperConfigIdentity) (generationReceipt, error) {
	if !validGenerationNonce(nonce) || validMaterialScope(plan) != nil {
		return generationReceipt{}, fmt.Errorf("invalid QUIC journal generation identity")
	}
	files, err := generationFiles(plan.Role)
	if err != nil {
		return generationReceipt{}, err
	}
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return generationReceipt{}, err
	}
	defer unix.Close(fd)
	if err := requireExclusiveRole(fd, plan.Role); err != nil {
		return generationReceipt{}, err
	}
	if err := directoryInventory(fd, files, false); err != nil {
		return generationReceipt{}, err
	}
	var dir unix.Stat_t
	if err := unix.Fstat(fd, &dir); err != nil || dir.Mode&unix.S_IFMT != unix.S_IFDIR ||
		dir.Mode&0o777 != 0o700 || dir.Uid != uint32(os.Geteuid()) {
		return generationReceipt{}, fmt.Errorf("QUIC generation directory is untrusted")
	}
	receipt := generationReceipt{SchemaVersion: 1, LinkID: plan.LinkID, Nonce: nonce,
		Role: plan.Role, DirectoryDevice: uint64(dir.Dev), DirectoryInode: dir.Ino,
		Expected: expected, Files: make(map[string]fileWitness, len(files))}
	for _, name := range files {
		identity, err := privateFileWitness(fd, name)
		if err != nil {
			return generationReceipt{}, err
		}
		receipt.Files[name] = identity
	}
	if err := unix.Fsync(fd); err != nil {
		return generationReceipt{}, fmt.Errorf("QUIC generation directory could not be synced")
	}
	return receipt, nil
}

// InspectGenerationReceipt verifies a complete, durable, nonce-bound positive
// create-time witness. This is necessary, NOT sufficient, for host resources
// ownership or running a helper. A missing receipt never permits adoption of
// identical old credentials/config; the Engine journal remains quarantined.
func InspectGenerationReceipt(root string, plan Plan, nonce string, expected HelperConfigIdentity) error {
	if !validGenerationNonce(nonce) || validMaterialScope(plan) != nil {
		return fmt.Errorf("invalid QUIC journal generation identity")
	}
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return err
	}
	names, err := generationFiles(plan.Role)
	if err != nil {
		unix.Close(fd)
		return err
	}
	if err := directoryInventory(fd, names, true); err != nil {
		unix.Close(fd)
		return err
	}
	raw, err := credentials.ReadPrivateFile(fd, generationReceiptName)
	unix.Close(fd)
	if err != nil {
		return fmt.Errorf("QUIC generation ownership receipt unavailable")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var recorded generationReceipt
	if err := decoder.Decode(&recorded); err != nil ||
		decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("QUIC generation ownership receipt is invalid")
	}
	if recorded.SchemaVersion != 1 || recorded.LinkID != plan.LinkID ||
		recorded.Nonce != nonce || recorded.Role != plan.Role ||
		recorded.Expected != expected {
		return fmt.Errorf("QUIC generation receipt does not bind immutable journal")
	}
	actual, err := captureGenerationReceiptForReadback(root, plan, nonce, expected)
	if err != nil || !reflect.DeepEqual(recorded, actual) {
		return fmt.Errorf("QUIC generation receipt does not match protected inode readback")
	}
	return nil
}

// Receipt verification compares the 5 actual material inodes but never
// reinterprets the receipt itself as one of the original five files.
func captureGenerationReceiptForReadback(root string, plan Plan, nonce string, expected HelperConfigIdentity) (generationReceipt, error) {
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return generationReceipt{}, err
	}
	defer unix.Close(fd)
	files, err := generationFiles(plan.Role)
	if err != nil {
		return generationReceipt{}, err
	}
	var dir unix.Stat_t
	if err := unix.Fstat(fd, &dir); err != nil || dir.Mode&unix.S_IFMT != unix.S_IFDIR ||
		dir.Mode&0o777 != 0o700 || dir.Uid != uint32(os.Geteuid()) {
		return generationReceipt{}, errors.New("QUIC generation directory identity unsafe")
	}
	receipt := generationReceipt{SchemaVersion: 1, LinkID: plan.LinkID, Nonce: nonce,
		Role: plan.Role, DirectoryDevice: uint64(dir.Dev), DirectoryInode: dir.Ino,
		Expected: expected, Files: make(map[string]fileWitness, len(files))}
	for _, name := range files {
		file, err := privateFileWitness(fd, name)
		if err != nil {
			return generationReceipt{}, err
		}
		receipt.Files[name] = file
	}
	return receipt, nil
}

// StageJournalGeneration is a source-only writer for an exact immutable
// Engine journal. It creates the Link material directory via exclusive
// mkdirat *before* any private file, then publishes a durable receipt only
// after the entire five-file generation is verified. On a retry, an already
// existing directory is accepted ONLY with that exact verified receipt.
// An interrupted unreceipted generation is quarantined, not resumed/cleared.
func StageJournalGeneration(ctx context.Context, root string, plan Plan, localWGUDPPort uint16,
	binary, nonce string, bundle CredentialBundle, expected HelperConfigIdentity) (HelperConfigIdentity, error) {
	return stageJournalGeneration(ctx, root, plan, localWGUDPPort, binary, nonce, bundle, expected, InspectPinnedHysteria)
}

func stageJournalGeneration(ctx context.Context, root string, plan Plan, localWGUDPPort uint16,
	binary, nonce string, bundle CredentialBundle, expected HelperConfigIdentity,
	verify helperVerifier) (HelperConfigIdentity, error) {
	if ctx == nil || !validGenerationNonce(nonce) || validMaterialScope(plan) != nil {
		return HelperConfigIdentity{}, fmt.Errorf("invalid QUIC journal generation preflight")
	}
	if err := ctx.Err(); err != nil {
		return HelperConfigIdentity{}, err
	}
	preview, err := previewHelperConfig(root, plan, localWGUDPPort, binary, bundle, verify)
	if err != nil || preview != expected {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation does not match expected immutable journal")
	}
	if err := ctx.Err(); err != nil {
		return HelperConfigIdentity{}, err
	}
	credsParent, err := credentials.OpenProtected(root, true)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer unix.Close(credsParent)
	quicDir, err := credentials.OpenOwnedPrivateDir(credsParent, "quic", true)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	defer unix.Close(quicDir)
	err = unix.Mkdirat(quicDir, string(plan.LinkID), 0o700)
	if err == unix.EEXIST {
		// A matching digest/credential is not a create-time ownership proof.
		// Only an already durable receipt of this exact journal can retry.
		if err := InspectGenerationReceipt(root, plan, nonce, expected); err != nil {
			return HelperConfigIdentity{}, fmt.Errorf("existing QUIC generation lacks proven creation ownership")
		}
		got, err := inspectHelperConfig(root, plan, localWGUDPPort, binary, verify)
		if err != nil || got != expected {
			return HelperConfigIdentity{}, fmt.Errorf("existing QUIC generation identity drift")
		}
		return got, nil
	}
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("cannot create fresh exclusive QUIC generation")
	}
	// No retry or cleanup if this fsync fails: a private, unreceipted
	// directory may now exist and must remain quarantined.
	if err := unix.Fsync(quicDir); err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation directory creation durability uncertain")
	}
	if err := ctx.Err(); err != nil {
		return HelperConfigIdentity{}, err
	}
	got, err := stageExpectedMaterials(ctx, root, plan, localWGUDPPort, binary, bundle, expected, verify)
	if err != nil || got != expected || ctx.Err() != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation incomplete; private files retained without ownership receipt")
	}
	recorded, err := captureGenerationReceipt(root, plan, nonce, expected)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation ownership readback incomplete")
	}
	raw, err := json.Marshal(recorded)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("cannot serialize QUIC generation ownership receipt")
	}
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	err = credentials.WritePrivateNoReplace(fd, generationReceiptName, raw)
	unix.Close(fd)
	clear(raw)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC ownership receipt publication uncertain")
	}
	if err := InspectGenerationReceipt(root, plan, nonce, expected); err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC ownership receipt readback failed")
	}
	return got, nil
}
