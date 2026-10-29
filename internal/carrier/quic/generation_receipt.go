package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	dup, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
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

// captureGenerationReceiptFD observes only one already pinned directory. It
// never attributes inode provenance by itself; the FIRST creation path also
// compares each witness with its original successful O_EXCL result.
func captureGenerationReceiptFD(fd int, plan Plan, nonce string, expected HelperConfigIdentity,
	receiptPresent bool) (generationReceipt, error) {
	if !validGenerationNonce(nonce) || validMaterialScope(plan) != nil {
		return generationReceipt{}, fmt.Errorf("invalid QUIC journal generation identity")
	}
	files, err := generationFiles(plan.Role)
	if err != nil {
		return generationReceipt{}, err
	}
	if err := requireExclusiveRole(fd, plan.Role); err != nil {
		return generationReceipt{}, err
	}
	if err := directoryInventory(fd, files, receiptPresent); err != nil {
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

// InspectGenerationReceipt never adopts matching bytes without the durable
// exact-nonce receipt. Receipt, inventory and all five inode witnesses are
// read through one pinned directory FD. The canonical path must still name
// that generation when inspection returns.
func InspectGenerationReceipt(root string, plan Plan, nonce string, expected HelperConfigIdentity) error {
	if !validGenerationNonce(nonce) || validMaterialScope(plan) != nil {
		return fmt.Errorf("invalid QUIC journal generation identity")
	}
	return withPinnedGenerationDir(root, plan.LinkID, func(fd int) error {
		return inspectGenerationReceiptFD(fd, plan, nonce, expected)
	})
}

// InspectJournalGeneration is the Engine's read-only generation-bound
// ownership AND semantic inspection. Neither the verified receipt nor any
// private material is accepted from a separately resolved directory.
func InspectJournalGeneration(root string, plan Plan, localWGUDPPort uint16, binary, nonce string,
	expected HelperConfigIdentity) (HelperConfigIdentity, error) {
	return inspectJournalGeneration(root, plan, localWGUDPPort, binary, nonce, expected, InspectPinnedHysteria, nil)
}

// Test-only injection points for deterministic directory/file replacement
// at exact inspection boundaries; production always supplies nil.
type generationInspectHooks struct {
	beforeReceipt func() error
	afterReceipt  func() error
	afterSemantic func() error
}

func inspectJournalGeneration(root string, plan Plan, localWGUDPPort uint16, binary, nonce string,
	expected HelperConfigIdentity, verify helperVerifier, hooks *generationInspectHooks) (HelperConfigIdentity, error) {
	if !validGenerationNonce(nonce) || validMaterialScope(plan) != nil ||
		helperConfigPreflight(root, plan, localWGUDPPort, binary) != nil {
		return HelperConfigIdentity{}, fmt.Errorf("invalid QUIC generation inspection intent")
	}
	var actual HelperConfigIdentity
	err := withPinnedGenerationDir(root, plan.LinkID, func(fd int) error {
		if hooks != nil && hooks.beforeReceipt != nil {
			if err := hooks.beforeReceipt(); err != nil {
				return fmt.Errorf("QUIC generation inspection interrupted")
			}
		}
		if err := inspectGenerationReceiptFD(fd, plan, nonce, expected); err != nil {
			return err
		}
		if hooks != nil && hooks.afterReceipt != nil {
			if err := hooks.afterReceipt(); err != nil {
				return fmt.Errorf("QUIC generation inspection interrupted")
			}
		}
		got, err := inspectHelperConfigFD(fd, root, plan, localWGUDPPort, binary, verify)
		if err != nil || got != expected {
			return fmt.Errorf("QUIC generation semantic material differs from immutable journal")
		}
		if hooks != nil && hooks.afterSemantic != nil {
			if err := hooks.afterSemantic(); err != nil {
				return fmt.Errorf("QUIC generation inspection interrupted")
			}
		}
		// A same-byte file inode replacement during the semantic read must
		// not survive a final receipt and inventory re-attestation.
		if err := inspectGenerationReceiptFD(fd, plan, nonce, expected); err != nil {
			return err
		}
		actual = got
		return nil
	})
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	return actual, nil
}

// withPinnedGenerationDir retains one verified credentials -> quic -> Link
// FD chain through the callback. A final fresh canonical traversal must
// match all three held directory identities, not only the leaf entry: an
// independent actor can replace a parent while preserving an old FD chain.
// It never creates, removes or changes private directory entries.
func withPinnedGenerationDir(root string, id domain.LinkID, inspect func(int) error) error {
	if id.Validate() != nil || inspect == nil {
		return fmt.Errorf("invalid QUIC generation inspection target")
	}
	creds, err := credentials.OpenProtected(root, false)
	if err != nil {
		return err
	}
	defer unix.Close(creds)
	parent, err := credentials.OpenOwnedPrivateDir(creds, "quic", false)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := credentials.OpenOwnedPrivateDir(parent, string(id), false)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var original unix.Stat_t
	if err := unix.Fstat(fd, &original); err != nil ||
		generationDirectoryPinned(parent, fd, string(id), original) != nil {
		return fmt.Errorf("QUIC generation directory was replaced before inspection")
	}
	if err := inspect(fd); err != nil {
		return err
	}
	if err := generationDirectoryPinned(parent, fd, string(id), original); err != nil {
		return err
	}
	freshCreds, err := credentials.OpenProtected(root, false)
	if err != nil {
		return fmt.Errorf("QUIC generation canonical private parent was replaced")
	}
	defer unix.Close(freshCreds)
	if !sameGenerationDirectoryFD(creds, freshCreds) {
		return fmt.Errorf("QUIC generation canonical credentials parent changed")
	}
	freshParent, err := credentials.OpenOwnedPrivateDir(freshCreds, "quic", false)
	if err != nil {
		return fmt.Errorf("QUIC generation canonical QUIC parent was replaced")
	}
	defer unix.Close(freshParent)
	if !sameGenerationDirectoryFD(parent, freshParent) {
		return fmt.Errorf("QUIC generation canonical QUIC parent changed")
	}
	return generationDirectoryPinned(freshParent, fd, string(id), original)
}

func sameGenerationDirectoryFD(first, second int) bool {
	var a, b unix.Stat_t
	return unix.Fstat(first, &a) == nil && unix.Fstat(second, &b) == nil &&
		a.Mode&unix.S_IFMT == unix.S_IFDIR && b.Mode&unix.S_IFMT == unix.S_IFDIR &&
		a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode &&
		a.Uid == b.Uid
}

func inspectGenerationReceiptFD(fd int, plan Plan, nonce string, expected HelperConfigIdentity) error {
	names, err := generationFiles(plan.Role)
	if err != nil {
		return err
	}
	if err := directoryInventory(fd, names, true); err != nil {
		return err
	}
	raw, err := credentials.ReadPrivateFile(fd, generationReceiptName)
	if err != nil {
		return fmt.Errorf("QUIC generation ownership receipt unavailable")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var recorded generationReceipt
	if err := decoder.Decode(&recorded); err != nil || decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("QUIC generation ownership receipt is invalid")
	}
	if recorded.SchemaVersion != 1 || recorded.LinkID != plan.LinkID ||
		recorded.Nonce != nonce || recorded.Role != plan.Role ||
		recorded.Expected != expected {
		return fmt.Errorf("QUIC generation receipt does not bind immutable journal")
	}
	actual, err := captureGenerationReceiptFD(fd, plan, nonce, expected, true)
	if err != nil || !reflect.DeepEqual(recorded, actual) {
		return fmt.Errorf("QUIC generation receipt does not match protected inode readback")
	}
	if err := directoryInventory(fd, names, true); err != nil {
		return fmt.Errorf("QUIC generation inventory changed after receipt inspection")
	}
	return nil
}

// generationDirectoryPinned requires the current canonical child path to
// remain the exact inode opened immediately after exclusive mkdirat.
func generationDirectoryPinned(parent, fd int, name string, created unix.Stat_t) error {
	var open, child unix.Stat_t
	if err := unix.Fstat(fd, &open); err != nil ||
		open.Mode&unix.S_IFMT != unix.S_IFDIR || open.Mode&0o777 != 0o700 ||
		open.Uid != uint32(os.Geteuid()) ||
		open.Dev != created.Dev || open.Ino != created.Ino ||
		open.Mode != created.Mode || open.Uid != created.Uid {
		return fmt.Errorf("originating QUIC generation directory FD identity changed")
	}
	if err := unix.Fstatat(parent, name, &child, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		child.Dev != created.Dev || child.Ino != created.Ino ||
		child.Mode != created.Mode || child.Uid != created.Uid {
		return fmt.Errorf("QUIC generation directory path was replaced")
	}
	return nil
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

// generationStageHooks allow deterministic, isolated foreign-file and
// directory interleavings. Production always passes nil.
type generationStageHooks struct {
	afterMkdir    func() error
	beforeFile    func(string) error
	afterFile     func(string) error
	beforeReceipt func() error
}

func stageJournalGeneration(ctx context.Context, root string, plan Plan, localWGUDPPort uint16,
	binary, nonce string, bundle CredentialBundle, expected HelperConfigIdentity,
	verify helperVerifier) (HelperConfigIdentity, error) {
	return stageJournalGenerationWithHooks(ctx, root, plan, localWGUDPPort, binary,
		nonce, bundle, expected, verify, nil)
}

func stageJournalGenerationWithHooks(ctx context.Context, root string, plan Plan, localWGUDPPort uint16,
	binary, nonce string, bundle CredentialBundle, expected HelperConfigIdentity,
	verify helperVerifier, hooks *generationStageHooks) (HelperConfigIdentity, error) {
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
	// Render privately before any filesystem mutation; the same existing
	// renderer validates the four credentials and complete Hysteria config.
	material := bundle.ProtectedFiles()
	defer clearRoleFiles(material)
	config, credID, err := renderHelperConfigFromFiles(root, plan, binary, material)
	if err != nil || credID != expected.Credentials {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation role credentials are not expected")
	}
	defer clear(config)
	sum := sha256.Sum256(config)
	if hex.EncodeToString(sum[:]) != expected.ConfigSHA256 {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation helper config identity drift")
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
		// Reconfirm the exact nonce-bound receipt AFTER independent semantic
		// inspection; a concurrent file/directory substitution must not turn
		// a formerly valid receipt into an accepted successful retry.
		if err := InspectGenerationReceipt(root, plan, nonce, expected); err != nil {
			return HelperConfigIdentity{}, fmt.Errorf("existing QUIC generation changed during retry")
		}
		return got, nil
	}
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("cannot create fresh exclusive QUIC generation")
	}
	// Open the just-created directory immediately, BEFORE any file staging.
	// The original FD is retained through creation, receipt and verification.
	fd, err := unix.Openat(quicDir, string(plan.LinkID),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("created QUIC generation cannot be pinned")
	}
	defer unix.Close(fd)
	var origin unix.Stat_t
	if err := unix.Fstat(fd, &origin); err != nil ||
		generationDirectoryPinned(quicDir, fd, string(plan.LinkID), origin) != nil {
		return HelperConfigIdentity{}, fmt.Errorf("new QUIC generation directory identity unverified")
	}
	// Any failure leaves this uncertain generation in place; NEVER cleanup.
	if err := unix.Fsync(quicDir); err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation directory creation durability uncertain")
	}
	if hooks != nil && hooks.afterMkdir != nil {
		if err := hooks.afterMkdir(); err != nil {
			return HelperConfigIdentity{}, fmt.Errorf("QUIC generation interrupted after mkdir")
		}
	}
	if err := generationDirectoryPinned(quicDir, fd, string(plan.LinkID), origin); err != nil {
		return HelperConfigIdentity{}, err
	}
	names, err := generationFiles(plan.Role)
	if err != nil {
		return HelperConfigIdentity{}, err
	}
	created := make(map[string]fileWitness, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return HelperConfigIdentity{}, fmt.Errorf("QUIC generation interrupted; unreceipted files retained")
		}
		if err := generationDirectoryPinned(quicDir, fd, string(plan.LinkID), origin); err != nil {
			return HelperConfigIdentity{}, err
		}
		if hooks != nil && hooks.beforeFile != nil {
			if err := hooks.beforeFile(name); err != nil {
				return HelperConfigIdentity{}, fmt.Errorf("QUIC generation interrupted before file creation")
			}
		}
		raw := material[name]
		if name == "helper.json" {
			raw = config
		}
		original, err := credentials.WritePrivateCreateOnly(fd, name, raw)
		if err != nil {
			return HelperConfigIdentity{}, fmt.Errorf("QUIC generation first creation failed; unreceipted material retained")
		}
		observed, err := privateFileWitness(fd, name)
		sum := sha256.Sum256(raw)
		if err != nil || observed.Device != original.Device ||
			observed.Inode != original.Inode || observed.SHA256 != hex.EncodeToString(sum[:]) {
			return HelperConfigIdentity{}, fmt.Errorf("QUIC generation created file identity unverified")
		}
		created[name] = observed
		if hooks != nil && hooks.afterFile != nil {
			if err := hooks.afterFile(name); err != nil {
				return HelperConfigIdentity{}, fmt.Errorf("QUIC generation interrupted after file creation")
			}
		}
	}
	if hooks != nil && hooks.beforeReceipt != nil {
		if err := hooks.beforeReceipt(); err != nil {
			return HelperConfigIdentity{}, fmt.Errorf("QUIC generation interrupted before receipt publication")
		}
	}
	if err := ctx.Err(); err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation cancelled before receipt; material retained")
	}
	if err := generationDirectoryPinned(quicDir, fd, string(plan.LinkID), origin); err != nil {
		return HelperConfigIdentity{}, err
	}
	recorded, err := captureGenerationReceiptFD(fd, plan, nonce, expected, false)
	if err != nil || recorded.DirectoryDevice != uint64(origin.Dev) ||
		recorded.DirectoryInode != origin.Ino || !reflect.DeepEqual(created, recorded.Files) {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generation originating file witnesses changed before receipt")
	}
	raw, err := json.Marshal(recorded)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("cannot serialize QUIC generation ownership receipt")
	}
	_, err = credentials.WritePrivateCreateOnly(fd, generationReceiptName, raw)
	clear(raw)
	if err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC ownership receipt publication uncertain")
	}
	if err := inspectGenerationReceiptFD(fd, plan, nonce, expected); err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC ownership receipt readback failed")
	}
	if err := generationDirectoryPinned(quicDir, fd, string(plan.LinkID), origin); err != nil {
		return HelperConfigIdentity{}, err
	}
	// Existing protected-file semantic inspection and exact helper identity
	// remain mandatory before returning a successful Stage result.
	got, err := inspectHelperConfig(root, plan, localWGUDPPort, binary, verify)
	if err != nil || got != expected {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC generated private material semantic attestation failed")
	}
	if err := generationDirectoryPinned(quicDir, fd, string(plan.LinkID), origin); err != nil {
		return HelperConfigIdentity{}, err
	}
	if err := inspectGenerationReceiptFD(fd, plan, nonce, expected); err != nil {
		return HelperConfigIdentity{}, fmt.Errorf("QUIC final generation receipt drift")
	}
	return got, nil
}
