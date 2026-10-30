package quicguard

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"golang.org/x/sys/unix"
)

const originReceiptDir = "quic-guard-origins"
const originReceiptMaxBytes = 2048

// originReceipt is an ORIGINAL-CREATE evidence record, written only after
// exclusive nft CREATE and its strict, same-thread kernel readback. It is NOT
// a live-object ownership lease, an authorization to delete/adopt a guard,
// or proof of survival through a reboot. Replaced nft objects can reuse handles.
// A privileged actor able to rewrite canonical State and protected receipt
// storage is outside this record's integrity boundary.
type originReceipt struct {
	SchemaVersion int                        `json:"schema_version"`
	LinkID        domain.LinkID              `json:"link_id"`
	Nonce         string                     `json:"nonce"`
	ListenPort    uint16                     `json:"listen_port"`
	Table         string                     `json:"table"`
	KernelBootID  string                     `json:"kernel_boot_id"`
	NetworkNS     string                     `json:"network_namespace"`
	Handles       linux.WGIngressLiveHandles `json:"handles"`
}

func (r originReceipt) validate(id domain.LinkID, nonce string, port uint16) error {
	if r.SchemaVersion != 1 || r.LinkID != id || r.Nonce != nonce || r.ListenPort != port ||
		!hostidentity.ValidBootID(r.KernelBootID) || !validNetworkNamespaceID(r.NetworkNS) ||
		r.Handles.Table == 0 || r.Handles.Chain == 0 || r.Handles.Rule == 0 {
		return fmt.Errorf("original QUIC guard receipt identity unverified")
	}
	raw, err := hex.DecodeString(nonce)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != nonce {
		return fmt.Errorf("invalid original QUIC journal nonce")
	}
	guard, err := linux.NewQUICWGIngressPlan(id, port, nonce)
	if err != nil || r.Table != guard.TableName() {
		return fmt.Errorf("original QUIC guard table binding invalid")
	}
	return nil
}

func originReceiptName(id domain.LinkID) string {
	return string(id) + ".json"
}

func openOriginReceiptDir(root string, create bool) (int, error) {
	creds, err := credentials.OpenProtected(root, create)
	if err != nil {
		return -1, fmt.Errorf("protected QUIC guard receipt root unavailable")
	}
	defer unix.Close(creds)
	dir, err := credentials.OpenOwnedPrivateDir(creds, originReceiptDir, create)
	if err != nil {
		return -1, fmt.Errorf("protected QUIC guard receipt directory unavailable")
	}
	if create && unix.Fsync(creds) != nil {
		unix.Close(dir)
		return -1, fmt.Errorf("QUIC guard receipt directory creation durability uncertain")
	}
	return dir, nil
}

func ensureOriginReceiptVacant(dir int, id domain.LinkID) error {
	if id.Validate() != nil {
		return fmt.Errorf("invalid QUIC guard receipt Link ID")
	}
	var st unix.Stat_t
	err := unix.Fstatat(dir, originReceiptName(id), &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != unix.ENOENT {
		return fmt.Errorf("original QUIC guard receipt already exists or vacancy uncertain")
	}
	return nil
}

type originReceiptFileIdentity struct {
	Device uint64
	Inode  uint64
}

func readOriginReceiptFD(dir int, id domain.LinkID, nonce string, port uint16) (originReceipt, error) {
	got, _, err := readOriginReceiptFDWithIdentity(dir, id, nonce, port)
	return got, err
}

// Both first and final host observations must be bound to the same receipt
// inode, not merely matching JSON at two unrelated file paths.
func readOriginReceiptFDWithIdentity(dir int, id domain.LinkID, nonce string, port uint16) (originReceipt, originReceiptFileIdentity, error) {
	var zero originReceipt
	name := originReceiptName(id)
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return zero, originReceiptFileIdentity{}, fmt.Errorf("original QUIC guard receipt unavailable")
	}
	f := os.NewFile(uintptr(fd), "quic-guard-origin-receipt")
	defer f.Close()
	var first, final unix.Stat_t
	if err := unix.Fstat(fd, &first); err != nil ||
		first.Mode&unix.S_IFMT != unix.S_IFREG ||
		first.Uid != uint32(os.Geteuid()) || first.Mode&0o777 != 0o600 ||
		first.Nlink != 1 || first.Size < 2 || first.Size > originReceiptMaxBytes {
		return zero, originReceiptFileIdentity{}, fmt.Errorf("original QUIC guard receipt file identity unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(f, originReceiptMaxBytes+1))
	if err != nil || int64(len(raw)) != first.Size {
		return zero, originReceiptFileIdentity{}, fmt.Errorf("original QUIC guard receipt read incomplete")
	}
	if err := unix.Fstatat(dir, name, &final, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		final.Dev != first.Dev || final.Ino != first.Ino ||
		final.Mode != first.Mode || final.Nlink != first.Nlink || final.Size != first.Size {
		return zero, originReceiptFileIdentity{}, fmt.Errorf("original QUIC guard receipt changed while reading")
	}
	var got originReceipt
	if json.Unmarshal(raw, &got) != nil || got.validate(id, nonce, port) != nil {
		return zero, originReceiptFileIdentity{}, fmt.Errorf("original QUIC guard receipt document invalid")
	}
	canonical, err := json.Marshal(got)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		// Strict round-trip rejects unknown/duplicate/case-aliased JSON fields
		// and multiple documents; a forged same-byte nft marker is no receipt.
		return zero, originReceiptFileIdentity{}, fmt.Errorf("original QUIC guard receipt encoding not canonical")
	}
	return got, originReceiptFileIdentity{Device: uint64(first.Dev), Inode: first.Ino}, nil
}

// persistOriginReceiptFD is intentionally CREATE-ONLY. If anything after nft
// dispatch fails, leave the journal and possible table quarantined; NEVER
// unlink, overwrite, adopt, or infer that the effect did not occur.
func persistOriginReceiptFD(root string, dir int, expected originReceipt, journalID domain.LinkID, nonce string, port uint16) error {
	if err := expected.validate(journalID, nonce, port); err != nil {
		return err
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("cannot serialize QUIC original guard evidence")
	}
	raw = append(raw, '\n')
	if len(raw) > originReceiptMaxBytes {
		return fmt.Errorf("QUIC original guard evidence oversized")
	}
	name := originReceiptName(expected.LinkID)
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("cannot exclusively create original QUIC guard receipt")
	}
	f := os.NewFile(uintptr(fd), "quic-guard-origin-receipt-write")
	n, writeErr := f.Write(raw)
	syncErr := f.Sync()
	var written unix.Stat_t
	statErr := unix.Fstat(fd, &written)
	closeErr := f.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || statErr != nil || closeErr != nil ||
		written.Mode&unix.S_IFMT != unix.S_IFREG || written.Mode&0o777 != 0o600 ||
		written.Uid != uint32(os.Geteuid()) || written.Nlink != 1 {
		return fmt.Errorf("original QUIC guard receipt write durability uncertain")
	}
	// Sync the directory name, then reopen by a FRESH protected path; merely
	// fsync'ing a stale FD does not prove the canonical directory still names it.
	if err := unix.Fsync(dir); err != nil {
		return fmt.Errorf("original QUIC guard receipt directory sync uncertain")
	}
	second, err := openOriginReceiptDir(root, false)
	if err != nil {
		return err
	}
	defer unix.Close(second)
	var firstDir, secondDir unix.Stat_t
	if unix.Fstat(dir, &firstDir) != nil || unix.Fstat(second, &secondDir) != nil ||
		firstDir.Dev != secondDir.Dev || firstDir.Ino != secondDir.Ino {
		return fmt.Errorf("original QUIC guard receipt directory identity changed")
	}
	got, identity, err := readOriginReceiptFDWithIdentity(second, expected.LinkID, expected.Nonce, expected.ListenPort)
	if err != nil || got != expected || identity.Device != uint64(written.Dev) || identity.Inode != written.Ino {
		return fmt.Errorf("original QUIC guard receipt readback unverified")
	}
	return nil
}

// InspectRecordedOriginal is READ-ONLY evidence that a previously recorded
// exclusive CREATE still has a matching nft shape in this exact boot/netns.
// Not sufficient for deletion/retirement after object replacement or reboot.
// Actual CLI, runtime helper, WG and restore remain unimplemented for QUIC.
func InspectRecordedOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID) (OriginalGuardObservation, error) {
	return inspectRecordedOriginal(ctx, engine, id, linux.ExecRunner{},
		hostidentity.CurrentKernelBootID, currentNetworkNamespace)
}

func inspectRecordedOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID,
	runner linux.BoundedRunner, bootID func() (string, error), networkNS func() (string, error)) (OriginalGuardObservation, error) {
	if ctx == nil || engine == nil || runner == nil || bootID == nil || networkNS == nil {
		return OriginalGuardObservation{}, fmt.Errorf("original QUIC recorded observation needs canonical Engine and fixed host readers")
	}
	var observation OriginalGuardObservation
	err := engine.WithQUICCrashIngressAdmission(ctx, id,
		func(c context.Context, root string, link domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			firstBoot, err := bootID()
			if err != nil || !hostidentity.ValidBootID(firstBoot) {
				return fmt.Errorf("original QUIC recorded boot identity unverified")
			}
			firstNS, err := networkNS()
			if err != nil || !validNetworkNamespaceID(firstNS) {
				return fmt.Errorf("original QUIC recorded namespace unverified")
			}
			dir, err := openOriginReceiptDir(root, false)
			if err != nil {
				return err
			}
			defer unix.Close(dir)
			record, initialFile, err := readOriginReceiptFDWithIdentity(dir, link, nonce, wg.ListenPort)
			if err != nil || record.KernelBootID != firstBoot || record.NetworkNS != firstNS {
				return fmt.Errorf("original QUIC receipt absent or from another host generation")
			}
			guard, err := linux.NewQUICWGIngressPlan(link, wg.ListenPort, nonce)
			if err != nil {
				return err
			}
			present, handles, err := linux.ReadWGIngressGuardHandles(c, runner, guard)
			if err != nil || !present || handles != record.Handles {
				return fmt.Errorf("recorded QUIC guard original differs from current kernel observation")
			}
			secondBoot, bErr := bootID()
			secondNS, nErr := networkNS()
			if bErr != nil || nErr != nil || firstBoot != secondBoot || firstNS != secondNS || c.Err() != nil {
				return fmt.Errorf("recorded QUIC guard host generation changed during observation")
			}
			// Keep the first directory pinned while independently resolving a
			// fresh canonical path. An interloper may substitute parent or
			// receipt inode while nft subprocesses execute.
			fresh, err := openOriginReceiptDir(root, false)
			if err != nil {
				return err
			}
			var oldDir, newDir unix.Stat_t
			same := unix.Fstat(dir, &oldDir) == nil && unix.Fstat(fresh, &newDir) == nil &&
				oldDir.Dev == newDir.Dev && oldDir.Ino == newDir.Ino
			again, finalFile, readErr := readOriginReceiptFDWithIdentity(fresh, link, nonce, wg.ListenPort)
			unix.Close(fresh)
			if !same || readErr != nil || again != record || finalFile != initialFile {
				return fmt.Errorf("recorded QUIC guard receipt changed during kernel observation")
			}
			observation = OriginalGuardObservation{
				LinkID: link, Table: guard.TableName(), ListenPort: wg.ListenPort,
				KernelBootID: firstBoot, NetworkNS: firstNS,
				Status: GuardRecordedOriginalWitness, Handles: handles,
			}
			return nil
		})
	if err != nil {
		return OriginalGuardObservation{}, err
	}
	return observation, nil
}
