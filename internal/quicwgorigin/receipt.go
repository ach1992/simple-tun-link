package quicwgorigin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/ach1992/simple-tun-link/internal/app"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/quicguard"
	"golang.org/x/sys/unix"
)

const receiptDir = "quic-wg-origins"
const receiptMaxBytes = 2048

// An original exclusive netlink ACK and immediate, thread-scoped readback
// produced this receipt. No field represents continuous kernel ownership:
// ifindexes, netns numbers and aliases may be reused after loss of the object.
type originalReceipt struct {
	SchemaVersion int                        `json:"schema_version"`
	LinkID        domain.LinkID              `json:"link_id"`
	Nonce         string                     `json:"nonce"`
	StagingName   string                     `json:"staging_name"`
	OwnerTag      string                     `json:"owner_tag"`
	IfIndex       int                        `json:"ifindex"`
	KernelBootID  string                     `json:"kernel_boot_id"`
	NetworkNS     string                     `json:"network_namespace"`
	ListenPort    uint16                     `json:"listen_port"`
	GuardHandles  linux.WGIngressLiveHandles `json:"guard_handles"`
}

type receiptIdentity struct {
	Device uint64
	Inode  uint64
}

func (r originalReceipt) validate(id domain.LinkID, nonce string, port uint16) error {
	origin, err := linux.PlanQUICWGHostOrigin(id, nonce, port)
	if err != nil || r.SchemaVersion != 1 || r.LinkID != id || r.Nonce != nonce ||
		r.ListenPort != port || r.StagingName != origin.StagingName ||
		r.OwnerTag != origin.OwnerTag || r.IfIndex <= 0 ||
		!hostidentity.ValidBootID(r.KernelBootID) || !validNetworkNamespaceID(r.NetworkNS) ||
		r.GuardHandles.Table == 0 || r.GuardHandles.Chain == 0 || r.GuardHandles.Rule == 0 {
		return fmt.Errorf("original QUIC kernel WG receipt is invalid")
	}
	return nil
}
func receiptName(id domain.LinkID) string { return string(id) + ".json" }

func openReceiptDir(root string, create bool) (int, error) {
	parent, err := credentials.OpenProtected(root, create)
	if err != nil {
		return -1, fmt.Errorf("protected kernel WG receipt root unavailable")
	}
	defer unix.Close(parent)
	fd, err := credentials.OpenOwnedPrivateDir(parent, receiptDir, create)
	if err != nil {
		return -1, fmt.Errorf("protected kernel WG receipt directory unavailable")
	}
	if create && unix.Fsync(parent) != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("kernel WG receipt parent fsync uncertain")
	}
	return fd, nil
}

func requireReceiptVacant(dir int, id domain.LinkID) error {
	if id.Validate() != nil {
		return fmt.Errorf("invalid kernel WG receipt Link ID")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dir, receiptName(id), &st, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		return fmt.Errorf("original QUIC kernel WG receipt exists or vacancy uncertain")
	}
	return nil
}

func readReceipt(dir int, id domain.LinkID, nonce string, port uint16) (originalReceipt, receiptIdentity, error) {
	var zero originalReceipt
	fd, err := unix.Openat(dir, receiptName(id), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, receiptIdentity{}, fmt.Errorf("original kernel WG birth receipt unavailable")
	}
	f := os.NewFile(uintptr(fd), "quic-native-wg-birth-receipt")
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != uint32(os.Geteuid()) || before.Mode&0o777 != 0o600 ||
		before.Nlink != 1 || before.Size < 2 || before.Size > receiptMaxBytes {
		return zero, receiptIdentity{}, fmt.Errorf("original kernel WG birth receipt inode unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(f, receiptMaxBytes+1))
	if err != nil || int64(len(raw)) != before.Size {
		return zero, receiptIdentity{}, fmt.Errorf("original kernel WG birth receipt incomplete")
	}
	if unix.Fstatat(dir, receiptName(id), &after, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		after.Dev != before.Dev || after.Ino != before.Ino ||
		after.Mode != before.Mode || after.Nlink != before.Nlink || after.Size != before.Size {
		return zero, receiptIdentity{}, fmt.Errorf("original kernel WG birth receipt replaced while reading")
	}
	var r originalReceipt
	if json.Unmarshal(raw, &r) != nil || r.validate(id, nonce, port) != nil {
		return zero, receiptIdentity{}, fmt.Errorf("original kernel WG receipt content invalid")
	}
	canonical, e := json.Marshal(r)
	if e != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return zero, receiptIdentity{}, fmt.Errorf("original kernel WG birth receipt not canonical")
	}
	return r, receiptIdentity{Device: uint64(before.Dev), Inode: before.Ino}, nil
}

func persistReceipt(root string, dir int, receipt originalReceipt) error {
	if err := receipt.validate(receipt.LinkID, receipt.Nonce, receipt.ListenPort); err != nil {
		return err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > receiptMaxBytes {
		return fmt.Errorf("original kernel WG birth receipt too large")
	}
	created, err := credentials.WritePrivateCreateOnly(dir, receiptName(receipt.LinkID), raw)
	if err != nil {
		return fmt.Errorf("original kernel WG birth receipt publication uncertain")
	}
	// Verify the path independently from the original directory FD, so a
	// replaced canonical root cannot make an orphaned receipt look durable.
	fresh, err := openReceiptDir(root, false)
	if err != nil {
		return err
	}
	defer unix.Close(fresh)
	var oldDir, newDir unix.Stat_t
	if unix.Fstat(dir, &oldDir) != nil || unix.Fstat(fresh, &newDir) != nil ||
		oldDir.Dev != newDir.Dev || oldDir.Ino != newDir.Ino {
		return fmt.Errorf("original WG receipt canonical directory replaced")
	}
	got, now, e := readReceipt(fresh, receipt.LinkID, receipt.Nonce, receipt.ListenPort)
	if e != nil || got != receipt || now.Device != created.Device || now.Inode != created.Inode {
		return fmt.Errorf("original WG receipt inode/readback changed")
	}
	return nil
}

// OriginalObservation attests only that the locally current guarded staging
// object is consistent with a previously observed exclusive CREATE. It cannot
// prove continuity of the kernel object across observations or authorize
// adoption, recovery, deletion or retirement.
type OriginalObservation struct {
	LinkID       domain.LinkID
	StagingName  string
	IfIndex      int
	KernelBootID string
	NetworkNS    string
	GuardHandles linux.WGIngressLiveHandles
}

// InspectRecordedOriginal is a read-only Engine/journal-bound inspection.
// It never creates, renames, configures, activates or retires the interface.
func InspectRecordedOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID) (OriginalObservation, error) {
	return inspectRecordedOriginal(ctx, engine, id, realKernelOps())
}

func inspectRecordedOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID, ops kernelOps) (OriginalObservation, error) {
	if ctx == nil || engine == nil || ops.runner == nil || ops.boot == nil || ops.ns == nil || ops.guard == nil {
		return OriginalObservation{}, fmt.Errorf("read-only original WG observation requires canonical Engine")
	}
	var observed OriginalObservation
	err := engine.WithQUICCrashIngressAdmission(ctx, id, func(c context.Context, root string, link domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var err error
		observed, err = inspectWithinAdmission(c, root, link, nonce, wg.ListenPort, wg.LocalPublicKey, ops)
		return err
	})
	if err != nil {
		return OriginalObservation{}, err
	}
	return observed, nil
}

func inspectWithinAdmission(ctx context.Context, root string, id domain.LinkID, nonce string, port uint16,
	public string, ops kernelOps) (OriginalObservation, error) {
	fail := func() (OriginalObservation, error) {
		return OriginalObservation{}, fmt.Errorf("original QUIC native WG host generation unverified; preserve journal")
	}
	boot, e1 := ops.boot()
	ns, e2 := ops.ns()
	if e1 != nil || e2 != nil || !hostidentity.ValidBootID(boot) || !validNetworkNamespaceID(ns) {
		return fail()
	}
	dir, e := openReceiptDir(root, false)
	if e != nil {
		return fail()
	}
	defer unix.Close(dir)
	receipt, initial, e := readReceipt(dir, id, nonce, port)
	if e != nil || receipt.KernelBootID != boot || receipt.NetworkNS != ns {
		return fail()
	}
	guard, e := ops.guard(ctx, root, id, nonce, port)
	if e != nil || guard.Status != quicguard.GuardRecordedOriginalWitness ||
		guard.KernelBootID != boot || guard.NetworkNS != ns ||
		guard.Handles != receipt.GuardHandles {
		return fail()
	}
	index, e := inspectStaged(ctx, ops.runner, receipt.StagingName, receipt.OwnerTag)
	if e != nil || index != receipt.IfIndex {
		return fail()
	}
	store, e := wgbackend.NewKeyStore(root)
	if e != nil {
		return fail()
	}
	key, e := store.OpenForWireGuard(id, public)
	if e != nil {
		return fail()
	}
	if key.Close() != nil {
		return fail()
	}
	// Re-resolve canonical path and receipt inode after all kernel/subprocess
	// reads, rejecting same-byte replacement during this observation.
	fresh, e := openReceiptDir(root, false)
	if e != nil {
		return fail()
	}
	var firstDir, lastDir unix.Stat_t
	same := unix.Fstat(dir, &firstDir) == nil && unix.Fstat(fresh, &lastDir) == nil &&
		firstDir.Dev == lastDir.Dev && firstDir.Ino == lastDir.Ino
	again, final, readErr := readReceipt(fresh, id, nonce, port)
	unix.Close(fresh)
	if !same || readErr != nil || again != receipt || final != initial ||
		!sameHostGeneration(boot, ns, ops) || ctx.Err() != nil {
		return fail()
	}
	return OriginalObservation{LinkID: id, StagingName: receipt.StagingName,
		IfIndex: receipt.IfIndex, KernelBootID: boot, NetworkNS: ns, GuardHandles: receipt.GuardHandles}, nil
}
