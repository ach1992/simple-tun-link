// Package quicwgorigin records only an initial, guarded native WireGuard
// kernel-object creation for an unresolved QUIC Engine journal. It does not
// own a Link lifecycle, activate interfaces, recover resources or retire them.
package quicwgorigin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/app"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/quicguard"
	"golang.org/x/sys/unix"
)

// StageOriginal is SOURCE-ONLY. The immutable Engine journal, trusted pinned
// Hysteria material, first-published private WG key and a recorded original
// nft guard are required. Nothing starts QUIC or opens a WG UDP listener.
// An uncertain ACK/readback/alias/receipt never triggers deletion or replay.
func StageOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID) error {
	return stageOriginal(ctx, engine, id, realKernelOps())
}

// Kernel operations are injectable only inside this package's regression
// tests. The exported writer always uses the real kernel and fixed readers.
type kernelOps struct {
	runner linux.BoundedRunner
	boot   func() (string, error)
	ns     func() (string, error)
	guard  func(context.Context, string, domain.LinkID, string, uint16) (quicguard.OriginalGuardObservation, error)
	create func(context.Context, string) error
	alias  func(context.Context, int, string) error
}

func realKernelOps() kernelOps {
	return kernelOps{runner: linux.ExecRunner{}, boot: hostidentity.CurrentKernelBootID,
		ns: currentNetworkNamespace, guard: quicguard.VerifyRecordedOriginalWithinAdmission,
		create: linux.CreateQUICWireGuardStaged, alias: linux.SetLinkAliasByIndex}
}

func stageOriginal(ctx context.Context, engine *app.Engine, id domain.LinkID, ops kernelOps) error {
	if ctx == nil || engine == nil || ops.runner == nil || ops.boot == nil || ops.ns == nil ||
		ops.guard == nil || ops.create == nil || ops.alias == nil {
		return fmt.Errorf("original QUIC native WG requires canonical Engine and host readers")
	}
	return engine.WithQUICCrashIngressAdmission(ctx, id,
		func(c context.Context, root string, link domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
			// Linux netns is a per-thread resource. All nft/ip/wg readers and
			// netlink writes must observe the exact calling thread's namespace.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			return createWithReceipt(c, root, link, nonce, wg, ops)
		})
}

func createWithReceipt(ctx context.Context, root string, id domain.LinkID, nonce string,
	wg domain.WireGuardOptions, ops kernelOps) error {
	origin, err := linux.PlanQUICWGHostOrigin(id, nonce, wg.ListenPort)
	if err != nil || wg.Validate() != nil || wg.PeerPort == 0 {
		return fmt.Errorf("original QUIC native WG journal identity invalid")
	}
	firstBoot, err := ops.boot()
	if err != nil || !hostidentity.ValidBootID(firstBoot) {
		return fmt.Errorf("original QUIC native WG boot identity unavailable")
	}
	firstNS, err := ops.ns()
	if err != nil || !validNetworkNamespaceID(firstNS) {
		return fmt.Errorf("original QUIC native WG namespace unavailable")
	}
	dir, err := openReceiptDir(root, true)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := requireReceiptVacant(dir, id); err != nil {
		return err
	}

	// This must be a first-creation witness for the nft guard, not merely a
	// matching nonce/table. The guard and birth receipt must already exist.
	guardBefore, err := ops.guard(ctx, root, id, nonce, wg.ListenPort)
	if err != nil || guardBefore.Status != quicguard.GuardRecordedOriginalWitness ||
		guardBefore.ReceiptDevice == 0 || guardBefore.ReceiptInode == 0 ||
		guardBefore.KernelBootID != firstBoot || guardBefore.NetworkNS != firstNS {
		return fmt.Errorf("original QUIC nft ingress is not positively recorded in this host generation")
	}
	keyStore, err := wgbackend.NewKeyStore(root)
	if err != nil {
		return fmt.Errorf("native WG key store unavailable")
	}
	keyFile, err := keyStore.OpenForWireGuard(id, wg.LocalPublicKey)
	if err != nil {
		return fmt.Errorf("journal-matched native WG key unavailable")
	}
	defer keyFile.Close()
	var keyBirth unix.Stat_t
	if unix.Fstat(int(keyFile.Fd()), &keyBirth) != nil || keyBirth.Ino == 0 {
		return fmt.Errorf("native WG key inode unavailable")
	}

	// Never confuse a persisted reservation with actual live socket/kernel
	// vacancy. Native WG can have moved to a different netns while its
	// birthplace UDP socket remains here. A missing tool is UNKNOWN.
	vacant, err := linux.WSSGlobalWGKernelVacant(ctx, ops.runner, "wg", wg.LocalPublicKey, wg.ListenPort)
	if err != nil || !vacant {
		return fmt.Errorf("native WG identity or birthplace UDP port not verifiably vacant")
	}
	vacant, err = linux.QUICWGAllStateUDPPortVacant(ctx, ops.runner, wg.ListenPort)
	if err != nil || !vacant {
		return fmt.Errorf("native WG UDP port not verifiably vacant")
	}
	if err := stagingVacant(ctx, ops.runner, origin.StagingName, origin.OwnerTag); err != nil {
		return fmt.Errorf("original QUIC native WG staging identity occupied or unverified")
	}
	if ctx.Err() != nil || !sameHostGeneration(firstBoot, firstNS, ops) {
		return fmt.Errorf("original QUIC native WG host generation changed before creation")
	}
	// ONLY a successful exclusive RTM_NEWLINK ACK can originate this WG
	// object. An ACK failure may still have changed the kernel: quarantine.
	if err := ops.create(ctx, origin.StagingName); err != nil {
		return fmt.Errorf("original QUIC kernel WG exclusive CREATE failed or uncertain; preserve journal and guard")
	}
	index, err := inspectStaged(ctx, ops.runner, origin.StagingName, "")
	if err != nil || index <= 0 || !sameHostGeneration(firstBoot, firstNS, ops) {
		return fmt.Errorf("original QUIC native WG CREATE readback uncertain; preserve journal and guard")
	}
	// Alias is deliberately NOT claimed atomic with RTM_NEWLINK. Target the
	// just-observed ifindex; preserve the unpredictable name on interruption.
	if err := ops.alias(ctx, index, origin.OwnerTag); err != nil {
		return fmt.Errorf("original QUIC native WG alias effect uncertain; preserve journal and guard")
	}
	verifiedIndex, err := inspectStaged(ctx, ops.runner, origin.StagingName, origin.OwnerTag)
	if err != nil || verifiedIndex != index || !sameHostGeneration(firstBoot, firstNS, ops) {
		return fmt.Errorf("original QUIC native WG post-alias identity uncertain; preserve journal and guard")
	}
	guardAfter, err := ops.guard(ctx, root, id, nonce, wg.ListenPort)
	if err != nil || guardAfter != guardBefore {
		return fmt.Errorf("original QUIC guard changed during native WG CREATE; preserve journal and host resources")
	}
	again, err := keyStore.OpenForWireGuard(id, wg.LocalPublicKey)
	if err != nil {
		return fmt.Errorf("original QUIC native WG key readback uncertain")
	}
	var keyNow unix.Stat_t
	e := unix.Fstat(int(again.Fd()), &keyNow)
	closeErr := again.Close()
	if e != nil || closeErr != nil || keyBirth.Dev != keyNow.Dev || keyBirth.Ino != keyNow.Ino {
		return fmt.Errorf("original QUIC native WG key inode changed during CREATE")
	}
	receipt := originalReceipt{SchemaVersion: 1, LinkID: id, Nonce: nonce, StagingName: origin.StagingName,
		OwnerTag: origin.OwnerTag, IfIndex: index, KernelBootID: firstBoot, NetworkNS: firstNS,
		ListenPort: wg.ListenPort, GuardHandles: guardBefore.Handles}
	if ctx.Err() != nil || !sameHostGeneration(firstBoot, firstNS, ops) {
		return fmt.Errorf("original QUIC native WG identity changed before receipt; preserve resources")
	}
	if err := persistReceipt(root, dir, receipt); err != nil {
		return fmt.Errorf("original QUIC native WG first-create receipt uncertain; preserve journal and resources")
	}
	// Publication itself is a possible long host-effect window: never
	// report a successful birth from stale pre-fsync kernel observations.
	finalIndex, finalErr := inspectStaged(ctx, ops.runner, origin.StagingName, origin.OwnerTag)
	finalGuard, guardErr := ops.guard(ctx, root, id, nonce, wg.ListenPort)
	if finalErr != nil || finalIndex != index || guardErr != nil || finalGuard != guardBefore ||
		ctx.Err() != nil || !sameHostGeneration(firstBoot, firstNS, ops) {
		return fmt.Errorf("original QUIC native WG post-receipt host identity uncertain; preserve resources")
	}
	return nil
}

func sameHostGeneration(boot, ns string, ops kernelOps) bool {
	nowBoot, err1 := ops.boot()
	nowNS, err2 := ops.ns()
	return err1 == nil && err2 == nil && nowBoot == boot && nowNS == ns
}

func currentNetworkNamespace() (string, error) {
	id, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil || !validNetworkNamespaceID(id) {
		return "", fmt.Errorf("native WG calling-thread namespace unverified")
	}
	return id, nil
}

func validNetworkNamespaceID(id string) bool {
	if !strings.HasPrefix(id, "net:[") || !strings.HasSuffix(id, "]") {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(id, "net:["), "]")
	if inner == "" || inner[0] == '0' || len(inner) > 20 {
		return false
	}
	for _, ch := range inner {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	parsed, err := strconv.ParseUint(inner, 10, 64)
	return err == nil && parsed != 0 && strconv.FormatUint(parsed, 10) == inner
}

type stagedLinkRow struct {
	IfIndex  int      `json:"ifindex"`
	IfName   string   `json:"ifname"`
	Alias    string   `json:"ifalias"`
	Flags    []string `json:"flags"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

// inspectStaged demands exact, sole kernel WireGuard object identity and an
// unactivated link, both before and after tagging. This is not an adoption
// or safe-deletion predicate: ifindex and kernel names may later be recycled.
func inspectStaged(ctx context.Context, runner linux.BoundedRunner, name, alias string) (int, error) {
	out, err := runner.RunBounded(ctx, linux.CaptureLimits{Stdout: 32 << 10, Stderr: 4 << 10},
		"ip", "-details", "-json", "link", "show", "dev", name)
	if err != nil || len(out.Stderr) != 0 || ctx.Err() != nil {
		return 0, fmt.Errorf("kernel staged native WG readback incomplete")
	}
	var rows []stagedLinkRow
	if json.Unmarshal(out.Stdout, &rows) != nil || len(rows) != 1 {
		return 0, fmt.Errorf("kernel staged native WG inventory ambiguous")
	}
	row := rows[0]
	if row.IfIndex <= 0 || row.IfName != name || row.Alias != alias || row.LinkInfo.Kind != "wireguard" {
		return 0, fmt.Errorf("kernel native WG type/name/index/alias mismatch")
	}
	for _, flag := range row.Flags {
		if flag == "UP" {
			return 0, fmt.Errorf("original kernel WG unexpectedly activated")
		}
	}
	addr, err := runner.RunBounded(ctx, linux.CaptureLimits{Stdout: 32 << 10, Stderr: 4 << 10},
		"ip", "-details", "-json", "address", "show", "dev", name)
	if err != nil || len(addr.Stderr) != 0 || ctx.Err() != nil {
		return 0, fmt.Errorf("original kernel WG address readback incomplete")
	}
	var addrRows []struct {
		IfName   string            `json:"ifname"`
		IfIndex  int               `json:"ifindex"`
		AddrInfo []json.RawMessage `json:"addr_info"`
	}
	if json.Unmarshal(addr.Stdout, &addrRows) != nil || len(addrRows) != 1 ||
		addrRows[0].IfName != name || addrRows[0].IfIndex != row.IfIndex ||
		len(addrRows[0].AddrInfo) != 0 {
		return 0, fmt.Errorf("original kernel WG has unexpected addresses or changed identity")
	}
	for _, check := range []struct{ field, want string }{
		{"public-key", "(none)"}, {"listen-port", "off"}, {"peers", ""},
	} {
		got, err := runner.RunBounded(ctx, linux.CaptureLimits{Stdout: 8 << 10, Stderr: 4 << 10},
			"wg", "show", name, check.field)
		if err != nil || len(got.Stderr) != 0 || ctx.Err() != nil || strings.TrimSpace(string(got.Stdout)) != check.want {
			return 0, fmt.Errorf("original native WG configuration unverified")
		}
	}
	return row.IfIndex, nil
}

// stagingVacant is only a pre-effect collision gate. The exclusive netlink
// CREATE below remains mandatory: a clean snapshot is never ownership proof
// or a lock against another process creating the same name immediately after.
func stagingVacant(ctx context.Context, runner linux.BoundedRunner, name, tag string) error {
	out, err := runner.RunBounded(ctx, linux.CaptureLimits{Stdout: 1 << 20, Stderr: 4 << 10},
		"ip", "-details", "-json", "link", "show")
	if err != nil || len(out.Stderr) != 0 || ctx.Err() != nil {
		return fmt.Errorf("kernel interface census incomplete")
	}
	var rows []stagedLinkRow
	if json.Unmarshal(out.Stdout, &rows) != nil || len(rows) == 0 {
		return fmt.Errorf("kernel interface census invalid")
	}
	for _, row := range rows {
		if row.IfIndex <= 0 || row.IfName == "" {
			return fmt.Errorf("kernel interface census malformed")
		}
		if row.IfName == name || row.Alias == tag {
			return fmt.Errorf("native WG original identity already present; no adoption")
		}
	}
	return nil
}
