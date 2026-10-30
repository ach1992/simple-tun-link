package quicwgorigin

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/quicguard"
)

// The Dev fixture has no wg/ss executable. Real netlink, ip, nft, and
// protected on-disk birth publication are exercised; only WG/ss inventories
// are mocked empty in the brand-new unshared netns. This test alone is NOT
// evidence of real WG configuration, production safety or durable ownership.
type isolatedKernelReader struct{ linux.ExecRunner }

func (r isolatedKernelReader) RunBounded(ctx context.Context, lim linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if name == "ip" || name == "nft" {
		return r.ExecRunner.RunBounded(ctx, lim, name, args...)
	}
	if name == "ss" && (reflect.DeepEqual(args, []string{"-H", "-u", "-l", "-n"}) ||
		reflect.DeepEqual(args, []string{"-H", "-u", "-a", "-n"})) {
		return linux.CommandResult{}, nil
	}
	if name == "wg" && (reflect.DeepEqual(args, []string{"show", "interfaces"}) ||
		reflect.DeepEqual(args, []string{"show", "all", "public-key"}) ||
		reflect.DeepEqual(args, []string{"show", "all", "listen-port"})) {
		return linux.CommandResult{}, nil
	}
	if name == "wg" && len(args) == 3 && args[0] == "show" {
		switch args[2] {
		case "public-key":
			return linux.CommandResult{Stdout: []byte("(none)\n")}, nil
		case "listen-port":
			return linux.CommandResult{Stdout: []byte("off\n")}, nil
		case "peers":
			return linux.CommandResult{}, nil
		}
	}
	return linux.CommandResult{}, fmt.Errorf("unexpected isolated kernel query")
}

func TestOriginalQUICNativeWGRealKernelDisposableNetNS(t *testing.T) {
	if os.Getenv("STL_QUIC_WG_ORIGINAL_NETNS") != "1" {
		t.Skip("explicit disposable mapped user/net namespace required")
	}
	nowUser, e1 := os.Readlink("/proc/self/ns/user")
	nowNet, e2 := os.Readlink("/proc/self/ns/net")
	parentUser, parentNet := os.Getenv("STL_QUIC_PARENT_USERNS"), os.Getenv("STL_QUIC_PARENT_NETNS")
	if e1 != nil || e2 != nil || nowUser == "" || nowNet == "" || parentUser == "" || parentNet == "" ||
		nowUser == parentUser || nowNet == parentNet || os.Geteuid() != 0 {
		t.Fatal("refuse host effect without verified separate disposable user AND net namespaces")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Fatal("isolated interface inventory unavailable")
	}
	for _, iface := range interfaces {
		switch iface.Name {
		case "lo", "gre0", "gretap0", "erspan0":
		default:
			t.Fatalf("foreign interface %q in purported disposable namespace", iface.Name)
		}
	}
	ctx := context.Background()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, wg := testInputs(t)
	plan, err := linux.NewQUICWGIngressPlan(testID, testPort, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := plan.NFTBatch()
	if err != nil {
		t.Fatal(err)
	}
	nft := exec.Command("nft", "-f", "-")
	nft.Stdin = strings.NewReader(batch)
	if err = nft.Run(); err != nil {
		t.Fatalf("isolated nft guard CREATE unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := exec.Command("nft", "delete", "table", "inet", plan.TableName()).Run(); err != nil {
			t.Errorf("isolated test-owned nft cleanup: %v", err)
		}
	})
	present, handles, err := linux.ReadWGIngressGuardHandles(ctx, linux.ExecRunner{}, plan)
	if err != nil || !present {
		t.Fatalf("actual isolated nft guard shape unavailable: %v", err)
	}
	bootRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	boot := strings.TrimSpace(string(bootRaw))
	reader := isolatedKernelReader{}
	guard := func(ctx context.Context, _ string, id domain.LinkID, nonce string, port uint16) (quicguard.OriginalGuardObservation, error) {
		live, e := linux.NewQUICWGIngressPlan(id, port, nonce)
		if e != nil {
			return quicguard.OriginalGuardObservation{}, e
		}
		yes, seen, e := linux.ReadWGIngressGuardHandles(ctx, reader, live)
		if e != nil || !yes {
			return quicguard.OriginalGuardObservation{}, fmt.Errorf("isolated guard disappeared")
		}
		return quicguard.OriginalGuardObservation{
			LinkID: id, Table: live.TableName(), ListenPort: port, KernelBootID: boot, NetworkNS: nowNet,
			Status: quicguard.GuardRecordedOriginalWitness, Handles: seen,
			ReceiptDevice: 22, ReceiptInode: 23}, nil
	}
	ops := kernelOps{runner: reader,
		boot: func() (string, error) { return boot, nil }, ns: currentNetworkNamespace,
		guard: guard, create: linux.CreateQUICWireGuardStaged, alias: linux.SetLinkAliasByIndex}
	// Injected positive guard witness is test-only; production requires an
	// actual persisted first-create nft receipt through quicguard.
	if err := createWithReceipt(ctx, root, testID, testNonce, wg, ops); err != nil {
		t.Fatalf("real exclusive native-WG kernel creation failed: %v", err)
	}
	inspected, err := inspectWithinAdmission(ctx, root, testID, testNonce, testPort, wg.LocalPublicKey, ops)
	if err != nil || inspected.IfIndex <= 0 || inspected.GuardHandles != handles ||
		inspected.NetworkNS != nowNet {
		t.Fatalf("recorded original kernel object not observed: %+v %v", inspected, err)
	}
	t.Cleanup(func() {
		// ONLY disposable netns, exact test-owned ifindex/name; this does
		// not model production retirement/adoption permission.
		if err := linux.DeleteLinkByIndex(context.Background(), inspected.IfIndex); err != nil {
			t.Errorf("isolated test-owned staged WG cleanup: %v", err)
		}
	})
	if err := createWithReceipt(ctx, root, testID, testNonce, wg, ops); err == nil {
		t.Fatal("real kernel first-creation was accepted twice")
	}
}
