package quicguard

import (
	"context"
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

// This opt-in test validates a REAL nft CREATE/strict readback in an
// unshared user+network namespace. The development host has no iptables
// and wg binaries in its chroot, so the iptables and WG/socket snapshots
// are simulated; the actual nft transaction and all nft readbacks remain real. Do not
// treat this as production-policy or end-to-end QUIC acceptance.
type isolatedNftGuardRunner struct{ linux.ExecRunner }

func (r isolatedNftGuardRunner) RunBounded(ctx context.Context, limit linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if name == "nft" {
		return r.ExecRunner.RunBounded(ctx, limit, name, args...)
	}
	switch {
	case name == "iptables" && reflect.DeepEqual(args, []string{"-V"}):
		return linux.CommandResult{Stdout: []byte("iptables v1.8.11 (nf_tables)\n")}, nil
	case name == "ip6tables" && reflect.DeepEqual(args, []string{"-V"}):
		return linux.CommandResult{Stdout: []byte("ip6tables v1.8.11 (nf_tables)\n")}, nil
	case name == "iptables-legacy-save" && len(args) == 0:
		return linux.CommandResult{Stdout: []byte{}}, nil
	case name == "ip6tables-legacy-save" && len(args) == 0:
		return linux.CommandResult{Stdout: []byte{}}, nil
	case name == "wg" && (reflect.DeepEqual(args, []string{"show", "interfaces"}) ||
		reflect.DeepEqual(args, []string{"show", "all", "public-key"}) ||
		reflect.DeepEqual(args, []string{"show", "all", "listen-port"})):
		return linux.CommandResult{Stdout: []byte{}}, nil
	case name == "ss" && (reflect.DeepEqual(args, []string{"-H", "-u", "-l", "-n"}) ||
		reflect.DeepEqual(args, []string{"-H", "-u", "-a", "-n"})):
		return linux.CommandResult{Stdout: []byte{}}, nil
	}
	return linux.CommandResult{}, fmt.Errorf("unexpected isolated firewall query")
}

func TestQUICOriginalGuardRealNFTDisposableUserNetNS(t *testing.T) {
	if os.Getenv("STL_QUIC_GUARD_NFT_E2E") != "1" {
		t.Skip("isolated user+network namespace test is opt-in")
	}
	self, e1 := os.Readlink("/proc/self/ns/net")
	user, e2 := os.Readlink("/proc/self/ns/user")
	parentNet, parentUser := os.Getenv("STL_QUIC_PARENT_NETNS"), os.Getenv("STL_QUIC_PARENT_USERNS")
	if e1 != nil || e2 != nil || parentNet == "" || parentUser == "" ||
		self == parentNet || user == parentUser || os.Geteuid() != 0 {
		t.Fatal("refuse nft mutation without explicitly verified fresh user and network namespaces")
	}
	plan, err := linux.NewQUICWGIngressPlan(fixtureID, 51820, fixtureNonce)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	runner := isolatedNftGuardRunner{}
	if err := publishOriginal(ctx, runner, fixtureID, fixtureNonce, testWG(), runOriginalNFTCreate); err != nil {
		t.Fatalf("isolated original create: %v", err)
	}
	t.Cleanup(func() {
		if err := exec.Command("nft", "delete", "table", "inet", plan.TableName()).Run(); err != nil {
			t.Errorf("scoped disposable guard deletion: %v", err)
		}
	})
	present, err := linux.InspectWGIngressGuard(ctx, runner, plan)
	if err != nil || !present {
		t.Fatalf("isolated created guard readback mismatch: %v", err)
	}
	if err := publishOriginal(ctx, runner, fixtureID, fixtureNonce, testWG(), runOriginalNFTCreate); err == nil {
		t.Fatal("original publisher adopted exact existing nft table on retry")
	}
}
