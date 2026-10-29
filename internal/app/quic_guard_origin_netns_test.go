package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Isolated-only test adapter: real kernel nft CREATE/list readback, with
// synthetic iptables-version/empty-legacy and empty WG/UDP-socket snapshots
// because iptables and wg tools are not installed in the disposable chroot. NOT evidence
// of physical-host firewall compatibility or a running Hysteria service.
type appIsolatedNFTGuardRunner struct{ linux.ExecRunner }

func (r appIsolatedNFTGuardRunner) RunBounded(ctx context.Context, lim linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if name == "nft" {
		return r.ExecRunner.RunBounded(ctx, lim, name, args...)
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
	return linux.CommandResult{}, fmt.Errorf("unexpected isolated nft test query")
}

type isolatedGuardDiagnosticHost struct {
	linux.QUICWGIngressHost
	lastErr error
}

func (h *isolatedGuardDiagnosticHost) PublishOriginalQUICWGIngress(ctx context.Context, id domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
	h.lastErr = h.QUICWGIngressHost.PublishOriginalQUICWGIngress(ctx, id, nonce, wg)
	return h.lastErr
}

func TestQUICOriginalGuardEngineMaterialAndRealNFTInDisposableNetNS(t *testing.T) {
	if os.Getenv("STL_QUIC_GUARD_NFT_E2E") != "1" {
		t.Skip("explicit netns + official Hysteria fixture required")
	}
	netNow, e1 := os.Readlink("/proc/self/ns/net")
	userNow, e2 := os.Readlink("/proc/self/ns/user")
	netBefore, userBefore := os.Getenv("STL_QUIC_PARENT_NETNS"), os.Getenv("STL_QUIC_PARENT_USERNS")
	if e1 != nil || e2 != nil || netBefore == "" || userBefore == "" || netNow == netBefore || userNow == userBefore || os.Geteuid() != 0 {
		t.Fatal("refuse host effect outside explicitly unshared network AND user namespaces")
	}
	probeOut, probeErr := (appIsolatedNFTGuardRunner{}).RunBounded(context.Background(), linux.CaptureLimits{Stdout: 8 << 20, Stderr: 64 << 10}, "nft", "-j", "list", "ruleset")
	if probeErr != nil || len(probeOut.Stderr) != 0 {
		t.Fatalf("isolated nft reader unavailable: %v", probeErr)
	}
	binary := os.Getenv("STL_QUIC_HYSTERIA_BIN")
	if binary == "" {
		t.Fatal("approved official Hysteria binary required")
	}
	if _, err := quic.InspectPinnedHysteria(binary); err != nil {
		t.Fatalf("official Hysteria fixture untrusted: %v", err)
	}
	for _, role := range []composition.Role{composition.Dial, composition.Listen} {
		t.Run(string(role), func(t *testing.T) {
			ctx := context.Background()
			backend := newFakeBackend()
			engine, store := newEngine(t, backend)
			intent := materialJournalForRole(role)
			listener, dialer, err := quic.GeneratePair(intent.Plan.Local.LinkID, intent.Plan.TLSName)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Clear()
			defer dialer.Clear()
			bundle := listener
			if role == composition.Dial {
				bundle = dialer
			}
			local := intent.Plan.Local
			plan := quic.Plan{LinkID: local.LinkID, Role: quic.Role(role), Underlay: intent.Plan.Physical, TLSName: intent.Plan.TLSName}
			if role == composition.Dial {
				plan.LocalForwardUDPPort = local.LocalHelperUDPPort
				plan.PeerWGUDPPort = local.RemoteWGUDPPort
			} else {
				plan.LocalWGUDPPort = local.LocalWGUDPPort
			}
			expected, err := quic.PreviewHelperConfig(store.RootDir(), plan, local.LocalWGUDPPort, binary, bundle)
			if err != nil {
				t.Fatal(err)
			}
			intent.CertificateSHA256 = expected.Credentials.CertificateSHA256
			intent.TrustCASHA256 = expected.Credentials.TrustCASHA256
			intent.AuthorizationSHA256 = expected.Credentials.AuthorizationSHA256
			intent.HelperConfigSHA256 = expected.ConfigSHA256
			intent.ExecutablePath = binary
			intent.ExecutableSHA256 = expected.Executable.SHA256
			intent.ExecutableDevice = expected.Executable.Device
			intent.ExecutableInode = expected.Executable.Inode
			prepared, err := engine.PrepareQUICCrash(ctx, intent, &quicVacancyProbe{})
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.StageQUICCrashMaterials(ctx, local.LinkID, bundle); err != nil {
				t.Fatalf("protected original material creation: %v", err)
			}
			snapshot, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			host := &isolatedGuardDiagnosticHost{QUICWGIngressHost: linux.QUICWGIngressHost{Runner: appIsolatedNFTGuardRunner{}}}
			if err := engine.StageQUICCrashIngressGuard(ctx, local.LinkID, host); err != nil {
				t.Fatalf("real isolated guarded creation: Engine %v; Linux %v", err, host.lastErr)
			}
			guard, err := linux.NewQUICWGIngressPlan(local.LinkID, local.LocalWGUDPPort, prepared.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			// Safe test-owned, namespace-private deletion only. Never a
			// production recovery pattern or ownership proof after restart.
			t.Cleanup(func() {
				if e := exec.Command("nft", "delete", "table", "inet", guard.TableName()).Run(); e != nil {
					t.Errorf("disposable original nft cleanup: %v", e)
				}
			})
			present, err := linux.InspectWGIngressGuard(ctx, appIsolatedNFTGuardRunner{}, guard)
			if err != nil || !present {
				t.Fatalf("real nft original readback failed: %v", err)
			}
			if err := engine.StageQUICCrashIngressGuard(ctx, local.LinkID, host); err == nil {
				t.Fatal("re-run silently adopted the same nft table")
			}
			after, err := store.Load(ctx)
			if err != nil || !reflect.DeepEqual(snapshot, after) || len(after.QUICCrashOperations) != 1 ||
				backend.applyCount != 0 || len(backend.present) != 0 {
				t.Fatalf("guard effect erased immutable journal or committed a fake Link: %v", err)
			}
		})
	}
}
