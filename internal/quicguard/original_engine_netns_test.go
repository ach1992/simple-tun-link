package quicguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
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

type isolatedVacancyProbe struct{}

func (isolatedVacancyProbe) Vacant(context.Context, []domain.ResourceClaim) (bool, error) {
	return true, nil
}

func isolatedEngine(t *testing.T) (*app.Engine, *state.FileStore) {
	t.Helper()
	root := t.TempDir()
	store := state.NewFileStore(root)
	registry, err := backend.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := app.New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	return engine, store
}

func isolatedIntent(role composition.Role) state.QUICCrashOperation {
	local := composition.QUICLocalAdmission{
		LinkID: "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Role: role,
		LocalWGUDPPort: 51821, LocalHelperUDPPort: 52211, RemoteWGUDPPort: 51820,
	}
	wg := domain.WireGuardOptions{
		LocalPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32)),
		PeerPublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32)),
		ListenPort:     51821, PeerPort: 52211,
	}
	if role == composition.Listen {
		local.LocalWGUDPPort = 51820
		local.LocalHelperUDPPort = 443
		local.RemoteWGUDPPort = 0
		wg.ListenPort = 51820
		wg.PeerPort = 51821
	}
	return state.QUICCrashOperation{
		Plan: composition.QUICHostPlan{Local: local,
			Physical: netip.MustParseAddrPort("198.51.100.60:443"), TLSName: "198.51.100.60"},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.96.20.0/31"), Peer: netip.MustParsePrefix("10.96.20.1/31")},
		WireGuard:         wg,
		CertificateSHA256: strings.Repeat("a", 64), TrustCASHA256: strings.Repeat("b", 64),
		AuthorizationSHA256: strings.Repeat("c", 64), HelperConfigSHA256: strings.Repeat("d", 64),
		ExecutablePath: "/opt/hysteria", ExecutableSHA256: strings.Repeat("e", 64),
		ExecutableDevice: 1, ExecutableInode: 2,
	}
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
			engine, store := isolatedEngine(t)
			intent := isolatedIntent(role)
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
			prepared, err := engine.PrepareQUICCrash(ctx, intent, isolatedVacancyProbe{})
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
			readBoot := func() (string, error) { return testBootID, nil }
			readNS := func() (string, error) { return currentNetworkNamespace() }
			absent, err := inspectPendingOriginal(ctx, engine, local.LinkID, appIsolatedNFTGuardRunner{}, readBoot, readNS)
			if err != nil || absent.Status != GuardNotVisible || absent.Handles != (linux.WGIngressLiveHandles{}) {
				t.Fatalf("pre-create read-only journal/host absence was not correctly scoped: %+v err=%v", absent, err)
			}
			if err := stageOriginal(ctx, engine, local.LinkID, appIsolatedNFTGuardRunner{}, runOriginalNFTCreate); err != nil {
				t.Fatalf("Engine-bound real isolated guarded creation failed: %v", err)
			}
			observed, err := inspectPendingOriginal(ctx, engine, local.LinkID, appIsolatedNFTGuardRunner{}, readBoot, readNS)
			if err != nil || observed.Status != GuardMatchingShapeUnowned ||
				observed.KernelBootID != testBootID || observed.NetworkNS == "" ||
				observed.LinkID != local.LinkID || observed.ListenPort != local.LocalWGUDPPort ||
				observed.Handles.Table == 0 || observed.Handles.Chain == 0 || observed.Handles.Rule == 0 {
				t.Fatalf("post-create readonly nft handles not recovered from original journal: %+v err=%v", observed, err)
			}
			// A repeat read can see the same exact bytes and kernel handles,
			// but still does not establish durable original ownership.
			next, err := inspectPendingOriginal(ctx, engine, local.LinkID, appIsolatedNFTGuardRunner{}, readBoot, readNS)
			if err != nil || next != observed {
				t.Fatalf("read-only recovery result unstable: %+v %+v err=%v", observed, next, err)
			}
			// A plausible but unsupported/replaced host-generation or
			// namespace witness must never be promoted into observation.
			changingBootCalls := 0
			changingBoot := func() (string, error) {
				changingBootCalls++
				if changingBootCalls == 1 {
					return testBootID, nil
				}
				return "abcdef01-2345-6789-abcd-ef0123456789", nil
			}
			changingNSCalls := 0
			changingNS := func() (string, error) {
				changingNSCalls++
				if changingNSCalls == 1 {
					return testNetNS, nil
				}
				return "net:[4026532999]", nil
			}
			failures := []struct {
				name string
				boot func() (string, error)
				ns   func() (string, error)
			}{
				{"malformed-boot", func() (string, error) { return "untrusted", nil }, readNS},
				{"changed-boot", changingBoot, readNS},
				{"malformed-netns", readBoot, func() (string, error) { return "net:[0]", nil }},
				{"changed-netns", readBoot, changingNS},
			}
			for _, failure := range failures {
				t.Run(failure.name, func(t *testing.T) {
					value, obsErr := inspectPendingOriginal(ctx, engine, local.LinkID,
						appIsolatedNFTGuardRunner{}, failure.boot, failure.ns)
					if obsErr == nil || value != (OriginalGuardObservation{}) {
						t.Fatalf("ambiguous host lifetime was accepted: %+v %v", value, obsErr)
					}
				})
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
			if err := stageOriginal(ctx, engine, local.LinkID, appIsolatedNFTGuardRunner{}, runOriginalNFTCreate); err == nil {
				t.Fatal("re-run silently adopted the same nft table")
			}
			after, err := store.Load(ctx)
			if err != nil || !reflect.DeepEqual(snapshot, after) || len(after.QUICCrashOperations) != 1 ||
				len(after.Links) != 0 {
				t.Fatalf("guard effect erased immutable journal or committed a fake Link: %v", err)
			}
		})
	}
}
