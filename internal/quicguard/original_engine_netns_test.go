package quicguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
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

type siblingNetworkNSObservation struct {
	Observation    OriginalGuardObservation
	ProcessNS      string
	ThreadNS       string
	WorkerTID      int
	ThreadReleased bool
	Err            error
}

// This runs ONLY inside the explicitly disposable user/net/mount test harness.
// A Go process can have different network namespaces on distinct OS threads.
// Its /proc/self/ns/net label stays at the process leader, whereas nft
// subprocesses inherit the network namespace of the locked calling thread.
func inspectOriginalInSiblingThreadNS(ctx context.Context, engine *app.Engine, id domain.LinkID) siblingNetworkNSObservation {
	return inspectOriginalInSiblingThreadNSWithOps(ctx, engine, id, unix.Unshare, unix.Setns)
}

// Test-only fault injection. A failed restoration must NEVER release a thread
// carrying a changed network namespace to unrelated Go work.
func inspectOriginalInSiblingThreadNSWithOps(ctx context.Context, engine *app.Engine, id domain.LinkID,
	enter func(int) error, restore func(int, int) error) siblingNetworkNSObservation {
	if enter == nil || restore == nil {
		return siblingNetworkNSObservation{Err: fmt.Errorf("disposable namespace operations required")}
	}
	// Reserve TWO different locked threads before choosing the worker. One
	// cannot both be the process leader, so the discriminating /proc/self
	// versus /proc/thread-self test never depends on scheduler luck.
	type lockedWorker struct {
		tid     int
		proceed chan bool
	}
	ready := make(chan lockedWorker, 2)
	result := make(chan siblingNetworkNSObservation, 1)
	for i := 0; i < 2; i++ {
		go func() {
			runtime.LockOSThread()
			worker := lockedWorker{tid: unix.Gettid(), proceed: make(chan bool, 1)}
			ready <- worker
			if !<-worker.proceed {
				runtime.UnlockOSThread() // no namespace change on the unused thread
				return
			}
			observed, safeToUnlock := inspectOriginalOnLockedThread(ctx, engine, id, enter, restore)
			observed.WorkerTID = worker.tid
			observed.ThreadReleased = safeToUnlock
			if safeToUnlock {
				runtime.UnlockOSThread()
			}
			// If restore failed, exit the goroutine STILL locked: Go will
			// terminate its OS thread rather than reuse the contaminated ns.
			result <- observed
		}()
	}
	first, second := <-ready, <-ready
	if first.tid == os.Getpid() {
		first, second = second, first
	}
	second.proceed <- false
	first.proceed <- true
	return <-result
}

// safeToUnlock is true only when no namespace change happened, or when the
// original namespace was restored and independently checked. The caller
// MUST terminate this goroutine without UnlockOSThread when it is false.
func inspectOriginalOnLockedThread(ctx context.Context, engine *app.Engine, id domain.LinkID,
	enter func(int) error, restore func(int, int) error) (observed siblingNetworkNSObservation, safeToUnlock bool) {
	safeToUnlock = true
	if unix.Gettid() == os.Getpid() {
		observed.Err = fmt.Errorf("sibling observer unexpectedly used the process leader")
		return
	}
	originalFD, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		observed.Err = fmt.Errorf("open original thread namespace: %w", err)
		return
	}
	defer originalFD.Close()
	originalNS, err := currentNetworkNamespace()
	if err != nil {
		observed.Err = fmt.Errorf("read original test-thread namespace: %w", err)
		return
	}
	observed.ProcessNS, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		observed.Err = fmt.Errorf("read process namespace: %w", err)
		return
	}
	if err := enter(unix.CLONE_NEWNET); err != nil {
		// Failed Unshare did not change namespace; releasing is safe.
		observed.Err = fmt.Errorf("enter disposable sibling network namespace: %w", err)
		return
	}
	safeToUnlock = false // namespace changed: only verified Setns may release
	defer func() {
		if err := restore(int(originalFD.Fd()), unix.CLONE_NEWNET); err != nil {
			observed.Err = fmt.Errorf("restore original test-thread namespace: %w", err)
			return
		}
		after, err := currentNetworkNamespace()
		if err != nil || after != originalNS {
			observed.Err = fmt.Errorf("original test-thread namespace restoration unverified")
			return
		}
		safeToUnlock = true
	}()
	observed.ThreadNS, err = currentNetworkNamespace()
	if err != nil {
		observed.Err = err
		return
	}
	if observed.ThreadNS == originalNS {
		observed.Err = fmt.Errorf("disposable sibling namespace not isolated")
		return
	}
	observed.Observation, observed.Err = inspectPendingOriginal(ctx, engine, id,
		appIsolatedNFTGuardRunner{},
		func() (string, error) { return testBootID, nil }, currentNetworkNamespace)
	return
}

// A locked goroutine that exits without UnlockOSThread must retire its
// contaminated worker thread, not leave it available for unrelated work.
func assertRetiredTestThread(t *testing.T, tid int) {
	t.Helper()
	if tid <= 0 {
		t.Fatal("invalid disposable worker TID")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := os.Stat(fmt.Sprintf("/proc/self/task/%d", tid))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Fatalf("disposable worker thread inventory unreadable: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("failed-restore disposable thread %d was not retired", tid)
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
			observed, err := inspectPendingOriginal(ctx, engine, local.LinkID, appIsolatedNFTGuardRunner{}, readBoot, readNS)
			if err != nil || observed.Status != GuardMatchingShapeUnowned ||
				observed.KernelBootID != testBootID || observed.NetworkNS == "" ||
				observed.LinkID != local.LinkID || observed.ListenPort != local.LocalWGUDPPort ||
				observed.Handles.Table == 0 || observed.Handles.Chain == 0 || observed.Handles.Rule == 0 {
				t.Fatalf("post-create readonly nft handles not recovered from original journal: %+v err=%v", observed, err)
			}
			// The SAME process now observes a separate network namespace on
			// another locked OS thread. The old /proc/self label incorrectly
			// described the first namespace, even when nft read the second.
			sibling := inspectOriginalInSiblingThreadNS(ctx, engine, local.LinkID)
			if sibling.Err != nil || sibling.ProcessNS != observed.NetworkNS ||
				sibling.ThreadNS == sibling.ProcessNS ||
				sibling.Observation.NetworkNS != sibling.ThreadNS ||
				sibling.Observation.Status != GuardNotVisible ||
				sibling.Observation.Handles != (linux.WGIngressLiveHandles{}) || !sibling.ThreadReleased {
				t.Fatalf("thread-scoped nft observation mislabeled sibling namespace: %+v", sibling)
			}
			// Early Unshare failure MUST unlock an unmodified worker.
			early := inspectOriginalInSiblingThreadNSWithOps(ctx, engine, local.LinkID,
				func(int) error { return errors.New("injected unshare failure") }, unix.Setns)
			if early.Err == nil || !strings.Contains(early.Err.Error(), "enter disposable sibling network namespace") ||
				!early.ThreadReleased || early.ThreadNS != "" {
				t.Fatalf("failed Unshare incorrectly quarantined or changed the thread: %+v", early)
			}

			// Deterministically fail restoration AFTER a real Unshare.
			// This test is isolated in a user/net/mount namespace; its
			// contaminated OS thread must die, never return to the Go pool.
			failedRestore := inspectOriginalInSiblingThreadNSWithOps(ctx, engine, local.LinkID,
				unix.Unshare, func(int, int) error { return errors.New("injected setns failure") })
			if failedRestore.Err == nil ||
				!strings.Contains(failedRestore.Err.Error(), "restore original test-thread namespace") ||
				failedRestore.ThreadNS == failedRestore.ProcessNS || failedRestore.ThreadNS == "" ||
				failedRestore.ThreadReleased {
				t.Fatalf("failed Setns released a modified OS thread: %+v", failedRestore)
			}
			assertRetiredTestThread(t, failedRestore.WorkerTID)

			// Even a restoration API that incorrectly reports success is
			// insufficient: exact thread-local namespace reinspection must
			// fail closed and retire the un-restored worker.
			falseSuccess := inspectOriginalInSiblingThreadNSWithOps(ctx, engine, local.LinkID,
				unix.Unshare, func(int, int) error { return nil })
			if falseSuccess.Err == nil ||
				!strings.Contains(falseSuccess.Err.Error(), "restoration unverified") ||
				falseSuccess.ThreadReleased {
				t.Fatalf("unverified restoration released a changed namespace thread: %+v", falseSuccess)
			}
			assertRetiredTestThread(t, falseSuccess.WorkerTID)
			// The original namespace and guard were left intact by all
			// sibling tests; none grants owner/recovery authority.
			recheck, recheckErr := inspectPendingOriginal(ctx, engine, local.LinkID,
				appIsolatedNFTGuardRunner{}, readBoot, readNS)
			if recheckErr != nil || recheck != observed {
				t.Fatalf("original namespace was altered by sibling read: %+v %v", recheck, recheckErr)
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
