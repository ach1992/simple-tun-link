//go:build linux && stl_e2e_lab

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	core "github.com/ach1992/simple-tun-link/internal/backend"
	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/managedmtu"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/quicguard"
	"github.com/ach1992/simple-tun-link/internal/quichelper"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// This tagged executable runs real public CLI/Engine transactions, protected
// material, kernel WireGuard and nftables. ONLY manager/process supervision and
// the nested-namespace boot source are test adapters. It is never a release
// binary and cannot prove systemd policy, a host reboot or physical networking.
func TestQUICManagedLabCLI(t *testing.T) {
	if os.Getenv("STL_QUIC_LAB_ARGS") == "" {
		t.Skip("explicit disposable namespace lab only")
	}
	if err := quicNamespaceLabGate(); err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("STL_QUIC_LAB_ARGS")), &args); err != nil {
		t.Fatal("invalid public command")
	}
	peer := os.Getenv("STL_QUIC_LAB_PEER")
	if peer != "alpha" && peer != "beta" {
		t.Fatal("unknown disposable peer")
	}
	root := "/lab/" + peer + "-state"
	store := state.NewFileStore(root)
	guard, err := quicguard.NewManaged(root, store)
	if err != nil {
		t.Fatal(err)
	}
	quicguard.ConfigureQUICNamespaceLab(guard, quicNamespaceBootID)
	linux.ConfigureQUICNamespaceLab(quicNamespaceBootID)
	host := &quicNamespaceLabHost{root: root, peer: peer, guard: guard}
	runner := linux.ExecRunner{}
	keys, err := wg.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	opts := wg.Options{Runner: runner, Routes: linux.RouteResolver{Runner: runner},
		Firewall:   linux.IPTablesFirewall{Runner: runner, Locks: state.NewLockManager(root)},
		Collisions: linux.CollisionInspector{Snapshotter: linux.HostSnapshotter{Runner: runner}}, Keys: keys, QUICHost: host}
	managed, err := wg.NewQUIC(opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.QUICHost = nil
	native, err := wg.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &runtimeOptions{stateRoot: root, backends: []core.Backend{native, managed}, probeRunner: runner,
		quicRetirementHost: host, quicHelperObserver: host.diagnose, mtuManager: managedmtu.HostMTUManager{Runner: runner, SetByIndex: linux.SetLinkMTUByIndex},
		configureEngine: func(e *app.Engine) { app.ConfigureQUICNamespaceLab(e, quicNamespaceBootID) }}
	if os.Getenv("STL_QUIC_LAB_FAIL_AFTER_HANDOFF") == "1" {
		runtime.writeHandoff = func(path string, raw []byte) error {
			if err := writeSensitiveHandoff(path, raw); err != nil {
				return err
			}
			return fmt.Errorf("disposable test interruption after protected handoff publication")
		}
	}
	if code := runWithRuntimeInput(args, os.Stdin, os.Stdout, os.Stderr, runtime); code != 0 {
		t.Fatalf("managed CLI exit=%d", code)
	}
}

func quicNamespaceLabGate() error {
	guard, err := os.ReadFile("/lab/namespace-guard")
	if err != nil || len(guard) != 33 || strings.TrimSpace(string(guard)) != os.Getenv("STL_QUIC_MANAGED_LAB") || os.Geteuid() != 0 {
		return fmt.Errorf("disposable namespace witness missing")
	}
	parent, err := os.ReadFile("/lab/parent-namespaces")
	if err != nil {
		return fmt.Errorf("parent namespace witness missing")
	}
	fields := strings.Fields(string(parent))
	if len(fields) != 3 {
		return fmt.Errorf("invalid parent namespace witness")
	}
	for i, name := range []string{"user", "net", "pid"} {
		current, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil || current == fields[i] {
			return fmt.Errorf("refusing shared parent namespace")
		}
	}
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	var inner, outer, count int
	if n, _ := fmt.Sscan(string(mapping), &inner, &outer, &count); n != 3 || inner != 0 || outer <= 0 || count != 1 {
		return fmt.Errorf("rootless one-user mapping required")
	}
	return nil
}

// The value is the actual kernel boot UUID. The source authentication is
// intentionally shimmed because a disposable PID namespace is not host PID 1.
func quicNamespaceBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	boot := strings.TrimSpace(string(raw))
	if !hostidentity.ValidBootID(boot) {
		return "", fmt.Errorf("invalid actual kernel boot UUID")
	}
	return boot, nil
}

type quicNamespaceLabHost struct {
	root, peer string
	guard      *quicguard.Managed
}
type quicNamespaceScopeKey struct{}
type quicNamespaceScope struct {
	link  domain.Link
	prior *state.QUICGeneration
}
type quicNamespaceReply struct {
	OK        bool   `json:"ok"`
	Active    bool   `json:"active"`
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
}

func (h *quicNamespaceLabHost) rpc(ctx context.Context, action string, link domain.Link, nonce string) (quicNamespaceReply, error) {
	if err := quicNamespaceLabGate(); err != nil {
		return quicNamespaceReply{}, err
	}
	if link.ID.Validate() != nil || len(nonce) != 32 {
		return quicNamespaceReply{}, fmt.Errorf("invalid test supervisor identity")
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", "/lab/"+h.peer+"-manager.sock")
	if err != nil {
		return quicNamespaceReply{}, fmt.Errorf("test manager unavailable")
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	request := struct{ Action, LinkID, Nonce, Role string }{action, string(link.ID), nonce, link.QUIC.Role}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return quicNamespaceReply{}, err
	}
	var response quicNamespaceReply
	decoder := json.NewDecoder(io.LimitReader(conn, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || !response.OK {
		return quicNamespaceReply{}, fmt.Errorf("test manager refused exact task process")
	}
	return response, nil
}
func (h *quicNamespaceLabHost) Begin(ctx context.Context, link domain.Link, prior *state.QUICGeneration) (context.Context, func() error, error) {
	if err := quicNamespaceLabGate(); err != nil {
		return nil, nil, err
	}
	runtime.LockOSThread()
	ctx, err := h.guard.Begin(ctx, link, prior)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, nil, err
	}
	scope := &quicNamespaceScope{link: link}
	if prior != nil {
		copy := *prior
		scope.prior = &copy
	}
	ctx = context.WithValue(ctx, quicNamespaceScopeKey{}, scope)
	closed := false
	return ctx, func() error {
		if !closed {
			closed = true
			runtime.UnlockOSThread()
		}
		return nil
	}, nil
}
func (h *quicNamespaceLabHost) GuardPresent(ctx context.Context, link domain.Link) (bool, error) {
	return h.guard.GuardPresent(ctx, link)
}
func (h *quicNamespaceLabHost) HelperPresent(ctx context.Context, link domain.Link) (bool, error) {
	r, err := h.rpc(ctx, "observe", link, core.QUICOrigin(ctx))
	return r.Active, err
}
func (h *quicNamespaceLabHost) HelperLoaded(ctx context.Context, link domain.Link) (bool, error) {
	return h.HelperPresent(ctx, link)
}
func (h *quicNamespaceLabHost) Preflight(ctx context.Context, link domain.Link, present bool) error {
	return h.guard.Preflight(ctx, link, present)
}
func (h *quicNamespaceLabHost) EnsureGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	return h.guard.EnsureGuard(ctx, link)
}
func (h *quicNamespaceLabHost) RemoveGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	return h.guard.RemoveGuard(ctx, link)
}

func (h *quicNamespaceLabHost) material(ctx context.Context, link domain.Link) (*quic.GenerationPin, quic.HelperConfigIdentity, string, error) {
	scope, ok := ctx.Value(quicNamespaceScopeKey{}).(*quicNamespaceScope)
	if !ok || scope.link != link {
		return nil, quic.HelperConfigIdentity{}, "", fmt.Errorf("test host scope unavailable")
	}
	var expected quic.HelperConfigIdentity
	var nonce string
	if scope.prior != nil {
		g := *scope.prior
		nonce = g.MaterialNonce
		expected = quic.HelperConfigIdentity{ConfigSHA256: g.Files.HelperConfig, Credentials: quic.CredentialIdentity{CertificateSHA256: g.Files.Certificate, TrustCASHA256: g.Files.TrustCA, AuthorizationSHA256: g.Files.Authorization}, Executable: pinnedexec.Identity{SHA256: g.ExecutableSHA256, Device: g.ExecutableDevice, Inode: g.ExecutableInode}}
	} else {
		op, ok := core.QUICManagedOperation(ctx)
		if !ok || op.Managed.Intent != link {
			return nil, expected, "", fmt.Errorf("test start lacks canonical durable journal")
		}
		nonce = op.Nonce
		expected = quic.HelperConfigIdentity{ConfigSHA256: op.HelperConfigSHA256, Credentials: quic.CredentialIdentity{CertificateSHA256: op.CertificateSHA256, TrustCASHA256: op.TrustCASHA256, AuthorizationSHA256: op.AuthorizationSHA256}, Executable: pinnedexec.Identity{SHA256: op.ExecutableSHA256, Device: op.ExecutableDevice, Inode: op.ExecutableInode}}
	}
	plan, err := quicPlanForLink(link)
	if err != nil {
		return nil, expected, nonce, err
	}
	pin, err := quic.OpenPinnedGeneration(ctx, h.root, plan, link.WireGuard.ListenPort, quic.DefaultExecutable, nonce, expected)
	return pin, expected, nonce, err
}
func (h *quicNamespaceLabHost) StartHelper(ctx context.Context, link domain.Link) (core.Rollback, error) {
	pin, _, _, err := h.material(ctx, link)
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	if _, ok := core.QUICManagedOperation(ctx); !ok {
		return nil, fmt.Errorf("test start requires canonical journal")
	}
	if err := pin.Verify(ctx); err != nil {
		return nil, err
	}
	reply, err := h.rpc(ctx, "start", link, core.QUICOrigin(ctx))
	if err != nil || !reply.Active {
		return nil, fmt.Errorf("real official helper start unverified")
	}
	if err := pin.Verify(ctx); err != nil {
		return nil, err
	}
	return func(c context.Context) error { _, err := h.rpc(c, "stop", link, core.QUICOrigin(ctx)); return err }, nil
}
func (h *quicNamespaceLabHost) StopHelper(ctx context.Context, link domain.Link) (core.Rollback, error) {
	if _, ok := core.QUICManagedOperation(ctx); !ok {
		return nil, fmt.Errorf("test stop requires canonical journal")
	}
	if _, err := h.rpc(ctx, "stop", link, core.QUICOrigin(ctx)); err != nil {
		return nil, err
	}
	return func(c context.Context) error { _, err := h.StartHelper(c, link); return err }, nil
}
func (h *quicNamespaceLabHost) Attest(ctx context.Context, link domain.Link) (state.QUICGeneration, error) {
	pin, expected, nonce, err := h.material(ctx, link)
	if err != nil {
		return state.QUICGeneration{}, err
	}
	defer pin.Close()
	r, err := h.rpc(ctx, "observe", link, core.QUICOrigin(ctx))
	if err != nil || !r.Active || r.PID <= 1 || r.StartTime == 0 {
		return state.QUICGeneration{}, fmt.Errorf("original test process unverified")
	}
	handles, err := h.guard.Attest(ctx, link)
	if err != nil {
		return state.QUICGeneration{}, err
	}
	boot, err := quicNamespaceBootID()
	if err != nil {
		return state.QUICGeneration{}, err
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return state.QUICGeneration{}, err
	}
	f := pin.Identity()
	g := state.QUICGeneration{Version: 1, OriginNonce: core.QUICOrigin(ctx), MaterialNonce: nonce,
		KernelBootID: boot, KernelBootSource: hostidentity.VerifiedHostBootSourceV1, NetworkNS: ns,
		GuardTableHandle: handles.Table, GuardChainHandle: handles.Chain, GuardRuleHandle: handles.Rule,
		ExecutablePath: quic.DefaultExecutable, ExecutableSHA256: expected.Executable.SHA256, ExecutableDevice: expected.Executable.Device, ExecutableInode: expected.Executable.Inode,
		Files: state.QUICFileIdentity{Certificate: f.CertificateSHA256, TLSKey: f.TLSKeySHA256, TrustCA: f.TrustCASHA256, Authorization: f.AuthorizationSHA256, HelperConfig: f.HelperConfigSHA256,
			DirectoryDevice: f.DirectoryDevice, DirectoryInode: f.DirectoryInode, ReceiptDevice: f.ReceiptDevice, ReceiptInode: f.ReceiptInode}}
	return g, pin.Verify(ctx)
}
func (h *quicNamespaceLabHost) VerifyRetirementHostAbsent(ctx context.Context, link domain.Link, g state.QUICGeneration) error {
	r, err := h.rpc(ctx, "observe", link, g.OriginNonce)
	if err != nil || r.Active {
		return fmt.Errorf("test helper remains live or unverified")
	}
	plan, err := linux.NewQUICWGIngressPlan(link.ID, link.WireGuard.ListenPort, g.OriginNonce)
	if err != nil {
		return err
	}
	present, err := linux.InspectWGIngressGuard(ctx, linux.ExecRunner{}, plan)
	if err != nil || present {
		return fmt.Errorf("real guard remains live or unverified")
	}
	vacant, err := linux.WSSGlobalWGKernelVacant(ctx, linux.ExecRunner{}, "wg", link.WireGuard.LocalPublicKey, link.WireGuard.ListenPort)
	if err != nil || !vacant {
		return fmt.Errorf("real WG resources remain")
	}
	ports := []uint16{link.WireGuard.ListenPort, link.QUIC.ForwardUDPPort}
	if link.QUIC.Role == "listen" {
		ports = append(ports, link.QUIC.UDPPort)
	}
	for _, port := range ports {
		if port != 0 {
			vacant, err := linux.QUICWGAllStateUDPPortVacant(ctx, linux.ExecRunner{}, port)
			if err != nil || !vacant {
				return fmt.Errorf("real UDP socket remains")
			}
		}
	}
	return nil
}

// Ensure the task entrypoint rejects parent-host execution before it can
// reach any runtime operation. This is a pure negative test in ordinary CI.
func TestQUICNamespaceLabRequiresIndependentNamespaces(t *testing.T) {
	if os.Getenv("STL_QUIC_MANAGED_LAB") != "" {
		t.Skip("inside dedicated fixture")
	}
	if err := quicNamespaceLabGate(); err == nil {
		t.Fatal("untagged invocation admitted")
	}
}

// This is explicitly process-supervisor evidence, never attributed systemd
// journal authentication. WireGuard/application proof is measured separately.
func (h *quicNamespaceLabHost) diagnose(ctx context.Context, link domain.Link) (quichelper.HelperDiagnostics, error) {
	result := quichelper.HelperDiagnostics{State: "unknown", Authentication: "not_observed", Handshake: "not_observed", JournalState: "namespace_supervisor_no_systemd_journal"}
	snapshot, err := state.NewFileStore(h.root).Load(ctx)
	if err != nil {
		return result, err
	}
	record, ok := snapshot.Find(link.ID)
	if !ok || record.Desired != link {
		return result, fmt.Errorf("test committed owner changed")
	}
	ctx, err = core.WithQUICOrigin(ctx, record.QUICGeneration.OriginNonce)
	if err != nil {
		return result, err
	}
	ctx = core.WithQUICGeneration(ctx, record.QUICGeneration)
	ctx, release, err := h.Begin(ctx, link, &record.QUICGeneration)
	if err != nil {
		return result, err
	}
	defer release()
	pin, _, _, err := h.material(ctx, link)
	if err != nil {
		return result, err
	}
	defer pin.Close()
	result.MaterialState = "verified"
	result.GuardPresent, err = h.guard.GuardPresent(ctx, link)
	if err != nil {
		return result, err
	}
	result.GuardObserved = true
	r, err := h.rpc(ctx, "observe", link, core.QUICOrigin(ctx))
	if err != nil {
		return result, err
	}
	result.HelperObserved = true
	result.HelperPresent = r.Active
	result.HelperLoaded = r.Active
	result.PID, result.ProcessStartTime = r.PID, r.StartTime
	result.State = "absent"
	if r.Active {
		result.State = "active"
	}
	return result, pin.Verify(ctx)
}
