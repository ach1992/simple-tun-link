//go:build linux && stl_e2e_lab

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	trace := &quicNamespaceLabTrace{Stage: "not_reached", Result: "not_reached", Reason: "none"}
	host := &quicNamespaceLabHost{root: root, peer: peer, guard: guard, trace: trace}
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
	runtime := &runtimeOptions{stateRoot: root, backends: []core.Backend{native, &quicNamespaceLabBackend{Backend: managed, trace: trace}}, probeRunner: runner,
		quicRetirementHost: host, quicHelperObserver: host.diagnose, mtuManager: managedmtu.HostMTUManager{Runner: runner, SetByIndex: linux.SetLinkMTUByIndex},
		configureEngine: func(e *app.Engine) { app.ConfigureQUICNamespaceLab(e, quicNamespaceBootID) }}
	runtime.writeHandoff = func(path string, raw []byte) error {
		trace.step("handoff", nil)
		if err := writeSensitiveHandoff(path, raw); err != nil {
			trace.step("handoff", err)
			return err
		}
		if os.Getenv("STL_QUIC_LAB_FAIL_AFTER_HANDOFF") == "1" {
			return fmt.Errorf("disposable test interruption after protected handoff publication")
		}
		return nil
	}
	if code := runWithRuntimeInput(args, os.Stdin, os.Stdout, os.Stderr, runtime); code != 0 {
		trace.report(root, store, keys, args)
		t.Fatalf("managed CLI exit=%d", code)
	}
}

// Diagnostics exist only in this tagged fixture. They never print a raw
// error, subprocess output, Link/key identity, file contents or a path. The
// wrapper forwards the actual backend and every optional interface unchanged.
type quicNamespaceLabTrace struct {
	Stage       string `json:"stage"`
	Result      string `json:"result"`
	Reason      string `json:"reason"`
	Check       string `json:"check,omitempty"`
	CheckReason string `json:"check_reason,omitempty"`
	link        domain.Link
}

func (d *quicNamespaceLabTrace) step(stage string, err error) {
	d.Stage, d.Result, d.Reason = stage, "ok", quicNamespaceDiagnosticReason(err)
	if err != nil {
		d.Result = "failed"
	}
}
func (d *quicNamespaceLabTrace) check(check string, err error) {
	d.Check, d.CheckReason = check, quicNamespaceDiagnosticReason(err)
}

func quicNamespaceDiagnosticReason(err error) string {
	if err == nil {
		return "none"
	}
	// Match only authored complete literals. Unrecognized text stays redacted;
	// these labels diagnose a failed check and never authorize an action.
	for current, depth := err, 0; current != nil && depth < 8; current, depth = errors.Unwrap(current), depth+1 {
		switch current.Error() {
		case "WSS WG nft readback reported unexpected stderr":
			return "nft_stderr"
		case "WSS WG IPv4 legacy readback reported unexpected stderr", "WSS WG IPv6 legacy readback reported unexpected stderr":
			return "legacy_stderr"
		case "WSS WG iptables version readback reported unexpected stderr", "WSS WG ip6tables version readback reported unexpected stderr":
			return "iptables_version_stderr"
		case "WSS WG IPv4 iptables backend is unknown or not nf_tables", "WSS WG IPv6 iptables backend is unknown or not nf_tables":
			return "iptables_backend"
		case "WSS WG nft contains an active foreign pre-guard hook":
			return "nft_foreign_early_hook"
		case "WSS WG nft metadata is absent, malformed or unsupported", "WSS WG nft ruleset JSON is invalid", "WSS WG nft ruleset must contain exactly one valid metadata object":
			return "nft_ruleset_schema"
		case "WSS WG nft base-chain priority cannot be inspected", "WSS WG nft base-chain priority is unsupported", "WSS WG nft base-chain policy is unsupported":
			return "nft_chain_policy"
		case "managed QUIC guard observation changed":
			return "guard_observation_changed"
		case "nft table inventory unavailable or incomplete":
			return "nft_inventory_unavailable"
		case "ambiguous nft table inventory", "ambiguous nft table inventory entry":
			return "nft_inventory_ambiguous"
		case "incomplete nft table inventory":
			return "nft_inventory_shape"
		case "incomplete nft table inventory metadata or observation", "unsupported nft table inventory metadata":
			return "nft_inventory_metadata"
		case "invalid nft table inventory row", "unsupported nft table inventory object", "duplicate nft table identity", "nft table inventory has trailing content":
			return "nft_inventory_members"
		case "nft guard table census handle unavailable":
			return "nft_inventory_handle"
		case "WG ingress table readback unavailable or incomplete":
			return "nft_table_unavailable"
		case "foreign or malformed WG ingress table":
			return "nft_table_shape"
		case "WG ingress nft table object identity changed during observation":
			return "nft_table_identity"
		case "helper path directory cannot be trusted", "helper path directory is not owner-controlled":
			return "helper_parent_trust"
		case "trusted helper executable cannot be opened":
			return "helper_open"
		case "helper executable owner/mode/inode invalid":
			return "helper_metadata"
		case "pinned helper executable SHA-256 mismatch":
			return "helper_digest"
		case "helper executable fingerprint unavailable", "helper executable changed during inspection":
			return "helper_readback"
		case "test manager unavailable", "test manager refused exact task process":
			return "manager_rpc"
		case "WSS physical source does not match resolved route":
			return "underlay_source"
		case "managed QUIC guard requires canonical journal and retained scope", "managed QUIC guard requires durable operation":
			return "guard_scope"
		case "managed QUIC guard durable journal changed":
			return "guard_journal"
		case "QUIC generation ownership receipt unavailable":
			return "material_receipt_missing"
		case "QUIC generation ownership receipt is invalid", "QUIC generation receipt does not bind immutable journal", "QUIC generation receipt does not match protected inode readback":
			return "material_receipt_rejected"
		}
		for _, prefix := range []string{"WSS WG IPv4 legacy readback failed", "WSS WG IPv6 legacy readback failed"} {
			if strings.HasPrefix(current.Error(), prefix) {
				return "legacy_readback_failed"
			}
		}
		for _, prefix := range []string{"WSS WG IPv4 legacy iptables coexistence is unverified:", "WSS WG IPv6 legacy iptables coexistence is unverified:"} {
			if strings.HasPrefix(current.Error(), prefix) {
				return "legacy_policy_unverified"
			}
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "permission"
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	default:
		return "other_redacted"
	}
}

type quicNamespaceLabBackend struct {
	*wg.Backend
	trace *quicNamespaceLabTrace
}

func (b *quicNamespaceLabBackend) Inspect(ctx context.Context, link domain.Link) (core.Observation, error) {
	b.trace.link = link
	value, err := b.Backend.Inspect(ctx, link)
	b.trace.step("inspect", err)
	return value, err
}
func (b *quicNamespaceLabBackend) Plan(ctx context.Context, request core.Request, observed core.Observation) (core.Plan, error) {
	value, err := b.Backend.Plan(ctx, request, observed)
	b.trace.step("plan", err)
	return value, err
}
func (b *quicNamespaceLabBackend) BeginQUIC(ctx context.Context, link domain.Link, prior *state.QUICGeneration) (context.Context, func() error, error) {
	value, close, err := b.Backend.BeginQUIC(ctx, link, prior)
	b.trace.step("begin", err)
	return value, close, err
}
func (b *quicNamespaceLabBackend) Validate(ctx context.Context, request core.Request, observed core.Observation, plan core.Plan) error {
	err := b.Backend.Validate(ctx, request, observed, plan)
	b.trace.step("validate", err)
	return err
}
func (b *quicNamespaceLabBackend) Apply(ctx context.Context, request core.Request, observed core.Observation, plan core.Plan) (core.Rollback, error) {
	value, err := b.Backend.Apply(ctx, request, observed, plan)
	b.trace.step("apply", err)
	return value, err
}
func (b *quicNamespaceLabBackend) Verify(ctx context.Context, request core.Request) (core.Observation, error) {
	value, err := b.Backend.Verify(ctx, request)
	b.trace.step("verify", err)
	return value, err
}

func quicNamespaceDiagnosticPath(path string) string {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "absent"
	}
	if err != nil {
		return "unreadable"
	}
	if info.Mode().IsRegular() {
		return "regular"
	}
	if info.IsDir() {
		return "directory"
	}
	return "other"
}

func (d *quicNamespaceLabTrace) report(root string, store *state.FileStore, keys *wg.KeyStore, args []string) {
	values := map[string]any{"stage": d.Stage, "result": d.Result, "reason": d.Reason,
		"check": d.Check, "check_reason": d.CheckReason}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, bootErr := quicNamespaceBootID()
	values["boot_readable"] = bootErr == nil
	_, helperErr := quic.InspectPinnedHysteria(quic.DefaultExecutable)
	values["helper_identity"] = quicNamespaceDiagnosticReason(helperErr)
	snapshot, err := store.Load(ctx)
	values["state_load"] = quicNamespaceDiagnosticReason(err)
	if err == nil && d.link.ID.Validate() == nil {
		_, committed := snapshot.Find(d.link.ID)
		op, pending := snapshot.FindQUICCrashOperation(d.link.ID)
		values["committed"], values["journal_present"] = committed, pending
		public, keyErr := keys.LocalPublicIdentity(d.link.ID)
		values["key_matches"] = keyErr == nil && public == d.link.WireGuard.LocalPublicKey
		values["key_readback"] = quicNamespaceDiagnosticReason(keyErr)
		dir := filepath.Join(root, "credentials", "quic", string(d.link.ID))
		values["material_directory"] = quicNamespaceDiagnosticPath(dir)
		values["material_config"] = quicNamespaceDiagnosticPath(filepath.Join(dir, "helper.json"))
		values["material_receipt"] = quicNamespaceDiagnosticPath(filepath.Join(dir, "generation-owner.json"))
		if pending && op.Managed != nil {
			plan, planErr := quic.PlanFromLink(op.Managed.Intent)
			if planErr == nil {
				expected := quic.HelperConfigIdentity{ConfigSHA256: op.HelperConfigSHA256,
					Credentials: quic.CredentialIdentity{CertificateSHA256: op.CertificateSHA256, TrustCASHA256: op.TrustCASHA256, AuthorizationSHA256: op.AuthorizationSHA256, ObfuscationSHA256: op.ObfuscationSHA256},
					Executable:  pinnedexec.Identity{SHA256: op.ExecutableSHA256, Device: op.ExecutableDevice, Inode: op.ExecutableInode}}
				nonce := op.Nonce
				if op.Managed.HadCommittedLink {
					nonce = op.Managed.OriginalGeneration.MaterialNonce
				}
				pin, pinErr := quic.OpenPinnedGeneration(ctx, root, plan, op.WireGuard.ListenPort, quic.DefaultExecutable, nonce, expected)
				values["material_verified"] = quicNamespaceDiagnosticReason(pinErr)
				if pin != nil {
					_ = pin.Close()
				}
			}
		}
	}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--output" && filepath.Dir(args[i+1]) == "/lab" {
			values["handoff"] = quicNamespaceDiagnosticPath(args[i+1])
			break
		}
	}
	encoded, err := json.Marshal(values)
	if err == nil {
		fmt.Fprintln(os.Stderr, "QUIC_MANAGED_FIXTURE_DIAGNOSTIC="+string(encoded))
	}
}

func TestQUICManagedLabDiagnosticRedactsUnknownErrors(t *testing.T) {
	const secret = "fixture-raw-secret-do-not-project"
	if actual := quicNamespaceDiagnosticReason(fmt.Errorf("unexpected private payload %s", secret)); actual != "other_redacted" {
		t.Fatal("unknown cause was not redacted")
	}
	if actual := quicNamespaceDiagnosticReason(fmt.Errorf("private context %s: %w", secret, syscall.EPERM)); actual != "permission" {
		t.Fatal("typed operating-system cause was not safely classified")
	}
	if actual := quicNamespaceDiagnosticReason(fmt.Errorf("nft table inventory unavailable or incomplete")); actual != "nft_inventory_unavailable" {
		t.Fatal("fixed inventory failure was not distinguished")
	}
}

func quicNamespaceReadWitness(name string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile("/lab/"+name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("private namespace witness unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("private namespace witness metadata unavailable")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode() != 0o600 || metadata.Uid != 0 || metadata.Nlink != 1 ||
		info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("private namespace witness metadata differs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("private namespace witness changed")
	}
	return raw, nil
}

func quicNamespaceGitHubRootGate() error {
	for name, expected := range map[string]string{
		"STL_RUN_PRIVILEGED_E2E": "1", "STL_QUIC_MANAGED_ROOT_LAUNCH": "github-hosted-pr",
		"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
		"GITHUB_REPOSITORY": "ach1992/simple-tun-link", "GITHUB_EVENT_NAME": "pull_request",
	} {
		if os.Getenv(name) != expected {
			return fmt.Errorf("root fixture requires the actual opted-in GitHub-hosted repository PR job")
		}
	}
	for _, name := range []string{"GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"} {
		text := os.Getenv(name)
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != text {
			return fmt.Errorf("root fixture run identity unavailable")
		}
	}
	return nil
}

func quicNamespaceLabGate() error {
	guard, err := quicNamespaceReadWitness("namespace-guard", 33)
	if err != nil || len(guard) != 33 || strings.TrimSpace(string(guard)) != os.Getenv("STL_QUIC_MANAGED_LAB") || os.Geteuid() != 0 {
		return fmt.Errorf("disposable namespace witness missing")
	}
	parent, err := quicNamespaceReadWitness("parent-namespaces", 512)
	if err != nil {
		return fmt.Errorf("parent namespace witness missing")
	}
	fields := strings.Fields(string(parent))
	if len(fields) != 4 {
		return fmt.Errorf("invalid parent namespace witness")
	}
	for i, name := range []string{"user", "net", "pid", "mnt"} {
		current, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil || current == fields[i] {
			return fmt.Errorf("refusing shared parent namespace")
		}
	}
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	originRaw, err := quicNamespaceReadWitness("origin-uid", 11)
	if err != nil {
		return err
	}
	originText := strings.TrimSuffix(string(originRaw), "\n")
	origin, err := strconv.ParseUint(originText, 10, 32)
	if err != nil || strconv.FormatUint(origin, 10) != originText {
		return fmt.Errorf("original UID witness invalid")
	}
	modeRaw, err := quicNamespaceReadWitness("namespace-mode", 32)
	if err != nil {
		return err
	}
	mode := strings.TrimSuffix(string(modeRaw), "\n")
	parts := strings.Fields(string(mapping))
	if len(parts) != 3 || parts[0] != "0" || parts[1] != originText || parts[2] != "1" {
		return fmt.Errorf("exact original one-user mapping required")
	}
	if origin == 0 {
		if mode != "github-hosted-root" {
			return fmt.Errorf("root namespace mode differs")
		}
		return quicNamespaceGitHubRootGate()
	}
	if mode != "rootless" {
		return fmt.Errorf("unprivileged namespace mode differs")
	}
	return nil
}

func TestQUICNamespaceRootModeRequiresGitHubProvenance(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("STL_RUN_PRIVILEGED_E2E", "1")
	t.Setenv("STL_QUIC_MANAGED_ROOT_LAUNCH", "github-hosted-pr")
	if err := quicNamespaceGitHubRootGate(); err == nil {
		t.Fatal("root opt-in without actual CI provenance was admitted")
	}
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
	trace      *quicNamespaceLabTrace
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
	present, err := h.guard.GuardPresent(ctx, link)
	h.trace.check("guard_readback", err)
	return present, err
}
func (h *quicNamespaceLabHost) HelperPresent(ctx context.Context, link domain.Link) (bool, error) {
	r, err := h.rpc(ctx, "observe", link, core.QUICOrigin(ctx))
	h.trace.check("helper_readback", err)
	return r.Active, err
}
func (h *quicNamespaceLabHost) HelperLoaded(ctx context.Context, link domain.Link) (bool, error) {
	return h.HelperPresent(ctx, link)
}
func (h *quicNamespaceLabHost) Preflight(ctx context.Context, link domain.Link, present bool) error {
	err := h.guard.Preflight(ctx, link, present)
	h.trace.check("guard_preflight", err)
	return err
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
		expected = quic.HelperConfigIdentity{ConfigSHA256: g.Files.HelperConfig, Credentials: quic.CredentialIdentity{CertificateSHA256: g.Files.Certificate, TrustCASHA256: g.Files.TrustCA, AuthorizationSHA256: g.Files.Authorization, ObfuscationSHA256: g.Files.ObfuscationSHA256}, Executable: pinnedexec.Identity{SHA256: g.ExecutableSHA256, Device: g.ExecutableDevice, Inode: g.ExecutableInode}}
	} else {
		op, ok := core.QUICManagedOperation(ctx)
		if !ok || op.Managed.Intent != link {
			return nil, expected, "", fmt.Errorf("test start lacks canonical durable journal")
		}
		nonce = op.Nonce
		expected = quic.HelperConfigIdentity{ConfigSHA256: op.HelperConfigSHA256, Credentials: quic.CredentialIdentity{CertificateSHA256: op.CertificateSHA256, TrustCASHA256: op.TrustCASHA256, AuthorizationSHA256: op.AuthorizationSHA256, ObfuscationSHA256: op.ObfuscationSHA256}, Executable: pinnedexec.Identity{SHA256: op.ExecutableSHA256, Device: op.ExecutableDevice, Inode: op.ExecutableInode}}
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
		Files: state.QUICFileIdentity{Certificate: f.CertificateSHA256, TLSKey: f.TLSKeySHA256, TrustCA: f.TrustCASHA256, Authorization: f.AuthorizationSHA256, ObfuscationSHA256: f.ObfuscationSHA256, HelperConfig: f.HelperConfigSHA256,
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
