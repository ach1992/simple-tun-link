package quichelper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/quicguard"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"golang.org/x/sys/unix"
)

type managedGuard interface {
	Begin(context.Context, domain.Link, *state.QUICGeneration) (context.Context, error)
	GuardPresent(context.Context, domain.Link) (bool, error)
	Preflight(context.Context, domain.Link, bool) error
	EnsureGuard(context.Context, domain.Link) (core.Rollback, error)
	RemoveGuard(context.Context, domain.Link) (core.Rollback, error)
	Attest(context.Context, domain.Link) (linux.WGIngressLiveHandles, error)
}

type retainedMaterial interface {
	Verify(context.Context) error
	VerifyForLaunch(context.Context) error
	Identity() quic.MaterialIdentity
	Close() error
}

// Host is the concrete per-Link managed QUIC adapter. NewHost fixes the local
// system manager, official executable and protected State root; all mutations
// require the canonical Engine's durable journal and retained transaction.
// It is independent of the source-only StartOriginal capability.
type Host struct {
	root  string
	store state.Store
	guard managedGuard
	ops   managedHostOps
}

// Test seams remain package-private. Backend tests inject the narrow QUICHost
// interface, never a production command, ownership or boot-source override.
type managedHostOps struct {
	host              func() (hostIdentity, error)
	inspect           func(context.Context, unitSpec) (managedUnitObservation, error)
	start             func(context.Context, unitSpec) error
	resetFailed       func(context.Context, unitSpec) error
	action            func(context.Context, string, string) error
	material          func(context.Context, string, quic.Plan, uint16, string, string, quic.HelperConfigIdentity, bool) (retainedMaterial, error)
	executable        func(string, string) (*os.File, pinnedexec.Identity, error)
	inspectExecutable func(string) (pinnedexec.Identity, error)
	events            func(context.Context, string, string, string) ([]HelperEvent, error)
}

func NewHost(root string, store state.Store) (*Host, error) {
	if store == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || !safeArgument(root) {
		return nil, fmt.Errorf("canonical managed QUIC State root required")
	}
	provider, ok := store.(interface{ RootDir() string })
	if !ok || provider.RootDir() != root {
		return nil, fmt.Errorf("managed QUIC Store and protected root differ")
	}
	guard, err := quicguard.NewManaged(root, store)
	if err != nil {
		return nil, err
	}
	return &Host{root: root, store: store, guard: guard, ops: managedHostOps{
		host: currentHostIdentity, inspect: inspectManagedUnit, start: startManagedUnit, resetFailed: resetFailedManagedUnit,
		action: func(ctx context.Context, action, name string) error {
			if action != "start" && action != "stop" {
				return fmt.Errorf("unsupported managed QUIC lifecycle action")
			}
			_, err := managerCommand(ctx, "systemctl", "--system", action, name, "--no-pager")
			return err
		},
		material: func(ctx context.Context, root string, p quic.Plan, port uint16, binary, nonce string, want quic.HelperConfigIdentity, removing bool) (retainedMaterial, error) {
			if removing {
				return quic.OpenPinnedGenerationForRemoval(ctx, root, p, port, binary, nonce, want)
			}
			return quic.OpenPinnedGeneration(ctx, root, p, port, binary, nonce, want)
		},
		executable: pinnedexec.Open, inspectExecutable: quic.InspectPinnedHysteria, events: readHelperEvents,
	}}, nil
}

type managedScopeKey struct{}
type managedScope struct {
	host                  *Host
	link                  domain.Link
	prior                 state.QUICGeneration
	operation             state.QUICCrashOperation
	hasOperation          bool
	origin, materialNonce string
	expected              quic.HelperConfigIdentity
	identity              hostIdentity
	material              retainedMaterial
	executable            *os.File
	processes             []*processPin
	last                  managedUnitObservation
	created, closed       bool
}

// Begin holds one OS thread and read-only descriptors until the Engine has
// classified publication success/failure. Its release function has no host
// lifecycle effects; uncertain/visible State publication never implies stop.
func (h *Host) Begin(ctx context.Context, link domain.Link, prior *state.QUICGeneration) (context.Context, func() error, error) {
	if h == nil || ctx == nil || h.store == nil || h.guard == nil || link.Validate() != nil || link.Backend != domain.BackendWireGuardQUIC {
		return nil, nil, managedError(link, "admission", "invalid_scope", "managed QUIC requires its canonical Link transaction", nil, false)
	}
	if _, nested := ctx.Value(managedScopeKey{}).(*managedScope); nested {
		return nil, nil, fmt.Errorf("nested managed QUIC scope is not admitted")
	}
	plan, err := quic.PlanFromLink(link)
	if err != nil {
		return nil, nil, err
	}
	s := &managedScope{host: h, link: link, origin: core.QUICOrigin(ctx)}
	if prior != nil {
		if err := prior.Validate(link); err != nil {
			return nil, nil, err
		}
		s.prior = *prior
		if s.origin != prior.OriginNonce {
			return nil, nil, fmt.Errorf("managed QUIC original nonce differs")
		}
		s.materialNonce = prior.MaterialNonce
		s.expected = generationExpected(*prior)
	}
	contextGeneration, hasContextGeneration := core.QUICGenerationFromContext(ctx)
	if hasContextGeneration != (prior != nil) || prior != nil && contextGeneration != *prior {
		return nil, nil, fmt.Errorf("managed QUIC context generation differs from canonical scope")
	}
	if op, ok := core.QUICManagedOperation(ctx); ok {
		if op.ValidateManaged() != nil || op.Managed.Intent != link ||
			op.Managed.HadCommittedLink != (prior != nil) || prior != nil && op.Managed.OriginalGeneration != *prior {
			return nil, nil, fmt.Errorf("managed QUIC journal differs from admitted Link")
		}
		s.operation, s.hasOperation = op, true
		if prior == nil {
			s.materialNonce, s.expected = op.Nonce, expectedMaterial(op)
			if s.origin != op.Nonce {
				return nil, nil, fmt.Errorf("managed QUIC fresh origin differs from journal")
			}
		}
		if expectedMaterial(op) != s.expected || op.ExecutablePath != quic.DefaultExecutable {
			return nil, nil, fmt.Errorf("managed QUIC executable/material intent differs")
		}
	} else if prior == nil {
		return nil, nil, fmt.Errorf("managed QUIC requires committed provenance or a fresh durable journal")
	}
	if err := h.verifyStoredAdmission(ctx, s); err != nil {
		return nil, nil, err
	}
	runtime.LockOSThread()
	locked := true
	closeScope := func() error {
		if s.closed {
			return nil
		}
		s.closed = true
		var result error
		for _, p := range s.processes {
			result = errors.Join(result, p.Close())
		}
		s.processes = nil
		if s.material != nil {
			result = errors.Join(result, s.material.Close())
		}
		if s.executable != nil {
			result = errors.Join(result, s.executable.Close())
		}
		if locked {
			runtime.UnlockOSThread()
			locked = false
		}
		return result
	}
	s.identity, err = h.ops.host()
	if err != nil {
		_ = closeScope()
		return nil, nil, managedError(link, "admission", "host_identity", "local system-manager or host identity could not be verified", err, false)
	}
	if s.hasOperation && (s.operation.Managed.KernelBootID != s.identity.BootID || s.operation.Managed.KernelBootSource != hostidentity.VerifiedHostBootSourceV1) {
		_ = closeScope()
		return nil, nil, managedError(link, "admission", "journal_boot_changed", "managed QUIC operation belongs to a different or unverified kernel lifetime; reconcile it without replaying effects", nil, false)
	}
	approved, err := h.ops.inspectExecutable(quic.DefaultExecutable)
	if err != nil || approved != s.expected.Executable {
		_ = closeScope()
		return nil, nil, managedError(link, "material", "executable_drift", "installed official QUIC executable differs from the Link generation", err, false)
	}
	s.executable, approved, err = h.ops.executable(quic.DefaultExecutable, s.expected.Executable.SHA256)
	if err != nil || approved != s.expected.Executable {
		_ = closeScope()
		return nil, nil, managedError(link, "material", "executable_drift", "original QUIC executable could not be retained", err, false)
	}
	removing := !s.hasOperation || s.operation.Managed.Operation == "remove"
	s.material, err = h.ops.material(ctx, h.root, plan, link.WireGuard.ListenPort, quic.DefaultExecutable, s.materialNonce, s.expected, removing)
	if err != nil {
		_ = closeScope()
		return nil, nil, managedError(link, "material", "material_drift", "protected QUIC generation could not be verified", err, false)
	}
	if prior != nil && materialFiles(s.material.Identity()) != prior.Files {
		_ = closeScope()
		return nil, nil, managedError(link, "material", "material_drift", "protected QUIC material identity differs from committed State", nil, false)
	}
	ctx, err = h.guard.Begin(ctx, link, prior)
	if err != nil {
		_ = closeScope()
		return nil, nil, err
	}
	ctx = context.WithValue(ctx, managedScopeKey{}, s)
	if err := h.verifyPins(ctx, s); err != nil {
		_ = closeScope()
		return nil, nil, err
	}
	return ctx, closeScope, nil
}

func generationExpected(g state.QUICGeneration) quic.HelperConfigIdentity {
	return quic.HelperConfigIdentity{ConfigSHA256: g.Files.HelperConfig, Credentials: quic.CredentialIdentity{
		CertificateSHA256: g.Files.Certificate, TrustCASHA256: g.Files.TrustCA, AuthorizationSHA256: g.Files.Authorization},
		Executable: pinnedexec.Identity{SHA256: g.ExecutableSHA256, Device: g.ExecutableDevice, Inode: g.ExecutableInode}}
}
func materialFiles(f quic.MaterialIdentity) state.QUICFileIdentity {
	return state.QUICFileIdentity{Certificate: f.CertificateSHA256, TLSKey: f.TLSKeySHA256, TrustCA: f.TrustCASHA256,
		Authorization: f.AuthorizationSHA256, HelperConfig: f.HelperConfigSHA256, DirectoryDevice: f.DirectoryDevice,
		DirectoryInode: f.DirectoryInode, ReceiptDevice: f.ReceiptDevice, ReceiptInode: f.ReceiptInode}
}

func (h *Host) verifyStoredAdmission(ctx context.Context, s *managedScope) error {
	snapshot, err := h.store.Load(ctx)
	if err != nil {
		return managedError(s.link, "admission", "state_unavailable", "protected QUIC State could not be read", err, false)
	}
	if s.hasOperation {
		actual, ok := snapshot.FindQUICCrashOperation(s.link.ID)
		if !ok || !reflect.DeepEqual(actual, s.operation) {
			return fmt.Errorf("managed QUIC durable journal changed or is absent")
		}
	}
	if s.prior.Version != 0 {
		record, ok := snapshot.Find(s.link.ID)
		if !ok || record.Desired != s.link || record.QUICGeneration != s.prior {
			return fmt.Errorf("managed QUIC committed owner changed")
		}
	} else if _, exists := snapshot.Find(s.link.ID); exists {
		return fmt.Errorf("fresh managed QUIC attempt overlaps a committed Link")
	}
	return nil
}

func (h *Host) scope(ctx context.Context, link domain.Link, effect bool) (*managedScope, error) {
	if ctx == nil {
		return nil, fmt.Errorf("managed QUIC scope missing")
	}
	s, ok := ctx.Value(managedScopeKey{}).(*managedScope)
	if !ok || s.closed || s.host != h || s.link != link || s.origin != core.QUICOrigin(ctx) {
		return nil, fmt.Errorf("managed QUIC retained transaction differs")
	}
	if effect {
		op, ok := core.QUICManagedOperation(ctx)
		if !ok || !s.hasOperation || !reflect.DeepEqual(op, s.operation) {
			return nil, fmt.Errorf("managed QUIC effect requires its exact durable journal")
		}
		if op.Managed.KernelBootID != s.identity.BootID || op.Managed.KernelBootSource != hostidentity.VerifiedHostBootSourceV1 {
			return nil, fmt.Errorf("managed QUIC journal kernel lifetime differs")
		}
		if err := h.verifyStoredAdmission(ctx, s); err != nil {
			return nil, err
		}
		if s.prior.Version != 0 && s.prior.KernelBootID != s.identity.BootID && !core.HasQUICColdBootExtinctionWitness(ctx, link.ID) {
			return nil, fmt.Errorf("managed QUIC recreation requires trusted old-kernel extinction")
		}
	}
	if err := h.verifyPins(ctx, s); err != nil {
		return nil, err
	}
	return s, nil
}

func (h *Host) verifyPins(ctx context.Context, s *managedScope) error {
	if ctx == nil || s.closed {
		return fmt.Errorf("managed QUIC retained transaction unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	host, err := h.ops.host()
	if err != nil || host != s.identity {
		return managedError(s.link, "verify", "host_identity", "QUIC host or manager identity changed during the operation", err, false)
	}
	if s.material == nil || s.executable == nil {
		return fmt.Errorf("managed QUIC original descriptors missing")
	}
	if err := s.material.Verify(ctx); err != nil {
		return managedError(s.link, "verify", "material_drift", "protected QUIC generation changed during the operation", err, false)
	}
	var st unix.Stat_t
	if unix.Fstat(int(s.executable.Fd()), &st) != nil || uint64(st.Dev) != s.expected.Executable.Device || st.Ino != s.expected.Executable.Inode {
		return managedError(s.link, "verify", "executable_drift", "retained QUIC executable identity changed", nil, false)
	}
	return nil
}

func (h *Host) spec(ctx context.Context, link domain.Link) (unitSpec, error) {
	plan, err := quic.PlanFromLink(link)
	if err != nil {
		return unitSpec{}, err
	}
	return buildManagedUnitSpec(plan, core.QUICOrigin(ctx), quic.DefaultExecutable, h.root)
}

func (h *Host) inspect(ctx context.Context, link domain.Link) (managedUnitObservation, error) {
	var empty managedUnitObservation
	spec, err := h.spec(ctx, link)
	if err != nil {
		return empty, err
	}
	obs, err := h.ops.inspect(ctx, spec)
	if err != nil {
		return empty, managedError(link, "helper_inspect", "unit_unverified", "managed QUIC unit or process identity could not be verified", err, false)
	}
	s, scoped := ctx.Value(managedScopeKey{}).(*managedScope)
	if scoped && (s.host != h || s.link != link || s.closed) {
		if obs.Process != nil {
			_ = obs.Process.Close()
		}
		return empty, fmt.Errorf("managed QUIC observation scope differs")
	}
	if obs.Loaded {
		g, committed := core.QUICGenerationFromContext(ctx)
		created := scoped && s.created
		if !created && (!committed || g.Validate(link) != nil || g.OriginNonce != core.QUICOrigin(ctx) || g.KernelBootID != obs.Host.BootID || g.NetworkNS != obs.Host.NetworkNS) {
			if obs.Process != nil {
				_ = obs.Process.Close()
			}
			return empty, managedError(link, "helper_inspect", "foreign_unit", "loaded QUIC helper lacks this managed generation's creation provenance", nil, false)
		}
		if !scoped {
			check := &managedScope{host: h, link: link, prior: g, origin: g.OriginNonce}
			if err := h.verifyStoredAdmission(ctx, check); err != nil {
				if obs.Process != nil {
					_ = obs.Process.Close()
				}
				return empty, err
			}
			exe, err := h.ops.inspectExecutable(quic.DefaultExecutable)
			if err != nil || exe != generationExpected(g).Executable {
				if obs.Process != nil {
					_ = obs.Process.Close()
				}
				return empty, managedError(link, "helper_inspect", "executable_drift", "committed QUIC executable identity differs", err, false)
			}
		}
	}
	if scoped {
		if obs.Host != s.identity {
			if obs.Process != nil {
				_ = obs.Process.Close()
			}
			return empty, fmt.Errorf("managed QUIC host changed between observations")
		}
		if obs.Process != nil {
			p := obs.Process.Observation
			if p.ExecutableDevice != s.expected.Executable.Device || p.ExecutableInode != s.expected.Executable.Inode {
				_ = obs.Process.Close()
				return empty, fmt.Errorf("managed QUIC running executable differs from original pin")
			}
			s.processes = append(s.processes, obs.Process)
		}
		s.last = obs
	} else if obs.Process != nil {
		_ = obs.Process.Close()
		obs.Process = nil
	}
	return obs, nil
}

func (h *Host) GuardPresent(ctx context.Context, link domain.Link) (bool, error) {
	return h.guard.GuardPresent(ctx, link)
}
func (h *Host) HelperPresent(ctx context.Context, link domain.Link) (bool, error) {
	obs, err := h.inspect(ctx, link)
	return obs.Active, err
}
func (h *Host) HelperLoaded(ctx context.Context, link domain.Link) (bool, error) {
	obs, err := h.inspect(ctx, link)
	return obs.Loaded, err
}

func (h *Host) Preflight(ctx context.Context, link domain.Link, guardPresent bool) error {
	if _, err := h.scope(ctx, link, false); err != nil {
		return err
	}
	if _, err := h.inspect(ctx, link); err != nil {
		return err
	}
	return h.guard.Preflight(ctx, link, guardPresent)
}
func (h *Host) EnsureGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	if _, err := h.scope(ctx, link, true); err != nil {
		return nil, err
	}
	return h.guard.EnsureGuard(ctx, link)
}
func (h *Host) RemoveGuard(ctx context.Context, link domain.Link) (core.Rollback, error) {
	if _, err := h.scope(ctx, link, true); err != nil {
		return nil, err
	}
	obs, err := h.inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	if obs.Loaded {
		return nil, managedError(link, "guard_remove", "helper_loaded", "stop the original managed QUIC helper before removing its ingress guard", nil, false)
	}
	return h.guard.RemoveGuard(ctx, link)
}

func (h *Host) StartHelper(ctx context.Context, link domain.Link) (core.Rollback, error) {
	s, err := h.scope(ctx, link, true)
	if err != nil {
		return nil, err
	}
	if err := h.verifyLaunch(ctx, s); err != nil {
		return nil, err
	}
	obs, err := h.inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	if obs.Active {
		return func(context.Context) error { return nil }, nil
	}
	spec, err := h.spec(ctx, link)
	if err != nil {
		return nil, err
	}
	if managedTerminalFailure(obs) {
		if err := h.collectTerminalFailure(ctx, link); err != nil {
			return nil, managedError(link, "helper_start", "terminal_reset_unverified", "terminal QUIC helper could not be independently reset and collected before launch", err, errors.Is(err, core.ErrIndeterminateHostEffect))
		}
		// ResetFailed clears the start limit and can collect the transient
		// definition. Revalidate the retained launch inputs after that effect,
		// then choose from a new observation rather than the cached loaded bit.
		if _, err := h.scope(ctx, link, true); err != nil {
			return nil, h.startFailure(ctx, s, spec, "start_after_reset_unverified", "terminal QUIC helper was collected but launch admission changed; preserve the operation journal", err)
		}
		if err := h.verifyLaunch(ctx, s); err != nil {
			return nil, h.startFailure(ctx, s, spec, "start_after_reset_unverified", "terminal QUIC helper was collected but its original material or guard is no longer launchable; preserve the operation journal", err)
		}
		obs, err = h.inspect(ctx, link)
		if err != nil || obs.Loaded {
			return nil, h.startFailure(ctx, s, spec, "start_after_reset_unverified", "QUIC helper vacancy changed after terminal reset; preserve the operation journal", err)
		}
	}
	if obs.Loaded {
		err = h.ops.action(ctx, "start", spec.Name)
	} else {
		err = h.ops.start(ctx, spec)
	}
	if err != nil {
		return nil, h.startFailure(ctx, s, spec, "start_uncertain", "QUIC helper start was dispatched but its outcome is uncertain; preserve the operation journal", err)
	}
	if !obs.Loaded {
		s.created = true
	}
	if err := h.waitUnit(ctx, link, true); err != nil {
		return nil, h.startFailure(ctx, s, spec, "start_unverified", "QUIC helper did not reach an independently verified running state; preserve the operation journal", err)
	}
	return func(c context.Context) error { _, err := h.StopHelper(c, link); return err }, nil
}

func (h *Host) verifyLaunch(ctx context.Context, s *managedScope) error {
	if err := s.material.VerifyForLaunch(ctx); err != nil {
		return managedError(s.link, "helper_start", "material_invalid", "QUIC launch requires valid original TLS material and exact helper configuration", err, false)
	}
	guard, err := h.guard.GuardPresent(ctx, s.link)
	if err != nil || !guard {
		return managedError(s.link, "helper_start", "guard_unverified", "QUIC helper start requires its independently verified ingress guard", err, false)
	}
	return nil
}

// This is the only managed reset admission. A receipt or a failed name alone
// never authorizes it: refresh the durable owner, retained material, manager,
// exact unit policy and effective dependency graph immediately before dispatch.
// Successful reset is followed by a strict unloaded observation, not merely a
// dead PID. No source-only first-start path calls this method.
func (h *Host) collectTerminalFailure(ctx context.Context, link domain.Link) error {
	if _, err := h.scope(ctx, link, true); err != nil {
		return err
	}
	obs, err := h.inspect(ctx, link)
	if err != nil {
		return err
	}
	if !obs.Loaded {
		return nil
	}
	if !managedTerminalFailure(obs) {
		return fmt.Errorf("managed QUIC terminal state changed before reset")
	}
	spec, err := h.spec(ctx, link)
	if err != nil {
		return err
	}
	if err := h.ops.resetFailed(ctx, spec); err != nil {
		return err
	}
	if _, err := h.scope(ctx, link, true); err != nil {
		return errors.Join(core.ErrIndeterminateHostEffect, err)
	}
	after, err := h.inspect(ctx, link)
	if err != nil {
		return errors.Join(core.ErrIndeterminateHostEffect, err)
	}
	if after.Loaded {
		return errors.Join(core.ErrIndeterminateHostEffect, fmt.Errorf("managed QUIC unit remained loaded after terminal reset"))
	}
	return nil
}

func (h *Host) startFailure(ctx context.Context, s *managedScope, spec unitSpec, reason, detail string, cause error) error {
	base := managedError(s.link, "helper_start", reason, detail, errors.Join(core.ErrIndeterminateHostEffect, cause), true)
	// Diagnosis of a dispatched failure grants no ownership or stop/retry
	// authority. Keep the original private cause even when optional safe
	// attributed helper evidence can give the operator a more useful reason.
	probe, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	obs, err := h.ops.inspect(probe, spec)
	if obs.Process != nil {
		_ = obs.Process.Close()
	}
	if err != nil || !obs.Loaded || obs.Host != s.identity || h.ops.events == nil {
		return base
	}
	invocation := obs.Values["InvocationID"]
	if !canonicalHex(invocation, 32) {
		return base
	}
	events, err := h.ops.events(probe, spec.Name, invocation, obs.Host.BootID)
	if err != nil {
		return base
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].ReasonCode == "" {
			continue
		}
		var typed *stlerr.Error
		if !errors.As(base, &typed) {
			return base
		}
		typed.ReasonCode, typed.NextStep = events[i].ReasonCode, events[i].NextStep
		typed.Detail += "; helper event: " + events[i].Event + " (" + events[i].ReasonCode + ")"
		return typed
	}
	return base
}

func (h *Host) StopHelper(ctx context.Context, link domain.Link) (core.Rollback, error) {
	_, err := h.scope(ctx, link, true)
	if err != nil {
		return nil, err
	}
	obs, err := h.inspect(ctx, link)
	if err != nil {
		return nil, err
	}
	if !obs.Loaded {
		return func(context.Context) error { return nil }, nil
	}
	if managedTerminalFailure(obs) {
		if err := h.collectTerminalFailure(ctx, link); err != nil {
			return nil, managedError(link, "helper_stop", "terminal_reset_unverified", "terminal QUIC helper absence could not be verified after its scoped reset; retain its guard and journal", err, errors.Is(err, core.ErrIndeterminateHostEffect))
		}
		return func(context.Context) error { return nil }, nil
	}
	spec, err := h.spec(ctx, link)
	if err != nil {
		return nil, err
	}
	if err := h.ops.action(ctx, "stop", spec.Name); err != nil {
		return nil, managedError(link, "helper_stop", "stop_uncertain", "QUIC helper stop outcome is uncertain; retain its guard and journal", errors.Join(core.ErrIndeterminateHostEffect, err), true)
	}
	if err := h.waitUnit(ctx, link, false); err != nil {
		return nil, managedError(link, "helper_stop", "stop_unverified", "original QUIC helper absence could not be verified after stop", errors.Join(core.ErrIndeterminateHostEffect, err), true)
	}
	if !obs.Active {
		return func(context.Context) error { return nil }, nil
	}
	return func(c context.Context) error { _, err := h.StartHelper(c, link); return err }, nil
}

func (h *Host) waitUnit(ctx context.Context, link domain.Link, active bool) error {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		obs, err := h.inspect(bounded, link)
		if err != nil {
			return err
		}
		if active && obs.Active || !active && !obs.Loaded {
			return nil
		}
		if !active && managedTerminalFailure(obs) {
			return h.collectTerminalFailure(bounded, link)
		}
		select {
		case <-bounded.Done():
			return bounded.Err()
		case <-ticker.C:
		}
	}
}

func (h *Host) Attest(ctx context.Context, link domain.Link) (state.QUICGeneration, error) {
	s, err := h.scope(ctx, link, false)
	if err != nil {
		return state.QUICGeneration{}, err
	}
	if err := h.verifyStoredAdmission(ctx, s); err != nil {
		return state.QUICGeneration{}, err
	}
	obs, err := h.inspect(ctx, link)
	if err != nil || !obs.Active {
		return state.QUICGeneration{}, managedError(link, "verify", "helper_inactive", "managed QUIC helper is not independently verified as running", err, false)
	}
	handles, err := h.guard.Attest(ctx, link)
	if err != nil {
		return state.QUICGeneration{}, err
	}
	if err := h.verifyPins(ctx, s); err != nil {
		return state.QUICGeneration{}, err
	}
	if obs.Process == nil || obs.Process.alive() != nil {
		return state.QUICGeneration{}, fmt.Errorf("managed QUIC process exited before State attestation")
	}
	return state.QUICGeneration{Version: 1, OriginNonce: s.origin, MaterialNonce: s.materialNonce,
		KernelBootID: s.identity.BootID, KernelBootSource: hostidentity.VerifiedHostBootSourceV1, NetworkNS: s.identity.NetworkNS,
		GuardTableHandle: handles.Table, GuardChainHandle: handles.Chain, GuardRuleHandle: handles.Rule,
		Files: materialFiles(s.material.Identity()), ExecutablePath: quic.DefaultExecutable,
		ExecutableSHA256: s.expected.Executable.SHA256, ExecutableDevice: s.expected.Executable.Device, ExecutableInode: s.expected.Executable.Inode}, nil
}

func managedError(link domain.Link, stage, reason, detail string, cause error, changed bool) error {
	var manager *managerFailure
	if errors.As(cause, &manager) {
		reason = "manager_" + manager.Kind
		switch manager.Kind {
		case "timeout":
			detail += "; the bounded system-manager request timed out"
		case "canceled":
			detail += "; the system-manager request was canceled"
		case "output_limit":
			detail += "; system-manager output exceeded its observation bound"
		case "command_exit":
			detail += fmt.Sprintf("; system-manager command exited with status %d", manager.ExitCode)
		case "command_unavailable":
			detail += "; the trusted local system-manager tool is unavailable"
		}
	}
	code := stlerr.CodeInspect
	mutation := "not_attempted"
	if changed {
		code, mutation = stlerr.CodeApply, "outcome_uncertain"
	}
	err := stlerr.Wrap(code, "quic_"+stage, string(link.ID), string(domain.BackendWireGuardQUIC), detail, cause)
	err.ReasonCode = "quic_" + reason
	err.NextStep = "inspect this Link's QUIC diagnostics and the retained operation journal before retrying"
	switch reason {
	case "executable_drift":
		err.NextStep = "verify the installed pinned Hysteria release and original executable identity; preserve the Link generation"
	case "material_drift", "material_invalid":
		err.NextStep = "inspect original protected material and certificate lifetime; do not overwrite or re-pair the active generation"
	case "state_unavailable":
		err.NextStep = "restore access to the original protected State location before any Link mutation"
	case "host_identity":
		err.NextStep = "run from the original host namespaces and verify the local PID1 system manager"
	case "journal_boot_changed":
		err.NextStep = "use the explicit managed QUIC kernel-extinction reconciliation after verifying the new host boot"
	case "foreign_unit", "unit_unverified":
		err.NextStep = "inspect this unit's ownership, dependencies and execution properties; preserve any foreign object"
	case "journal_unavailable":
		err.NextStep = "inspect local journal availability and permissions; use the separately reported process and exit state"
	case "unprovisioned":
		err.NextStep = "complete canonical pairing or inspect the pending managed operation before retrying"
	case "helper_not_absent", "guard_not_absent", "wireguard_not_absent", "udp_not_absent":
		err.NextStep = "complete or reconcile the exact managed Remove before retiring private material"
	}
	err.Evidence = &stlerr.OperationEvidence{Stage: stage, HostMutation: mutation, DesiredState: "not_committed", Rollback: "not_attempted"}
	return err
}
