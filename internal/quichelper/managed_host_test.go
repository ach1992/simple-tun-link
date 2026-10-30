package quichelper

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/state"
	"golang.org/x/sys/unix"
)

type managedMemoryStore struct {
	root     string
	snapshot state.Snapshot
}

func (s *managedMemoryStore) RootDir() string                              { return s.root }
func (s *managedMemoryStore) Load(context.Context) (state.Snapshot, error) { return s.snapshot, nil }
func (s *managedMemoryStore) Update(_ context.Context, fn func(*state.Snapshot) error) error {
	return fn(&s.snapshot)
}

type fakeManagedMaterial struct {
	identity             quic.MaterialIdentity
	verifyErr, launchErr error
	closed               bool
	closes               int
}

func (p *fakeManagedMaterial) Verify(context.Context) error {
	if p.closed {
		return errors.New("closed material")
	}
	return p.verifyErr
}
func (p *fakeManagedMaterial) VerifyForLaunch(ctx context.Context) error {
	if err := p.Verify(ctx); err != nil {
		return err
	}
	return p.launchErr
}
func (p *fakeManagedMaterial) Identity() quic.MaterialIdentity { return p.identity }
func (p *fakeManagedMaterial) Close() error                    { p.closed = true; p.closes++; return nil }

type fakeManagedGuard struct{ present bool }

func (g *fakeManagedGuard) Begin(ctx context.Context, _ domain.Link, _ *state.QUICGeneration) (context.Context, error) {
	return ctx, nil
}
func (g *fakeManagedGuard) GuardPresent(context.Context, domain.Link) (bool, error) {
	return g.present, nil
}
func (g *fakeManagedGuard) Preflight(context.Context, domain.Link, bool) error { return nil }
func (g *fakeManagedGuard) EnsureGuard(context.Context, domain.Link) (core.Rollback, error) {
	g.present = true
	return func(context.Context) error { return nil }, nil
}
func (g *fakeManagedGuard) RemoveGuard(context.Context, domain.Link) (core.Rollback, error) {
	g.present = false
	return func(context.Context) error { return nil }, nil
}
func (g *fakeManagedGuard) Attest(context.Context, domain.Link) (linux.WGIngressLiveHandles, error) {
	if !g.present {
		return linux.WGIngressLiveHandles{}, errors.New("guard missing")
	}
	return linux.WGIngressLiveHandles{Table: 1, Chain: 2, Rule: 3}, nil
}

type managedHostFixture struct {
	host                                    *Host
	store                                   *managedMemoryStore
	link                                    domain.Link
	op                                      state.QUICCrashOperation
	identity                                hostIdentity
	material                                *fakeManagedMaterial
	binary                                  string
	loaded, active, failed                  bool
	starts, stops                           int
	transientStarts, existingStarts, resets int
	materialForRemoval                      bool
	startErr                                error
}

func newManagedHostFixture(t *testing.T) *managedHostFixture {
	t.Helper()
	old := newOriginFixture(t)
	f := &managedHostFixture{binary: old.op.ExecutablePath, op: old.op, identity: hostIdentity{BootID: "11111111-2222-3333-4444-555555555555", NetworkNS: "net:[4026532999]", MountNS: "mnt:[2]", PIDNS: "pid:[3]", UserNS: "user:[4]", ManagerStartTime: 1}}
	f.link = domain.Link{ID: fixtureID, Backend: domain.BackendWireGuardQUIC, Encapsulation: domain.EncapUDP,
		Underlay: domain.Underlay{Local: netip.MustParseAddr("198.51.100.60"), Peer: netip.MustParseAddr("198.51.100.61")}, Addresses: old.op.Addresses,
		WireGuard: old.op.WireGuard, QUIC: domain.QUICOptions{Role: "listen", UDPPort: 443, TLSServerName: "198.51.100.60"}}
	if err := f.link.Validate(); err != nil {
		t.Fatal(err)
	}
	f.op.ExecutablePath = quic.DefaultExecutable
	f.op.Managed = &state.QUICManagedOperation{Version: 1, Intent: f.link, Operation: "ensure", KernelBootID: f.identity.BootID, KernelBootSource: hostidentity.VerifiedHostBootSourceV1}
	if err := f.op.ValidateManaged(); err != nil {
		t.Fatal(err)
	}
	f.store = &managedMemoryStore{root: old.root, snapshot: state.EmptySnapshot()}
	f.store.snapshot.QUICCrashOperations = []state.QUICCrashOperation{f.op}
	f.material = &fakeManagedMaterial{identity: quic.MaterialIdentity{CertificateSHA256: f.op.CertificateSHA256, TLSKeySHA256: strings.Repeat("e", 64), TrustCASHA256: f.op.TrustCASHA256,
		AuthorizationSHA256: f.op.AuthorizationSHA256, HelperConfigSHA256: f.op.HelperConfigSHA256, DirectoryDevice: 1, DirectoryInode: 2, ReceiptDevice: 3, ReceiptInode: 4}}
	f.host = &Host{root: old.root, store: f.store, guard: &fakeManagedGuard{present: true}}
	f.host.ops = managedHostOps{
		host:              func() (hostIdentity, error) { return f.identity, nil },
		inspectExecutable: func(string) (pinnedexec.Identity, error) { return expectedMaterial(f.op).Executable, nil },
		executable: func(_ string, digest string) (*os.File, pinnedexec.Identity, error) {
			return pinnedexec.Open(f.binary, digest)
		},
		material: func(_ context.Context, _ string, _ quic.Plan, _ uint16, _, _ string, _ quic.HelperConfigIdentity, removing bool) (retainedMaterial, error) {
			f.materialForRemoval = removing
			return f.material, nil
		},
		start: func(context.Context, unitSpec) error {
			f.starts++
			f.transientStarts++
			if f.startErr != nil {
				return f.startErr
			}
			f.loaded, f.active, f.failed = true, true, false
			return nil
		},
		resetFailed: func(_ context.Context, s unitSpec) error {
			if s.Name != "stl-quic-"+string(f.link.ID)[4:]+".service" || !f.loaded || !f.failed || f.active {
				return errors.New("reset was not scoped to the original terminal failed unit")
			}
			f.resets++
			f.loaded, f.active, f.failed = false, false, false
			return nil
		},
		action: func(_ context.Context, action, _ string) error {
			if action == "stop" {
				f.stops++
				// systemd stop leaves a terminal failed unit loaded when
				// CollectMode=inactive; only its scoped reset collects it.
				if !f.failed {
					f.loaded, f.active = false, false
				}
			} else if action == "start" {
				f.starts++
				f.existingStarts++
				f.loaded, f.active, f.failed = true, true, false
			} else {
				return errors.New("unexpected lifecycle action")
			}
			return nil
		},
		events: func(context.Context, string, string, string) ([]HelperEvent, error) { return nil, nil },
		inspect: func(_ context.Context, s unitSpec) (managedUnitObservation, error) {
			o := managedUnitObservation{Loaded: f.loaded, Active: f.active, Host: f.identity, Values: managedRunningProperties(s)}
			if f.failed {
				o.Values["ActiveState"], o.Values["SubState"], o.Values["MainPID"], o.Values["Result"] = "failed", "failed", "0", "start-limit-hit"
			} else if !f.active {
				o.Values["ActiveState"], o.Values["SubState"], o.Values["MainPID"] = "inactive", "dead", "0"
			}
			if f.active {
				fd, err := unix.PidfdOpen(os.Getpid(), 0)
				if err != nil {
					return o, err
				}
				o.Process = &processPin{fd: fd, Observation: processObservation{PID: os.Getpid(), StartTime: 1, InvocationID: strings.Repeat("a", 32), ControlGroup: "/system.slice/" + s.Name,
					NetworkNS: f.identity.NetworkNS, ExecutableDevice: f.op.ExecutableDevice, ExecutableInode: f.op.ExecutableInode, StartMonotonicUSec: 100}}
			}
			return o, nil
		},
	}
	return f
}

func (f *managedHostFixture) context(t *testing.T) context.Context {
	t.Helper()
	ctx, err := core.WithQUICOrigin(context.Background(), f.op.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = core.WithQUICManagedOperation(ctx, f.op)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func (f *managedHostFixture) beginCommitted(t *testing.T, operation string) (context.Context, func() error) {
	t.Helper()
	g := state.QUICGeneration{Version: 1, OriginNonce: f.op.Nonce, MaterialNonce: f.op.Nonce,
		KernelBootID: f.identity.BootID, KernelBootSource: hostidentity.VerifiedHostBootSourceV1, NetworkNS: f.identity.NetworkNS,
		WGIfIndex: 10, GuardTableHandle: 1, GuardChainHandle: 2, GuardRuleHandle: 3,
		Files: materialFiles(f.material.Identity()), ExecutablePath: quic.DefaultExecutable,
		ExecutableSHA256: f.op.ExecutableSHA256, ExecutableDevice: f.op.ExecutableDevice, ExecutableInode: f.op.ExecutableInode}
	if err := g.Validate(f.link); err != nil {
		t.Fatal(err)
	}
	f.op.Managed.Operation, f.op.Managed.HadCommittedLink, f.op.Managed.OriginalGeneration = operation, true, g
	f.store.snapshot.Links = []state.LinkRecord{{Desired: f.link, QUICGeneration: g}}
	f.store.snapshot.QUICCrashOperations = []state.QUICCrashOperation{f.op}
	ctx := core.WithQUICGeneration(f.context(t), g)
	ctx, release, err := f.host.Begin(ctx, f.link, &g)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, release
}

func TestManagedScopeRetainsDescriptorsAcrossPublicationAndReleaseNeverStops(t *testing.T) {
	f := newManagedHostFixture(t)
	ctx, closeScope, err := f.host.Begin(f.context(t), f.link, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeScope()
	if _, err := f.host.StartHelper(ctx, f.link); err != nil {
		t.Fatal(err)
	}
	g, err := f.host.Attest(ctx, f.link)
	if err != nil {
		t.Fatal(err)
	}
	g.WGIfIndex = 10
	if err := g.Validate(f.link); err != nil {
		t.Fatal(err)
	}
	scope := ctx.Value(managedScopeKey{}).(*managedScope)
	if scope.executable == nil || f.material.closed || len(scope.processes) == 0 {
		t.Fatal("pins ended before canonical State publication")
	}
	fd := int(scope.executable.Fd())
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		t.Fatal("executable descriptor already closed")
	}
	// Model both durable and visible-but-unconfirmed publication: releasing
	// the scope must never compensate a now-visible committed generation.
	f.store.snapshot.Links = []state.LinkRecord{{Desired: f.link, QUICGeneration: g}}
	f.store.snapshot.QUICCrashOperations = nil
	if err := closeScope(); err != nil {
		t.Fatal(err)
	}
	if f.stops != 0 || !f.loaded || !f.active || !f.material.closed || f.material.closes != 1 {
		t.Fatal("descriptor release mutated live helper")
	}
	if unix.Fstat(fd, &st) != unix.EBADF {
		t.Fatal("descriptor release leaked executable")
	}
	if _, err := f.host.StopHelper(ctx, f.link); err == nil {
		t.Fatal("closed scope remained an effect authority")
	}
}

func TestManagedExplicitRollbackStopsOnlyTheAdmittedCreatedUnit(t *testing.T) {
	f := newManagedHostFixture(t)
	ctx, release, err := f.host.Begin(f.context(t), f.link, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	undo, err := f.host.StartHelper(ctx, f.link)
	if err != nil {
		t.Fatal(err)
	}
	if f.stops != 0 {
		t.Fatal("start stopped the helper")
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	if f.stops != 1 || f.loaded {
		t.Fatal("explicit rollback did not stop original helper")
	}
}

func TestManagedFreshScopeNeverAdoptsPreexistingUnitOrFabricatedJournal(t *testing.T) {
	for _, change := range []string{"preexisting", "preexisting-failed", "missing-journal", "changed-journal", "host-drift", "closed", "invalid-launch", "missing-guard", "cancel"} {
		t.Run(change, func(t *testing.T) {
			f := newManagedHostFixture(t)
			ctx, release, err := f.host.Begin(f.context(t), f.link, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			switch change {
			case "preexisting":
				f.loaded, f.active = true, true
			case "preexisting-failed":
				f.loaded, f.failed = true, true
			case "missing-journal":
				f.store.snapshot.QUICCrashOperations = nil
			case "changed-journal":
				f.store.snapshot.QUICCrashOperations[0].Nonce = strings.Repeat("b", 32)
			case "host-drift":
				f.identity.ManagerStartTime++
			case "closed":
				release()
			case "invalid-launch":
				f.material.launchErr = errors.New("expired TLS certificate")
			case "missing-guard":
				f.host.guard.(*fakeManagedGuard).present = false
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := f.host.StartHelper(ctx, f.link); err == nil {
				t.Fatal("unverified effect admitted")
			}
			if f.starts != 0 || f.stops != 0 || f.resets != 0 {
				t.Fatal("refusal performed a lifecycle effect")
			}
		})
	}
}

func TestManagedExecutableApprovalDoesNotAcceptSameBytesReplacement(t *testing.T) {
	f := newManagedHostFixture(t)
	raw, err := os.ReadFile(f.binary)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if err := os.Rename(f.binary, f.binary+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.binary, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, release, err := f.host.Begin(f.context(t), f.link, nil); err == nil {
		release()
		t.Fatal("approval then same-byte replacement was accepted")
	}
	if f.starts != 0 {
		t.Fatal("replacement reached an effect")
	}
}

func TestManagedDispatchedFailureRetainsJournalAndCauseWithoutStop(t *testing.T) {
	f := newManagedHostFixture(t)
	secret := errors.New("secret helper stderr must remain private")
	f.startErr = &managerFailure{Kind: "timeout", cause: secret}
	ctx, release, err := f.host.Begin(f.context(t), f.link, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	undo, err := f.host.StartHelper(ctx, f.link)
	if err == nil || undo != nil || !errors.Is(err, core.ErrIndeterminateHostEffect) || !errors.Is(err, secret) {
		t.Fatal("uncertain dispatched failure lost its journal/cause contract")
	}
	if f.starts != 1 || f.stops != 0 || len(f.store.snapshot.QUICCrashOperations) != 1 {
		t.Fatal("uncertain effect was stopped or cleared")
	}
	if strings.Contains(err.Error(), secret.Error()) {
		t.Fatal("private failure text exposed")
	}
}

func TestManagedRuntimeAndPureRendererUseExactlyOneJSONFormatArgument(t *testing.T) {
	f := newManagedHostFixture(t)
	ctx := f.context(t)
	plan, err := quic.PlanFromLink(f.link)
	if err != nil {
		t.Fatal(err)
	}
	command, err := quic.Build(plan, quic.DefaultExecutable, f.store.root, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer command.Clear()
	spec, err := f.host.spec(ctx, f.link)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(command.Args, spec.Args) {
		t.Fatal("managed renderer and production systemd command differ")
	}
	count := 0
	for _, arg := range spec.Args {
		if arg == "--log-format" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("managed log-format flag duplicated or absent")
	}
}

func TestManagedRemoveCollectsCommittedTerminalFailureWithExpiredMaterial(t *testing.T) {
	f := newManagedHostFixture(t)
	f.loaded, f.failed = true, true
	f.material.launchErr = errors.New("original TLS certificate has expired")
	ctx, release := f.beginCommitted(t, "remove")
	defer release()
	undo, err := f.host.StopHelper(ctx, f.link)
	if err != nil {
		t.Fatal(err)
	}
	if !f.materialForRemoval || f.resets != 1 || f.stops != 0 || f.loaded || f.starts != 0 {
		t.Fatal("expired exact generation did not collect only its terminal failed helper")
	}
	if !f.host.guard.(*fakeManagedGuard).present || len(f.store.snapshot.QUICCrashOperations) != 1 {
		t.Fatal("helper collection also removed guard or consumed the canonical journal")
	}
	if err := undo(ctx); err != nil || f.starts != 0 {
		t.Fatal("a previously failed helper was incorrectly relaunched by rollback")
	}
}

func TestManagedStopCollectsTerminalFailureReachedAfterStopDispatch(t *testing.T) {
	f := newManagedHostFixture(t)
	f.loaded, f.active = true, true
	ctx, release := f.beginCommitted(t, "remove")
	defer release()
	f.host.ops.action = func(_ context.Context, action, _ string) error {
		if action != "stop" {
			return errors.New("unexpected action")
		}
		f.stops++
		f.active, f.failed = false, true
		return nil
	}
	if _, err := f.host.StopHelper(ctx, f.link); err != nil {
		t.Fatal(err)
	}
	if f.stops != 1 || f.resets != 1 || f.loaded {
		t.Fatal("terminal failure after the stop job remained loaded")
	}
}

func TestManagedStartRecreatesCollectedTerminalFailureAndStartsExistingInactiveUnit(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "inactive-definition", true: "collected-terminal-failure"}[failed], func(t *testing.T) {
			f := newManagedHostFixture(t)
			f.loaded, f.failed = true, failed
			ctx, release := f.beginCommitted(t, "ensure")
			defer release()
			if _, err := f.host.StartHelper(ctx, f.link); err != nil {
				t.Fatal(err)
			}
			if !f.loaded || !f.active || f.starts != 1 {
				t.Fatal("controlled helper recovery did not verify one current process")
			}
			if failed && (f.resets != 1 || f.transientStarts != 1 || f.existingStarts != 0) {
				t.Fatal("collected transient definition was restarted from stale loaded observation")
			}
			if !failed && (f.resets != 0 || f.transientStarts != 0 || f.existingStarts != 1) {
				t.Fatal("owned inactive definition was reset or recreated unnecessarily")
			}
		})
	}
}

func TestManagedTerminalStartRequiresCurrentMaterialBeforeReset(t *testing.T) {
	f := newManagedHostFixture(t)
	f.loaded, f.failed = true, true
	ctx, release := f.beginCommitted(t, "ensure")
	defer release()
	f.material.launchErr = errors.New("expired certificate")
	if _, err := f.host.StartHelper(ctx, f.link); err == nil {
		t.Fatal("expired generation reached controlled start")
	}
	if f.resets != 0 || f.starts != 0 || !f.loaded {
		t.Fatal("invalid launch reset an otherwise retained terminal failure")
	}
}

func TestManagedTerminalResetRechecksCanonicalAdmissionAndEffectivePolicy(t *testing.T) {
	for _, drift := range []string{"journal", "material", "host", "foreign-hook", "incoming-upholds", "source-only-description", "reactivated"} {
		t.Run(drift, func(t *testing.T) {
			f := newManagedHostFixture(t)
			f.loaded, f.failed = true, true
			ctx, release := f.beginCommitted(t, "remove")
			defer release()
			inspect, calls := f.host.ops.inspect, 0
			f.host.ops.inspect = func(c context.Context, s unitSpec) (managedUnitObservation, error) {
				obs, err := inspect(c, s)
				calls++
				if calls == 1 {
					switch drift {
					case "journal":
						f.store.snapshot.QUICCrashOperations = nil
					case "material":
						f.material.verifyErr = errors.New("protected material replaced")
					case "host":
						f.identity.ManagerStartTime++
					case "reactivated":
						f.failed, f.active = false, true
					}
				} else {
					switch drift {
					case "foreign-hook":
						obs.Values["ExecStopPost"] = "foreign command"
					case "incoming-upholds":
						obs.Values["UpheldBy"] = "foreign.service"
					case "source-only-description":
						obs.Values["Description"] = "STL-QUIC-" + string(f.link.ID) + ":tx:" + f.op.Nonce
					}
					if policyErr := verifyManagedUnitProperties(obs.Values, s, false); policyErr != nil {
						return obs, policyErr
					}
				}
				return obs, err
			}
			_, err := f.host.StopHelper(ctx, f.link)
			if err == nil || errors.Is(err, core.ErrIndeterminateHostEffect) {
				t.Fatal("pre-dispatch reset refusal lost its nonmutating boundary")
			}
			if f.resets != 0 || f.stops != 0 || f.starts != 0 {
				t.Fatal("drifted terminal identity reached a lifecycle command")
			}
		})
	}
}

func TestManagedTerminalResetUncertaintyNeverClearsJournalOrGuard(t *testing.T) {
	for _, failure := range []string{"dispatch", "readback", "still-loaded", "changed-journal", "canceled", "launch-expired-after-reset"} {
		t.Run(failure, func(t *testing.T) {
			f := newManagedHostFixture(t)
			f.loaded, f.failed = true, true
			operation := "remove"
			if failure == "launch-expired-after-reset" {
				operation = "ensure"
			}
			ctx, release := f.beginCommitted(t, operation)
			defer release()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			privateCause := errors.New("private manager stderr secret canary")
			reset := f.host.ops.resetFailed
			f.host.ops.resetFailed = func(c context.Context, s unitSpec) error {
				if failure == "dispatch" {
					f.resets++
					return errors.Join(core.ErrIndeterminateHostEffect, &managerFailure{Kind: "timeout", cause: privateCause})
				}
				if err := reset(c, s); err != nil {
					return err
				}
				switch failure {
				case "readback":
					f.host.ops.inspect = func(context.Context, unitSpec) (managedUnitObservation, error) {
						return managedUnitObservation{}, privateCause
					}
				case "still-loaded":
					f.loaded = true
				case "changed-journal":
					f.store.snapshot.QUICCrashOperations[0].Nonce = strings.Repeat("b", 32)
				case "canceled":
					cancel()
				case "launch-expired-after-reset":
					f.material.launchErr = privateCause
				}
				return nil
			}
			var err error
			if operation == "ensure" {
				_, err = f.host.StartHelper(ctx, f.link)
			} else {
				_, err = f.host.StopHelper(ctx, f.link)
			}
			if err == nil || !errors.Is(err, core.ErrIndeterminateHostEffect) {
				t.Fatal("reset dispatch/readback uncertainty lost its quarantine classification")
			}
			if f.resets != 1 || f.starts != 0 || f.stops != 0 || !f.host.guard.(*fakeManagedGuard).present || len(f.store.snapshot.QUICCrashOperations) != 1 {
				t.Fatal("uncertain terminal collection continued into an unrelated effect or consumed its journal")
			}
			if strings.Contains(err.Error(), privateCause.Error()) {
				t.Fatal("reset failure exposed private command output")
			}
		})
	}
}
