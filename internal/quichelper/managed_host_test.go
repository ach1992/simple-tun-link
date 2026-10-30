package quichelper

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
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
	host           *Host
	store          *managedMemoryStore
	link           domain.Link
	op             state.QUICCrashOperation
	identity       hostIdentity
	material       *fakeManagedMaterial
	binary         string
	loaded, active bool
	starts, stops  int
	startErr       error
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
	f.op.Managed = &state.QUICManagedOperation{Version: 1, Intent: f.link, Operation: "ensure"}
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
		material: func(context.Context, string, quic.Plan, uint16, string, string, quic.HelperConfigIdentity, bool) (retainedMaterial, error) {
			return f.material, nil
		},
		start: func(context.Context, unitSpec) error {
			f.starts++
			if f.startErr != nil {
				return f.startErr
			}
			f.loaded, f.active = true, true
			return nil
		},
		action: func(_ context.Context, action, _ string) error {
			if action == "stop" {
				f.stops++
				f.loaded, f.active = false, false
			} else {
				f.starts++
				f.loaded, f.active = true, true
			}
			return nil
		},
		events: func(context.Context, string, string, string) ([]HelperEvent, error) { return nil, nil },
		inspect: func(_ context.Context, s unitSpec) (managedUnitObservation, error) {
			o := managedUnitObservation{Loaded: f.loaded, Active: f.active, Host: f.identity, Values: managedRunningProperties(s)}
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
	for _, change := range []string{"preexisting", "missing-journal", "changed-journal", "host-drift", "closed", "invalid-launch", "missing-guard", "cancel"} {
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
			if f.starts != 0 || f.stops != 0 {
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
