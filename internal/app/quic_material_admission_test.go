package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func quicMaterialIdentity(op state.QUICCrashOperation) quic.HelperConfigIdentity {
	return quic.HelperConfigIdentity{
		ConfigSHA256: op.HelperConfigSHA256,
		Credentials: quic.CredentialIdentity{
			CertificateSHA256:   op.CertificateSHA256,
			TrustCASHA256:       op.TrustCASHA256,
			AuthorizationSHA256: op.AuthorizationSHA256,
		},
		Executable: linux.PinnedExecutableIdentity{
			SHA256: op.ExecutableSHA256,
			Device: op.ExecutableDevice, Inode: op.ExecutableInode,
		},
	}
}

func materialJournalForRole(role composition.Role) state.QUICCrashOperation {
	op := quicCrashIntentFixture()
	if role == composition.Listen {
		op.Plan.Local.Role = composition.Listen
		op.Plan.Local.LocalWGUDPPort = 51820
		op.Plan.Local.LocalHelperUDPPort = op.Plan.Physical.Port()
		op.Plan.Local.RemoteWGUDPPort = 0
		op.WireGuard.ListenPort = 51820
		op.WireGuard.PeerPort = 51821
	}
	return op
}

func TestInspectQUICCrashMaterialsBindsStateRootTopologyAndAllFingerprints(t *testing.T) {
	for _, role := range []composition.Role{composition.Dial, composition.Listen} {
		t.Run(string(role), func(t *testing.T) {
			ctx := context.Background()
			backend := newFakeBackend()
			engine, store := newEngine(t, backend)
			prepared, err := engine.PrepareQUICCrash(ctx, materialJournalForRole(role), &quicVacancyProbe{})
			if err != nil {
				t.Fatal(err)
			}
			prior, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			called := 0
			inspect := func(root string, plan quic.Plan, port uint16, binary string) (quic.HelperConfigIdentity, error) {
				called++
				expected, err := plan.HostPlan(port)
				if err != nil || expected != prepared.Plan ||
					root != store.RootDir() || binary != prepared.ExecutablePath ||
					port != prepared.WireGuard.ListenPort {
					t.Fatalf("journal Plan/State root/executable substituted: %+v %v", plan, err)
				}
				return quicMaterialIdentity(prepared), nil
			}
			if err := engine.inspectQUICCrashMaterials(ctx, prepared.Plan.Local.LinkID, inspect); err != nil {
				t.Fatal(err)
			}
			if called != 1 || backend.applyCount != 0 || len(backend.present) != 0 {
				t.Fatal("inspection performed host mutation or failed to inspect exactly once")
			}
			after, err := store.Load(ctx)
			if err != nil || !reflect.DeepEqual(prior, after) {
				t.Fatalf("read-only material inspection changed durable journal: %v", err)
			}
		})
	}
}

func TestInspectQUICCrashMaterialsRejectsDriftAndUnverifiedFiles(t *testing.T) {
	ctx := context.Background()
	engine, store := newEngine(t, newFakeBackend())
	op, err := engine.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	prior, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*quic.HelperConfigIdentity)
	}{
		{"certificate", func(x *quic.HelperConfigIdentity) { x.Credentials.CertificateSHA256 = strings.Repeat("f", 64) }},
		{"CA", func(x *quic.HelperConfigIdentity) { x.Credentials.TrustCASHA256 = strings.Repeat("f", 64) }},
		{"bearer", func(x *quic.HelperConfigIdentity) { x.Credentials.AuthorizationSHA256 = strings.Repeat("f", 64) }},
		{"config", func(x *quic.HelperConfigIdentity) { x.ConfigSHA256 = strings.Repeat("f", 64) }},
		{"binary-digest", func(x *quic.HelperConfigIdentity) { x.Executable.SHA256 = strings.Repeat("f", 64) }},
		{"binary-device", func(x *quic.HelperConfigIdentity) { x.Executable.Device++ }},
		{"binary-inode", func(x *quic.HelperConfigIdentity) { x.Executable.Inode++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := quicMaterialIdentity(op)
			tc.mutate(&identity)
			err := engine.inspectQUICCrashMaterials(ctx, op.Plan.Local.LinkID, func(string, quic.Plan, uint16, string) (quic.HelperConfigIdentity, error) { return identity, nil })
			if stlerr.CodeOf(err) != stlerr.CodeConflict {
				t.Fatalf("accepted untrusted material: %v", err)
			}
		})
	}
	secret := "PRIVATE TOKEN must never appear in Engine errors"
	err = engine.inspectQUICCrashMaterials(ctx, op.Plan.Local.LinkID, func(string, quic.Plan, uint16, string) (quic.HelperConfigIdentity, error) {
		return quic.HelperConfigIdentity{}, errors.New(secret)
	})
	if stlerr.CodeOf(err) != stlerr.CodeState || strings.Contains(err.Error(), secret) {
		t.Fatalf("inspection failure not fail-closed or secret-safe: %v", err)
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(prior, after) {
		t.Fatalf("failed inspections modified journal: %v", err)
	}
}

func TestInspectQUICCrashMaterialsRejectsNoJournalOrMissingOfficialHelper(t *testing.T) {
	ctx := context.Background()
	engine, store := newEngine(t, newFakeBackend())
	candidate := quicCrashIntentFixture()
	called := false
	reader := func(string, quic.Plan, uint16, string) (quic.HelperConfigIdentity, error) {
		called = true
		return quic.HelperConfigIdentity{}, nil
	}
	if err := engine.inspectQUICCrashMaterials(ctx, candidate.Plan.Local.LinkID, reader); stlerr.CodeOf(err) != stlerr.CodeConflict || called {
		t.Fatalf("missing journal caused material inspection: %v", err)
	}
	candidate.ExecutablePath = "/nonexistent/stl-quic-attestation-helper"
	if _, err := engine.PrepareQUICCrash(ctx, candidate, &quicVacancyProbe{}); err != nil {
		t.Fatal(err)
	}
	if err := engine.InspectQUICCrashMaterials(ctx, candidate.Plan.Local.LinkID); stlerr.CodeOf(err) != stlerr.CodeState {
		t.Fatalf("public Engine path accepted missing official pinned helper: %v", err)
	}
	fresh, err := store.Load(ctx)
	if err != nil || len(fresh.QUICCrashOperations) != 1 {
		t.Fatalf("failed helper inspection erased journal: %v", err)
	}
}

// The read-only callback must run while the REAL file-backed Link and
// resource locks are held, not only after a stale preflight. A competing
// acquisition of each exact lock must fail on its own bounded deadline.
func TestInspectQUICCrashMaterialsHoldsRealLinkAndResourceLocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	engine, _ := newEngine(t, newFakeBackend())
	op, err := engine.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	entered, proceed := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()
	finished := make(chan error, 1)
	go func() {
		finished <- engine.inspectQUICCrashMaterials(ctx, op.Plan.Local.LinkID,
			func(string, quic.Plan, uint16, string) (quic.HelperConfigIdentity, error) {
				close(entered)
				select {
				case <-proceed:
				case <-ctx.Done():
					return quic.HelperConfigIdentity{}, ctx.Err()
				}
				return quicMaterialIdentity(op), nil
			})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("material inspector did not enter locked section")
	}
	for _, claim := range []domain.ResourceClaim{
		linkLock(op.Plan.Local.LinkID),
		{Kind: domain.ResourceUDPListenPort, Key: "51821"},
		{Kind: domain.ResourceUDPListenPort, Key: "52211"},
	} {
		contender, stop := context.WithTimeout(ctx, 65*time.Millisecond)
		release, acquireErr := engine.locks.Acquire(contender, []domain.ResourceClaim{claim})
		stop()
		if acquireErr == nil {
			_ = release()
			t.Fatalf("actual canonical claim lock not held: %+v", claim)
		}
		if !errors.Is(acquireErr, context.DeadlineExceeded) {
			t.Fatalf("unexpected lock contender error for %+v: %v", claim, acquireErr)
		}
	}
	close(proceed)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	release, err := engine.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(op.Plan.Local.LinkID)})
	if err != nil {
		t.Fatalf("material inspector retained Link lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

// A Store implementation without a canonical root cannot redirect the
// protected-file read to an arbitrary caller-chosen private directory.
type quicRootlessStore struct{ state.Store }

func TestInspectQUICCrashMaterialsFailsClosedWithoutCanonicalRoot(t *testing.T) {
	engine, store := newEngine(t, newFakeBackend())
	engine.store = quicRootlessStore{Store: store}
	var called atomic.Bool
	err := engine.inspectQUICCrashMaterials(context.Background(), quicCrashIntentFixture().Plan.Local.LinkID,
		func(string, quic.Plan, uint16, string) (quic.HelperConfigIdentity, error) {
			called.Store(true)
			return quic.HelperConfigIdentity{}, nil
		})
	if stlerr.CodeOf(err) != stlerr.CodeState || called.Load() {
		t.Fatalf("rootless Store admitted file identity: %v", err)
	}
}
