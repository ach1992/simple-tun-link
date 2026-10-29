package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestStageQUICCrashMaterialsUsesExactJournalPlanAndRetainsQuarantine(t *testing.T) {
	for _, role := range []composition.Role{composition.Dial, composition.Listen} {
		t.Run(string(role), func(t *testing.T) {
			ctx := context.Background()
			backend := newFakeBackend()
			engine, store := newEngine(t, backend)
			op, err := engine.PrepareQUICCrash(ctx, materialJournalForRole(role), &quicVacancyProbe{})
			if err != nil {
				t.Fatal(err)
			}
			before, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			stage := func(_ context.Context, root string, plan quic.Plan, port uint16, binary string,
				_ quic.CredentialBundle, expected quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
				calls++
				roundTrip, err := plan.HostPlan(port)
				if err != nil || roundTrip != op.Plan || port != op.WireGuard.ListenPort ||
					root != store.RootDir() || binary != op.ExecutablePath ||
					expected != quicMaterialIdentity(op) {
					t.Fatalf("stager could substitute journal Plan/root/helper identity: %v", err)
				}
				return expected, nil
			}
			if err := engine.stageQUICCrashMaterials(ctx, op.Plan.Local.LinkID, quic.CredentialBundle{}, stage); err != nil {
				t.Fatal(err)
			}
			after, err := store.Load(ctx)
			if err != nil || calls != 1 || !reflect.DeepEqual(before, after) ||
				len(after.QUICCrashOperations) != 1 || backend.applyCount != 0 || len(backend.present) != 0 {
				t.Fatalf("stage changed committed State, quarantine or backend: %v", err)
			}
		})
	}
}

func TestStageQUICCrashMaterialsRejectsMissingJournalAndUntrustedMaterial(t *testing.T) {
	ctx := context.Background()
	backend := newFakeBackend()
	engine, store := newEngine(t, backend)
	op := quicCrashIntentFixture()
	calls := 0
	stage := func(_ context.Context, _ string, _ quic.Plan, _ uint16, _ string, _ quic.CredentialBundle,
		expected quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
		calls++
		return expected, nil
	}
	if err := engine.stageQUICCrashMaterials(ctx, op.Plan.Local.LinkID, quic.CredentialBundle{}, stage); stlerr.CodeOf(err) != stlerr.CodeConflict || calls != 0 {
		t.Fatalf("un-journaled staging admitted: %v", err)
	}
	prepared, err := engine.PrepareQUICCrash(ctx, op, &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	prior, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Public Engine route is wired to real official pinned helper and real
	// protected material, not the test-only callback.
	if err := engine.StageQUICCrashMaterials(ctx, op.Plan.Local.LinkID, quic.CredentialBundle{}); stlerr.CodeOf(err) != stlerr.CodeState {
		t.Fatalf("public stager accepted untrusted material or missing helper: %v", err)
	}
	dir := filepath.Join(store.RootDir(), "credentials", "quic", string(op.Plan.Local.LinkID))
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("untrusted public input created files: %v", err)
	}
	secret := "TEST SECRET PRIVATE BEARER should not escape"
	fail := func(_ context.Context, _ string, _ quic.Plan, _ uint16, _ string, _ quic.CredentialBundle,
		_ quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
		return quic.HelperConfigIdentity{}, errors.New(secret)
	}
	if err := engine.stageQUICCrashMaterials(ctx, op.Plan.Local.LinkID, quic.CredentialBundle{}, fail); stlerr.CodeOf(err) != stlerr.CodeState || strings.Contains(err.Error(), secret) {
		t.Fatalf("underlying sensitive failure escaped: %v", err)
	}
	drift := func(_ context.Context, _ string, _ quic.Plan, _ uint16, _ string, _ quic.CredentialBundle,
		identity quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
		identity.Executable.Inode++
		return identity, nil
	}
	if err := engine.stageQUICCrashMaterials(ctx, op.Plan.Local.LinkID, quic.CredentialBundle{}, drift); stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("post-stage executable drift admitted: %v", err)
	}
	engine.store = quicRootlessStore{Store: store}
	if err := engine.stageQUICCrashMaterials(ctx, op.Plan.Local.LinkID, quic.CredentialBundle{}, stage); stlerr.CodeOf(err) != stlerr.CodeState || calls != 0 {
		t.Fatalf("noncanonical State root admitted: %v", err)
	}
	engine.store = store
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(prior, after) || len(after.QUICCrashOperations) != 1 ||
		after.QUICCrashOperations[0].Nonce != prepared.Nonce || backend.applyCount != 0 {
		t.Fatalf("stage errors modified immutable journal or host: %v", err)
	}
}

func TestStageQUICCrashMaterialsHoldsFileBackedLinkAndUDPResourceLocks(t *testing.T) {
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
		finished <- engine.stageQUICCrashMaterials(ctx, op.Plan.Local.LinkID, quic.CredentialBundle{},
			func(_ context.Context, _ string, _ quic.Plan, _ uint16, _ string, _ quic.CredentialBundle,
				expected quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
				close(entered)
				select {
				case <-proceed:
				case <-ctx.Done():
					return quic.HelperConfigIdentity{}, ctx.Err()
				}
				return expected, nil
			})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("stager did not enter locked section")
	}
	for _, claim := range []domain.ResourceClaim{
		linkLock(op.Plan.Local.LinkID),
		{Kind: domain.ResourceUDPListenPort, Key: "51821"},
		{Kind: domain.ResourceUDPListenPort, Key: "52211"},
	} {
		contender, stop := context.WithTimeout(ctx, 65*time.Millisecond)
		release, err := engine.locks.Acquire(contender, []domain.ResourceClaim{claim})
		stop()
		if err == nil {
			_ = release()
			t.Fatalf("staging lacked lock %+v", claim)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wrong lock error %+v: %v", claim, err)
		}
	}
	close(proceed)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	release, err := engine.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(op.Plan.Local.LinkID)})
	if err != nil {
		t.Fatalf("staging leaked Link lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

// Independent QUIC journal generations must both stage successfully without
// touching each other's State. The canonical resource lock mapper deliberately
// serializes all IPv4 Link Address changes via stl-address-space/ipv4, even
// when the individual Link IDs, UDP ports and routes do not conflict.
func TestStageQUICCrashMaterialsIndependentLinksPreserveStateUnderSharedIPv4Lock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	engine, store := newEngine(t, newFakeBackend())
	first := quicCrashIntentFixture()
	second := first
	second.Plan.Local.LinkID = domain.LinkID("lnk_99999999999999999999999999999999")
	second.Plan.Local.LocalWGUDPPort = 51822
	second.Plan.Local.LocalHelperUDPPort = 52212
	second.Addresses.Local = netip.MustParsePrefix("10.96.21.0/31")
	second.Addresses.Peer = netip.MustParsePrefix("10.96.21.1/31")
	second.WireGuard.ListenPort, second.WireGuard.PeerPort = 51822, 52212
	second.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	for _, op := range []struct {
		name   string
		intent state.QUICCrashOperation
	}{
		{"first", first}, {"second", second},
	} {
		if _, err := engine.PrepareQUICCrash(ctx, op.intent, &quicVacancyProbe{}); err != nil {
			t.Fatalf("%s journal conflict: %v", op.name, err)
		}
	}
	prior, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan domain.LinkID, 2)
	proceed := make(chan struct{})
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()
	finished := make(chan error, 2)
	for _, id := range []domain.LinkID{first.Plan.Local.LinkID, second.Plan.Local.LinkID} {
		go func(id domain.LinkID) {
			finished <- engine.stageQUICCrashMaterials(ctx, id, quic.CredentialBundle{},
				func(_ context.Context, _ string, _ quic.Plan, _ uint16, _ string, _ quic.CredentialBundle,
					expected quic.HelperConfigIdentity) (quic.HelperConfigIdentity, error) {
					entered <- id
					select {
					case <-proceed:
					case <-ctx.Done():
						return quic.HelperConfigIdentity{}, ctx.Err()
					}
					return expected, nil
				})
		}(id)
	}
	var a domain.LinkID
	select {
	case a = <-entered:
	case <-ctx.Done():
		t.Fatal("first staging blocked")
	}
	select {
	case b := <-entered:
		t.Fatalf("shared IPv4 address-space lock incorrectly allowed concurrent staging for %s and %s", a, b)
	case <-time.After(75 * time.Millisecond):
		// The second Link waits on the global canonical IPv4 lock;
		// that is intended to prevent address-space write races.
	}
	close(proceed)
	var b domain.LinkID
	select {
	case b = <-entered:
	case <-ctx.Done():
		t.Fatal("second independent Link did not resume after lock release")
	}
	if a == b {
		t.Fatal("second staging used first Link identity")
	}
	for range 2 {
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(prior, after) {
		t.Fatalf("independent staging changed journals: %v", err)
	}
}
