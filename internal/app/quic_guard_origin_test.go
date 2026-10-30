package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type testQUICOriginalAdmissionCallback struct{ calls int }

func (h *testQUICOriginalAdmissionCallback) invoke(context.Context, string, domain.LinkID, string, domain.WireGuardOptions) error {
	h.calls++
	return nil
}

func TestQUICOriginalGuardEngineRequiresJournalMaterialsAndExactOrigin(t *testing.T) {
	for _, role := range []composition.Role{composition.Dial, composition.Listen} {
		t.Run(string(role), func(t *testing.T) {
			ctx := context.Background()
			backend := newFakeBackend()
			engine, store := newEngine(t, backend)
			op, err := engine.PrepareQUICCrash(ctx, materialJournalForRole(role), &quicVacancyProbe{})
			if err != nil {
				t.Fatal(err)
			}
			prior, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			inspect, publish := 0, 0
			err = engine.withQUICCrashIngressAdmission(ctx, op.Plan.Local.LinkID,
				func(root string, plan quic.Plan, port uint16, got state.QUICCrashOperation) error {
					inspect++
					recreated, e := plan.HostPlan(port)
					if e != nil || recreated != op.Plan || root != store.RootDir() || got.Nonce != op.Nonce || port != op.WireGuard.ListenPort ||
						got.HelperConfigSHA256 != op.HelperConfigSHA256 || got.ExecutableInode != op.ExecutableInode {
						t.Fatalf("Engine trust admission substituted original journal: %v", e)
					}
					return nil
				}, func(_ context.Context, originRoot string, id domain.LinkID, nonce string, wg domain.WireGuardOptions) error {
					publish++
					if inspect != 1 || originRoot != store.RootDir() || id != op.Plan.Local.LinkID || nonce != op.Nonce || wg != op.WireGuard {
						t.Fatal("Engine admission callback lacks exact journal-bound and attested identity")
					}
					return nil
				})
			after, e := store.Load(ctx)
			if err != nil || e != nil || inspect != 1 || publish != 1 || backend.applyCount != 0 ||
				!reflect.DeepEqual(prior, after) || len(after.QUICCrashOperations) != 1 {
				t.Fatalf("Engine admission did not preserve pending durable journal: %v %v", err, e)
			}
		})
	}
}

func TestQUICOriginalGuardEngineNeverRunsWithoutJournalOrTrustedMaterials(t *testing.T) {
	ctx := context.Background()
	engine, store := newEngine(t, newFakeBackend())
	intent := materialJournalForRole(composition.Listen)
	host := &testQUICOriginalAdmissionCallback{}
	if err := engine.WithQUICCrashIngressAdmission(ctx, intent.Plan.Local.LinkID, nil); stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("nil admission callback accepted: %v", err)
	}
	if err := engine.WithQUICCrashIngressAdmission(ctx, intent.Plan.Local.LinkID, host.invoke); stlerr.CodeOf(err) != stlerr.CodeConflict || host.calls != 0 {
		t.Fatalf("absent journal admission invoked effect callback: %v", err)
	}
	op, err := engine.PrepareQUICCrash(ctx, intent, &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Public production path cannot fabricate receipts/materials; it must
	// fail closed before any network or firewall effect.
	if err := engine.WithQUICCrashIngressAdmission(ctx, op.Plan.Local.LinkID, host.invoke); stlerr.CodeOf(err) != stlerr.CodeState || host.calls != 0 {
		t.Fatalf("untrusted real material created guard: %v", err)
	}
	secret := "SENSITIVE_QUIC_ORIGINAL_HOST_ERROR"
	called := false
	err = engine.withQUICCrashIngressAdmission(ctx, op.Plan.Local.LinkID,
		func(string, quic.Plan, uint16, state.QUICCrashOperation) error { return errors.New(secret) },
		func(context.Context, string, domain.LinkID, string, domain.WireGuardOptions) error {
			called = true
			return nil
		})
	if stlerr.CodeOf(err) != stlerr.CodeState || called || strings.Contains(err.Error(), secret) {
		t.Fatalf("material failure leaked or created host guard: %v", err)
	}
	err = engine.withQUICCrashIngressAdmission(ctx, op.Plan.Local.LinkID,
		func(string, quic.Plan, uint16, state.QUICCrashOperation) error { return nil },
		func(context.Context, string, domain.LinkID, string, domain.WireGuardOptions) error {
			called = true
			return errors.New(secret)
		})
	if stlerr.CodeOf(err) != stlerr.CodeState || !called || strings.Contains(err.Error(), secret) {
		t.Fatalf("uncertain host dispatch leaked or discarded quarantine: %v", err)
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("guard failure lost durable intent: %v", err)
	}
}
