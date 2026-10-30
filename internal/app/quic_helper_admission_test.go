package app

import (
	"context"
	"encoding/json"
	"errors"
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

func TestQUICHelperAdmissionBindsOriginalJournalAndReattestsAfterActivation(t *testing.T) {
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
			var events []string
			inspect := func(root string, plan quic.Plan, port uint16, got state.QUICCrashOperation) error {
				events = append(events, "inspect")
				host, err := plan.HostPlan(port)
				if err != nil || host != op.Plan || root != store.RootDir() || !reflect.DeepEqual(got, op) {
					t.Fatal("material reattestation was not bound to the immutable journal")
				}
				return nil
			}
			err = engine.withQUICCrashHelperAdmission(ctx, op.Plan.Local.LinkID, inspect,
				func(gotCtx context.Context, root string, plan quic.Plan, got state.QUICCrashOperation) error {
					events = append(events, "activate")
					host, err := plan.HostPlan(got.WireGuard.ListenPort)
					if err != nil || host != op.Plan || gotCtx != ctx || root != store.RootDir() || !reflect.DeepEqual(got, op) {
						t.Fatal("helper callback received caller-substituted activation identity")
					}
					// A callback-local edit cannot rewrite the expected journal
					// through the resource slice's shared backing storage.
					got.Resources[0].Key = "callback-local-change"
					return nil
				})
			after, readErr := store.Load(ctx)
			if err != nil || readErr != nil || !reflect.DeepEqual(before, after) ||
				!reflect.DeepEqual(events, []string{"inspect", "activate", "inspect"}) || backend.applyCount != 0 {
				t.Fatalf("helper admission changed journal, dispatched backend or missed reattestation: %v %v %v", err, readErr, events)
			}
		})
	}
}

func TestQUICHelperAdmissionRequiresJournalAndRealProtectedGeneration(t *testing.T) {
	ctx := context.Background()
	engine, store := newEngine(t, newFakeBackend())
	intent := quicCrashIntentFixture()
	calls := 0
	activate := func(context.Context, string, quic.Plan, state.QUICCrashOperation) error { calls++; return nil }
	if err := engine.WithQUICCrashHelperAdmission(ctx, intent.Plan.Local.LinkID, nil); stlerr.CodeOf(err) != stlerr.CodeInvalid {
		t.Fatalf("nil helper callback accepted: %v", err)
	}
	if err := engine.WithQUICCrashHelperAdmission(ctx, intent.Plan.Local.LinkID, activate); stlerr.CodeOf(err) != stlerr.CodeConflict || calls != 0 {
		t.Fatalf("missing journal admitted helper effect: %v", err)
	}
	op, err := engine.PrepareQUICCrash(ctx, intent, &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.WithQUICCrashHelperAdmission(ctx, op.Plan.Local.LinkID, activate); stlerr.CodeOf(err) != stlerr.CodeState || calls != 0 {
		t.Fatalf("public path bypassed real protected material verification: %v", err)
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("failed public admission changed quarantine: %v", err)
	}
}

func TestQUICHelperAdmissionFailureAndCancellationKeepQuarantine(t *testing.T) {
	for _, stage := range []string{"pre-material", "post-material", "activation", "cancel-before", "cancel-inspect", "cancel-activation"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			engine, store := newEngine(t, newFakeBackend())
			op, err := engine.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
			if err != nil {
				t.Fatal(err)
			}
			before, err := store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			const secret = "PRIVATE_HELPER_BEARER_AND_ERROR_OUTPUT"
			inspects, activations := 0, 0
			if stage == "cancel-before" {
				cancel()
			}
			err = engine.withQUICCrashHelperAdmission(ctx, op.Plan.Local.LinkID,
				func(string, quic.Plan, uint16, state.QUICCrashOperation) error {
					inspects++
					if stage == "pre-material" || (stage == "post-material" && inspects == 2) {
						return errors.New(secret)
					}
					if stage == "cancel-inspect" {
						cancel()
					}
					return nil
				},
				func(context.Context, string, quic.Plan, state.QUICCrashOperation) error {
					activations++
					if stage == "activation" {
						return errors.New(secret)
					}
					if stage == "cancel-activation" {
						cancel()
					}
					return nil
				})
			if stlerr.CodeOf(err) != stlerr.CodeState || strings.Contains(err.Error(), secret) {
				t.Fatalf("uncertain helper stage did not fail closed with sanitized context: %v", err)
			}
			wantActivations := 1
			if stage == "pre-material" || stage == "cancel-before" || stage == "cancel-inspect" {
				wantActivations = 0
			}
			if activations != wantActivations || (stage == "post-material" && inspects != 2) || (stage == "cancel-before" && inspects != 0) {
				t.Fatalf("wrong effect boundary: inspect=%d activate=%d", inspects, activations)
			}
			after, err := store.Load(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("helper failure consumed or changed the journal: %v", err)
			}
		})
	}
}

func TestQUICHelperAdmissionHoldsCanonicalLocksThroughActivationAndReadback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	engine, _ := newEngine(t, newFakeBackend())
	op, err := engine.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	assertLocked := func(claim domain.ResourceClaim) {
		t.Helper()
		competing, stop := context.WithTimeout(ctx, 65*time.Millisecond)
		defer stop()
		release, err := engine.locks.Acquire(competing, []domain.ResourceClaim{claim})
		if err == nil {
			_ = release()
			t.Fatalf("canonical claim was released early: %+v", claim)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected lock contention failure: %v", err)
		}
	}
	inspects := 0
	err = engine.withQUICCrashHelperAdmission(ctx, op.Plan.Local.LinkID,
		func(string, quic.Plan, uint16, state.QUICCrashOperation) error {
			inspects++
			if inspects == 2 {
				assertLocked(linkLock(op.Plan.Local.LinkID))
			}
			return nil
		},
		func(context.Context, string, quic.Plan, state.QUICCrashOperation) error {
			assertLocked(linkLock(op.Plan.Local.LinkID))
			assertLocked(domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: "51821"})
			return nil
		})
	if err != nil || inspects != 2 {
		t.Fatalf("locked helper admission failed: %v", err)
	}
	release, err := engine.locks.Acquire(ctx, []domain.ResourceClaim{linkLock(op.Plan.Local.LinkID)})
	if err != nil {
		t.Fatalf("helper admission retained completed lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestQUICHelperAdmissionRejectsJournalDriftWithoutOverwritingEvidence(t *testing.T) {
	ctx := context.Background()
	engine, store := newEngine(t, newFakeBackend())
	op, err := engine.PrepareQUICCrash(ctx, quicCrashIntentFixture(), &quicVacancyProbe{})
	if err != nil {
		t.Fatal(err)
	}
	const changedDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	err = engine.withQUICCrashHelperAdmission(ctx, op.Plan.Local.LinkID,
		func(string, quic.Plan, uint16, state.QUICCrashOperation) error { return nil },
		func(context.Context, string, quic.Plan, state.QUICCrashOperation) error {
			// FileStore.Update correctly forbids immutable-journal changes.
			// Model an out-of-band writer ignoring Engine/Store locks only
			// inside this test's private temporary State root instead.
			snapshot, err := store.Load(ctx)
			if err != nil {
				return err
			}
			snapshot.QUICCrashOperations[0].HelperConfigSHA256 = changedDigest
			raw, err := json.Marshal(snapshot)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(store.RootDir(), "state.json"), append(raw, '\n'), 0o600)
		})
	if stlerr.CodeOf(err) != stlerr.CodeConflict {
		t.Fatalf("changed immutable journal was accepted after activation: %v", err)
	}
	after, err := store.Load(ctx)
	if err != nil || len(after.QUICCrashOperations) != 1 || after.QUICCrashOperations[0].HelperConfigSHA256 != changedDigest {
		t.Fatalf("admission tried to rewrite changed evidence: %v", err)
	}
}
