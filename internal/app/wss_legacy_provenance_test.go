package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
)

const testWSSBootThird = "33333333-3333-4333-8333-333333333333"

// Old or unsupported-host WSS Links have real, committed original kernel
// objects and protected credentials, but no trusted historical birth source.
func legacyWSSWithVisibleOriginal(t *testing.T) (context.Context, string, *crashWSSBackend, *Engine, *state.FileStore, domain.Link, state.LinkRecord) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	before, store := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
	before.kernelBootID = func() (string, error) { return "", hostidentity.ErrUntrustedKernelBootSource }
	link := journalTestLink(t)
	if _, err := before.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	original, ok := mustLoadCrashSnapshot(t, store).Find(link.ID)
	if !ok || original.WSSKernelBootID != "" || original.WSSKernelBootSource != "" {
		t.Fatal("initial unsupported host invented trusted original birth provenance")
	}
	return ctx, root, host, before, store, link, original
}

func TestWSSLegacyVisibleOriginalNeverPromotedByOrdinaryEnsure(t *testing.T) {
	for _, tc := range []struct {
		name string
		boot string
	}{
		{"later-trusted-native-source", testWSSBootBefore},
		{"different-trusted-generation-observation", testWSSBootAfter},
		{"still-untrusted-source", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, root, host, _, store, link, original := legacyWSSWithVisibleOriginal(t)
			e, _ := restartedWSSRecoveryEngine(t, root, host, tc.boot)
			if tc.boot == "" {
				e.kernelBootID = func() (string, error) { return "", errors.New("untrusted host") }
			}
			initial := mustLoadCrashSnapshot(t, store)
			applies := host.applyCount
			result, err := e.Ensure(ctx, link)
			if err != nil || result.Changed {
				t.Fatalf("idempotent original unexpectedly changed or failed: result=%+v err=%v", result, err)
			}
			if host.applyCount != applies || !reflect.DeepEqual(mustLoadCrashSnapshot(t, store), initial) {
				t.Fatal("ordinary no-op promoted legacy birth, changed State or reapplied original")
			}
			// Sidecar repair with a live, exact original must also never
			// re-attest its historical birth from the current host.
			host.present[link.ID] = []domain.ResourceClaim{}
			if _, err := e.Ensure(ctx, link); err != nil {
				t.Fatalf("live-original sidecar repair: %v", err)
			}
			after, ok := mustLoadCrashSnapshot(t, store).Find(link.ID)
			if !ok || after.WSSKernelBootID != "" || after.WSSKernelBootSource != "" ||
				after.WSSOrigin != original.WSSOrigin || after.WSSFiles != original.WSSFiles ||
				!reflect.DeepEqual(after.OwnedResources, original.OwnedResources) {
				t.Fatal("sidecar repair changed original provenance or committed identity")
			}
			delete(host.present, link.ID) // moved DOWN to a hidden namespace
			denied := mustLoadCrashSnapshot(t, store)
			applies = host.applyCount
			for name, operation := range map[string]func() error{
				"ensure":  func() error { _, err := e.Ensure(ctx, link); return err },
				"restore": func() error { _, err := e.RestoreAll(ctx); return err },
				"remove":  func() error { _, err := e.Remove(ctx, link.ID); return err },
			} {
				if err := operation(); err == nil {
					t.Fatalf("%s recreated or retired a legacy missing original", name)
				}
				if host.applyCount != applies || !reflect.DeepEqual(mustLoadCrashSnapshot(t, store), denied) {
					t.Fatalf("%s changed a missing original or protected State", name)
				}
			}
		})
	}
}

// The positive path is an Arm with the old host's verified source, a real
// (simulated only here) kernel-generation transition, strict reconciled
// vacancy and a one-use proof consumed before restored host effects.
func prepareLegacyColdBootRestore(t *testing.T) (context.Context, string, *crashWSSBackend, *Engine, *state.FileStore, domain.Link, state.LinkRecord) {
	t.Helper()
	ctx, root, host, before, store, link, original := legacyWSSWithVisibleOriginal(t)
	// Make a REAL durable committed-repair journal by crashing after Apply.
	// This is not a fabricated/synthetic journal inserted into State.
	host.present[link.ID] = []domain.ResourceClaim{}
	host.crashAfterHost = true
	causeCrash(t, func() { _, _ = before.Ensure(ctx, link) })
	if _, ok := mustLoadCrashSnapshot(t, store).FindWSSCrashOperation(link.ID); !ok {
		t.Fatal("legitimate committed original crash journal missing")
	}
	// A legacy journal cannot be cleared into a non-restorable Link.
	if err := before.ReconcileWSSCrashRepairVacant(ctx, link.ID); err == nil {
		t.Fatal("legacy repair journal was consumed without original extinction proof")
	}
	before.kernelBootID = func() (string, error) { return testWSSBootBefore, nil }
	if err := before.ArmWSSColdBootRecovery(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	// A real full-host reboot destroys the old namespace WG; the fake
	// current-host inventory is explicitly cleared after the phase change.
	delete(host.present, link.ID)
	after, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	if err := after.ReconcileWSSCrashColdBoot(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	snapshot := mustLoadCrashSnapshot(t, store)
	rec, ok := snapshot.Find(link.ID)
	if !ok || rec.Desired != original.Desired ||
		rec.WSSOrigin != original.WSSOrigin || rec.WSSFiles != original.WSSFiles ||
		!reflect.DeepEqual(rec.OwnedResources, original.OwnedResources) ||
		rec.WSSKernelBootID != "" || rec.WSSKernelBootSource != "" {
		t.Fatal("cold-boot repair forged original birth or changed committed owner")
	}
	want := state.WSSColdBootRestore{
		ArmedFrom: testWSSBootBefore, ReconciledAt: testWSSBootAfter,
		Source: hostidentity.VerifiedHostBootSourceV1,
	}
	if rec.WSSColdBootRestore != want {
		t.Fatalf("missing scoped one-use recovery proof: %+v", rec.WSSColdBootRestore)
	}
	if _, pending := snapshot.FindWSSCrashOperation(link.ID); pending {
		t.Fatal("manual reconciliation did not atomically consume its original journal")
	}
	return ctx, root, host, after, store, link, original
}

func TestWSSLegacyColdBootRepairRestoresOnlyNewOriginalGeneration(t *testing.T) {
	ctx, root, host, after, store, link, original := prepareLegacyColdBootRestore(t)
	saved := mustLoadCrashSnapshot(t, store)
	applies := host.applyCount
	// An apparently matching current-boot original cannot be adopted by
	// virtue of a previously empty reconciliation.
	host.present[link.ID] = []domain.ResourceClaim{}
	if _, err := after.RestoreAll(ctx); err == nil {
		t.Fatal("foreign or unexpected original was adopted after manual recovery")
	}
	if host.applyCount != applies || !reflect.DeepEqual(saved, mustLoadCrashSnapshot(t, store)) {
		t.Fatal("unexpected visible original consumed recovery proof")
	}
	delete(host.present, link.ID)
	// The manual authority is for Ensure/Restore only, not deletion or
	// issuance of a credential retirement receipt.
	if _, err := after.Remove(ctx, link.ID); err == nil {
		t.Fatal("manual restore proof was misused to retire a missing original")
	}
	if err := after.RetireWSSCredential(ctx, link.ID); err == nil {
		t.Fatal("manual restore proof was misused as a retirement receipt")
	}
	result, err := after.RestoreAll(ctx)
	if err != nil || len(result) != 1 || !result[0].Changed {
		t.Fatalf("authorized recovered original not created: %+v %v", result, err)
	}
	committed := mustLoadCrashSnapshot(t, store)
	restored, ok := committed.Find(link.ID)
	if !ok || restored.WSSKernelBootID != testWSSBootAfter ||
		restored.WSSKernelBootSource != hostidentity.VerifiedHostBootSourceV1 ||
		restored.WSSColdBootRestore != (state.WSSColdBootRestore{}) ||
		restored.WSSOrigin != original.WSSOrigin || restored.WSSFiles != original.WSSFiles ||
		!reflect.DeepEqual(restored.OwnedResources, original.OwnedResources) {
		t.Fatal("verified NEW kernel generation not bound to retained original identity")
	}
	if _, pending := committed.FindWSSCrashOperation(link.ID); pending {
		t.Fatal("successful restore failed to consume replacement crash journal")
	}
	reread, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	beforeNoop := mustLoadCrashSnapshot(t, store)
	noChange, err := reread.Ensure(ctx, link)
	if err != nil || noChange.Changed || !reflect.DeepEqual(beforeNoop, mustLoadCrashSnapshot(t, store)) {
		t.Fatal("subsequent idempotent Ensure unexpectedly altered restored generation")
	}
}

func TestWSSLegacyColdBootRestoreWitnessSpentBeforeHostEffect(t *testing.T) {
	ctx, root, host, after, store, link, original := prepareLegacyColdBootRestore(t)
	host.crashAfterHost = true
	causeCrash(t, func() { _, _ = after.RestoreAll(ctx) })
	incomplete := mustLoadCrashSnapshot(t, store)
	pending, exists := incomplete.FindWSSCrashOperation(link.ID)
	rec, ok := incomplete.Find(link.ID)
	if !exists || !ok || !pending.HadCommittedLink || pending.Operation != "ensure" ||
		!rec.WSSColdBootRestore.Spent || rec.WSSKernelBootID != "" ||
		rec.WSSOrigin != original.WSSOrigin || rec.WSSFiles != original.WSSFiles {
		t.Fatal("interruptible restore did not durably spend its old-kernel witness with pre-effect journal")
	}
	fresh, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	applies := host.applyCount
	for _, operation := range []func() error{
		func() error { _, err := fresh.RestoreAll(ctx); return err },
		func() error { _, err := fresh.Ensure(ctx, link); return err },
		func() error { return fresh.ReconcileWSSCrashRepairVacant(ctx, link.ID) },
		func() error { _, err := fresh.Remove(ctx, link.ID); return err },
	} {
		if err := operation(); err == nil {
			t.Fatal("crashed restore reused spent proof or consumed critical journal")
		}
		if host.applyCount != applies || !reflect.DeepEqual(incomplete, mustLoadCrashSnapshot(t, store)) {
			t.Fatal("rejected replay changed protected State or applied host effects")
		}
	}
	// The original manual recovery path stays available after a separate
	// additional authorized host-kernel reboot, rather than rearming an
	// already spent witness in the same generation.
	if err := fresh.ArmWSSColdBootRecovery(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	afterArm, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	if err := afterArm.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
		t.Fatal("same-kernel cold-boot replay admitted")
	}
	delete(host.present, link.ID)
	nextBoot, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootThird)
	if err := nextBoot.ReconcileWSSCrashColdBoot(ctx, link.ID); err != nil {
		t.Fatalf("separately rearmed later real-kernel transition not recoverable: %v", err)
	}
	renewed, ok := mustLoadCrashSnapshot(t, store).Find(link.ID)
	if !ok || renewed.WSSColdBootRestore.Spent || renewed.WSSColdBootRestore.ArmedFrom != testWSSBootAfter ||
		renewed.WSSColdBootRestore.ReconciledAt != testWSSBootThird {
		t.Fatal("new attested cold-boot phase did not issue fresh bounded authorization")
	}
	if _, err := nextBoot.RestoreAll(ctx); err != nil {
		t.Fatalf("future separately admitted recovery still blocked: %v", err)
	}
	if record, exists := mustLoadCrashSnapshot(t, store).Find(link.ID); !exists ||
		record.WSSKernelBootID != testWSSBootThird || record.WSSColdBootRestore != (state.WSSColdBootRestore{}) {
		t.Fatal("separate approved kernel transition did not restore live source provenance")
	}
}

func TestWSSLegacyColdBootRestoreRejectsUntrustedCurrentBoot(t *testing.T) {
	ctx, root, host, _, store, _, _ := prepareLegacyColdBootRestore(t)
	before := mustLoadCrashSnapshot(t, store)
	for _, bad := range []string{"", testWSSBootBefore} {
		e, _ := restartedWSSRecoveryEngine(t, root, host, bad)
		if _, err := e.RestoreAll(ctx); err == nil {
			t.Fatalf("original/untrusted kernel %q used manual recovery proof: %v", bad, err)
		}
		if !reflect.DeepEqual(before, mustLoadCrashSnapshot(t, store)) {
			t.Fatal("untrusted boot consumed protected restore proof")
		}
	}
}

// Exact original-object compensation is still useful on an unsupported host.
// It must remove only confirmed original objects while retaining the last
// legacy journal for a later trusted manual kernel-reset continuation.
func TestWSSLegacyOriginalCompensationRetainsManualColdBootCheckpoint(t *testing.T) {
	ctx, root, host, originalEngine, store, link, original := legacyWSSWithVisibleOriginal(t)
	host.present[link.ID] = []domain.ResourceClaim{}
	host.crashAfterHost = true
	causeCrash(t, func() { _, _ = originalEngine.Ensure(ctx, link) })
	start := mustLoadCrashSnapshot(t, store)
	journal, pending := start.FindWSSCrashOperation(link.ID)
	if !pending || !journal.HadCommittedLink || journal.Operation != "ensure" {
		t.Fatal("original interrupted committed repair journal not durably published")
	}
	if err := originalEngine.ReconcileWSSCrashOriginal(ctx, link.ID); err != nil {
		t.Fatalf("positive scoped original compensation denied: %v", err)
	}
	if host.recoveryCount != 1 {
		t.Fatal("precise original-object deletion was skipped")
	}
	cleared := mustLoadCrashSnapshot(t, store)
	kept, exists := cleared.FindWSSCrashOperation(link.ID)
	rec, committed := cleared.Find(link.ID)
	if !exists || !committed || !reflect.DeepEqual(kept, journal) ||
		!reflect.DeepEqual(rec, original) || len(cleared.RemovalReceipts) != 0 {
		t.Fatal("compensating legacy original discarded its only viable recovery journal or altered identity")
	}
	if _, visible := host.present[link.ID]; visible {
		t.Fatal("scoped host compensation did not remove the original object")
	}
	for _, retry := range []func() error{
		func() error { return originalEngine.ReconcileWSSCrashOriginal(ctx, link.ID) },
		func() error { return originalEngine.ReconcileWSSCrashRepairVacant(ctx, link.ID) },
		func() error { _, err := originalEngine.RestoreAll(ctx); return err },
		func() error { _, err := originalEngine.Remove(ctx, link.ID); return err },
	} {
		if err := retry(); err == nil {
			t.Fatal("compensated same-kernel legacy original was replayed or journal released")
		}
		if next := mustLoadCrashSnapshot(t, store); !reflect.DeepEqual(next, cleared) {
			t.Fatal("denial changed original Link/journal/credentials")
		}
	}
	arm, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
	if err := arm.ArmWSSColdBootRecovery(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	after, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	if err := after.ReconcileWSSCrashColdBoot(ctx, link.ID); err != nil {
		t.Fatalf("trusted later manual recovery was stranded after compensated original: %v", err)
	}
	authorized, ok := mustLoadCrashSnapshot(t, store).Find(link.ID)
	if !ok || authorized.WSSColdBootRestore == (state.WSSColdBootRestore{}) ||
		authorized.WSSKernelBootSource != "" || authorized.WSSOrigin != original.WSSOrigin {
		t.Fatal("trusted recovery forged original birth or lost explicit one-use restore authority")
	}
	if _, err := after.RestoreAll(ctx); err != nil {
		t.Fatalf("approved future original recreation still blocked: %v", err)
	}
	restored, ok := mustLoadCrashSnapshot(t, store).Find(link.ID)
	if !ok || restored.WSSKernelBootID != testWSSBootAfter ||
		restored.WSSColdBootRestore != (state.WSSColdBootRestore{}) ||
		restored.WSSFiles != original.WSSFiles || restored.WSSOrigin != original.WSSOrigin {
		t.Fatal("original generation or protected issuance identity was not restored")
	}
}
