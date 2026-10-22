package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/state"
)

const testWSSBootBefore = "11111111-1111-4111-8111-111111111111"
const testWSSBootAfter = "22222222-2222-4222-8222-222222222222"

// New Engine + FileStore + lock manager emulate a NEW process against the
// same durable protected directory after a kernel reboot, not a context
// proof surviving across process memory.
func restartedWSSRecoveryEngine(t *testing.T, root string, host *crashWSSBackend,
	boot string) (*Engine, *state.FileStore) {
	t.Helper()
	registry, err := backend.NewRegistry(host)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	e, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	e.SetWSSRetirementStore(fakeWSSIssuance{})
	e.kernelBootID = func() (string, error) { return boot, nil }
	host.store = store
	return e, store
}

func TestWSSColdBootManualCheckpointAndRecoveryAcrossFreshProcesses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		committed bool
		remove    bool
	}{
		{"initial-ensure", false, false},
		{"committed-repair", true, false},
		{"committed-remove", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			host := &crashWSSBackend{fakeBackend: newFakeBackend()}
			before, store := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
			link := journalTestLink(t)
			var original state.LinkRecord
			if tc.committed {
				if _, err := before.Ensure(ctx, link); err != nil {
					t.Fatal(err)
				}
				original, _ = mustLoadCrashSnapshot(t, store).Find(link.ID)
			}
			if tc.committed && !tc.remove {
				delete(host.present, link.ID)
			}
			host.crashAfterHost = true
			if tc.remove {
				causeCrash(t, func() { _, _ = before.Remove(ctx, link.ID) })
			} else {
				causeCrash(t, func() { _, _ = before.Ensure(ctx, link) })
			}
			pending, exists := mustLoadCrashSnapshot(t, store).FindWSSCrashOperation(link.ID)
			if !exists || pending.ColdBootArmedFrom != "" {
				t.Fatal("pre-effect journal was not retained before explicit recovery arm")
			}
			if err := before.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
				t.Fatal("unarmed journal permitted cold-boot recovery")
			}
			if err := before.ArmWSSColdBootRecovery(ctx, link.ID); err != nil {
				t.Fatal(err)
			}
			armed, exists := mustLoadCrashSnapshot(t, store).FindWSSCrashOperation(link.ID)
			if !exists || armed.ColdBootArmedFrom != testWSSBootBefore ||
				!reflect.DeepEqual(armed.Intent, pending.Intent) ||
				!reflect.DeepEqual(armed.Resources, pending.Resources) {
				t.Fatal("arming mutated original intent/claims or lost protected checkpoint")
			}
			if err := before.ArmWSSColdBootRecovery(ctx, link.ID); err != nil {
				t.Fatalf("identical cold boot re-arm should be idempotent: %v", err)
			}
			if err := before.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
				t.Fatal("same kernel boot falsely certified old WireGuard extinction")
			}
			// Fresh Engine and State reader after a simulated kernel generation
			// transition; intentionally retain host observations to reject
			// even true reboot when a NEW resource now conflicts.
			after, refreshed := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
			// The old kernel is gone, but an independently created current-
			// boot replacement can still occupy the same reserved identity.
			host.present[link.ID] = nil
			if err := after.ArmWSSColdBootRecovery(ctx, link.ID); err == nil {
				t.Fatal("re-arming after reboot overwrote single-use checkpoint")
			}
			if err := after.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
				t.Fatal("new/live unverified host object was adopted after reboot")
			}
			if _, exists := mustLoadCrashSnapshot(t, refreshed).FindWSSCrashOperation(link.ID); !exists {
				t.Fatal("foreign/live resource was not quarantined")
			}
			delete(host.present, link.ID) // independently confirmed gone after boot
			if err := after.ReconcileWSSCrashColdBoot(ctx, link.ID); err != nil {
				t.Fatalf("fresh-process, new-kernel-boot original recovery: %v", err)
			}
			result := mustLoadCrashSnapshot(t, refreshed)
			if _, exists := result.FindWSSCrashOperation(link.ID); exists {
				t.Fatal("atomic verified recovery did not consume original journal")
			}
			if tc.remove {
				if _, exists := result.Find(link.ID); exists {
					t.Fatal("removed original owner still committed")
				}
				receipt, exists := result.FindRemovalReceipt(link.ID)
				if !exists || receipt.Retired || receipt.WSSFiles != original.WSSFiles {
					t.Fatal("original credential-bound removal receipt missing")
				}
				if err := after.RetireWSSCredential(ctx, link.ID); err != nil {
					t.Fatal(err)
				}
			} else if tc.committed {
				committed, exists := result.Find(link.ID)
				if !exists || !reflect.DeepEqual(committed, original) {
					t.Fatal("committed repair lost original Link, nonce or credentials")
				}
			} else {
				if _, exists := result.Find(link.ID); exists {
					t.Fatal("uncommitted initial Ensure was fabricated")
				}
			}
			if err := after.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
				t.Fatal("repeat recovery consumed a journal twice")
			}
		})
	}
}

func TestWSSColdBootRecoveryDeniesDriftedCredentialsAndForgedBoots(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	before, store := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
	link := journalTestLink(t)
	if _, err := before.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	host.crashAfterHost = true
	causeCrash(t, func() { _, _ = before.Remove(ctx, link.ID) })
	if err := before.ArmWSSColdBootRecovery(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	delete(host.present, link.ID)
	for _, bad := range []string{"", "not-a-kernel-uuid", "00000000-0000-0000-0000-000000000000", testWSSBootBefore} {
		b, _ := restartedWSSRecoveryEngine(t, root, host, bad)
		if err := b.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
			t.Fatalf("forged/same/missing kernel boot %q permitted clearance", bad)
		}
	}
	b, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	b.SetWSSRetirementStore(driftedWSSIssuance{})
	if err := b.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
		t.Fatal("original issued TLS/bearer fingerprint mismatch permitted retirement")
	}
	if _, found := mustLoadCrashSnapshot(t, store).FindWSSCrashOperation(link.ID); !found {
		t.Fatal("invalid boot/credential attempts mutated protected journal")
	}
	b.SetWSSRetirementStore(fakeWSSIssuance{})
	b.kernelBootID = func() (string, error) { return "", errors.New("host proc unavailable") }
	if err := b.ReconcileWSSCrashColdBoot(ctx, link.ID); err == nil {
		t.Fatal("unavailable kernel identity permitted recovery")
	}
	b.kernelBootID = func() (string, error) { return testWSSBootAfter, nil }
	if err := b.ReconcileWSSCrashColdBoot(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
}

func TestWSSColdBootStateCheckpointIntegrity(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	e, store := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
	link := journalTestLink(t)
	host.crashAfterHost = true
	causeCrash(t, func() { _, _ = e.Ensure(ctx, link) })
	if err := e.ArmWSSColdBootRecovery(ctx, link.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		for i := range s.WSSCrashOperations {
			if s.WSSCrashOperations[i].Intent.ID == link.ID {
				s.WSSCrashOperations[i].ColdBootArmedFrom = "wrong-format"
			}
		}
		return nil
	}); err == nil || !strings.Contains(err.Error(), "cold-boot") {
		t.Fatalf("tampered boot checkpoint was accepted: %v", err)
	}
}
