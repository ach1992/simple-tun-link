package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Models an original committed WG moved to another namespace and left DOWN.
// Its birthplace interface and UDP socket disappear, even while the same
// original kernel object remains live and can later be raised again.
func TestWSSOrdinaryCommittedMissingOriginalNeverRecreatesOrRetiresSameKernel(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	original, store := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
	link := journalTestLink(t)
	if _, err := original.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	saved := mustLoadCrashSnapshot(t, store)
	record, exists := saved.Find(link.ID)
	if !exists || record.WSSKernelBootID != testWSSBootBefore || record.WSSKernelBootSource != hostidentity.VerifiedHostBootSourceV1 {
		t.Fatal("original WSS committed Link not bound to verified birth generation")
	}
	originalHostResources := append([]domain.ResourceClaim(nil), host.present[link.ID]...)
	delete(host.present, link.ID) // migrated-DOWN original remains alive in another namespace
	calls := host.applyCount
	for name, attempt := range map[string]func() error{
		"ordinary-ensure":        func() error { _, err := original.Ensure(ctx, link); return err },
		"restore-all":            func() error { _, err := original.RestoreAll(ctx); return err },
		"first-remove":           func() error { _, err := original.Remove(ctx, link.ID); return err },
		"retire-without-receipt": func() error { return original.RetireWSSCredential(ctx, link.ID) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := attempt(); err == nil {
				t.Fatal("missing same-kernel original granted automatic mutation")
			}
			if host.applyCount != calls {
				t.Fatal("denied operation reached host backend Apply")
			}
			if next := mustLoadCrashSnapshot(t, store); !reflect.DeepEqual(next, saved) {
				t.Fatal("denial altered original owner, reservations, journal, receipt or fingerprints")
			}
		})
	}
	// Visibility returning in the original namespace cannot retroactively
	// authorize the earlier rejected retirement/recreation.
	host.present[link.ID] = originalHostResources
	if _, err := original.Ensure(ctx, link); err != nil {
		t.Fatalf("same trusted original visible again but idempotent Ensure failed: %v", err)
	}
	if host.applyCount != calls {
		t.Fatal("visible idempotent original was recreated")
	}
	if !reflect.DeepEqual(saved, mustLoadCrashSnapshot(t, store)) {
		t.Fatal("reappearing original changed owner identity")
	}
}

func TestWSSOrdinaryTrustedNewKernelRestoreAndRemoval(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	before, store := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
	link := journalTestLink(t)
	if _, err := before.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	prior, _ := mustLoadCrashSnapshot(t, store).Find(link.ID)
	delete(host.present, link.ID) // extinct after simulated genuinely new kernel
	after, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	if _, err := after.RestoreAll(ctx); err != nil {
		t.Fatalf("trusted post-reboot restore blocked: %v", err)
	}
	restored, _ := mustLoadCrashSnapshot(t, store).Find(link.ID)
	if restored.WSSKernelBootID != testWSSBootAfter || restored.WSSKernelBootSource != hostidentity.VerifiedHostBootSourceV1 ||
		restored.WSSOrigin != prior.WSSOrigin || restored.WSSFiles != prior.WSSFiles || !reflect.DeepEqual(restored.OwnedResources, prior.OwnedResources) {
		t.Fatal("genuine-generation restore did not update generation while preserving original identity")
	}
	if _, err := after.Remove(ctx, link.ID); err != nil {
		t.Fatalf("exact-index ordinary Remove failed: %v", err)
	}
	receipt, found := mustLoadCrashSnapshot(t, store).FindRemovalReceipt(link.ID)
	if !found || !receipt.Retired || receipt.WSSOriginalTermination != state.WSSOriginalExactIfIndexDeleted {
		t.Fatal("ordinary exact-index Remove did not persist its own termination proof")
	}
}

func TestWSSOrdinaryTrustedExtinctEmptyOriginalRemoveAndLegacyReceiptDenial(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	before, store := restartedWSSRecoveryEngine(t, root, host, testWSSBootBefore)
	link := journalTestLink(t)
	if _, err := before.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	delete(host.present, link.ID)
	after, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	if _, err := after.Remove(ctx, link.ID); err != nil {
		t.Fatalf("trusted original kernel extinction did not permit strict empty-host Remove: %v", err)
	}
	receipt, ok := mustLoadCrashSnapshot(t, store).FindRemovalReceipt(link.ID)
	if !ok || receipt.WSSOriginalTermination != state.WSSOriginalKernelGenerationExtinct {
		t.Fatal("post-reboot empty original receipt missing authenticated kernel-generation proof")
	}
	// Model an older receipt without any origin-termination contract. Even
	// though local host inventories are empty, it cannot authorize credential
	// retirement in the new implementation.
	if err := store.Update(ctx, func(s *state.Snapshot) error {
		for i := range s.RemovalReceipts {
			if s.RemovalReceipts[i].LinkID == link.ID {
				s.RemovalReceipts[i].Retired = false
				s.RemovalReceipts[i].WSSOriginalTermination = ""
				return nil
			}
		}
		return errors.New("expected exact WSS receipt")
	}); err != nil {
		t.Fatal(err)
	}
	legacy := mustLoadCrashSnapshot(t, store)
	if err := after.RetireWSSCredential(ctx, link.ID); err == nil {
		t.Fatal("legacy receipt retired private WSS material")
	}
	if !reflect.DeepEqual(legacy, mustLoadCrashSnapshot(t, store)) {
		t.Fatal("legacy receipt denial changed durable State")
	}
}

func TestWSSOrdinaryLegacyUntrustedBirthNeverClaimsOldKernelExtinct(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	host := &crashWSSBackend{fakeBackend: newFakeBackend()}
	registry, err := backend.NewRegistry(host)
	if err != nil {
		t.Fatal(err)
	}
	store := state.NewFileStore(root)
	before, err := New(registry, store, state.NewLockManager(root))
	if err != nil {
		t.Fatal(err)
	}
	before.SetWSSRetirementStore(fakeWSSIssuance{})
	before.kernelBootID = func() (string, error) { return "", hostidentity.ErrUntrustedKernelBootSource }
	host.store = store
	link := journalTestLink(t)
	if _, err := before.Ensure(ctx, link); err != nil {
		t.Fatal(err)
	}
	saved := mustLoadCrashSnapshot(t, store)
	record, _ := saved.Find(link.ID)
	if record.WSSKernelBootID != "" || record.WSSKernelBootSource != "" {
		t.Fatal("untrusted kernel source minted birth-generation credential")
	}
	delete(host.present, link.ID)
	after, _ := restartedWSSRecoveryEngine(t, root, host, testWSSBootAfter)
	for _, operation := range []func() error{
		func() error { _, err := after.Ensure(ctx, link); return err },
		func() error { _, err := after.RestoreAll(ctx); return err },
		func() error { _, err := after.Remove(ctx, link.ID); return err },
	} {
		if err := operation(); err == nil {
			t.Fatal("legacy untrusted birth allowed original extinction")
		}
	}
	if !reflect.DeepEqual(saved, mustLoadCrashSnapshot(t, store)) {
		t.Fatal("legacy birth denial changed original State")
	}
}
