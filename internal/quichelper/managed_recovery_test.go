package quichelper

import (
	"context"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/hostidentity"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestManagedRecoveryNeverTreatsSourceReceiptSameBootOrFabricationAsAuthority(t *testing.T) {
	for _, change := range []string{"source-only", "same-boot", "not-stored", "different-nonce", "untrusted-boot"} {
		t.Run(change, func(t *testing.T) {
			f := newManagedHostFixture(t)
			op := f.op
			metadata := *op.Managed
			op.Managed = &metadata
			calls := 0
			f.host.ops.inspect = func(context.Context, unitSpec) (managedUnitObservation, error) {
				calls++
				return managedUnitObservation{}, nil
			}
			switch change {
			case "source-only":
				op.Managed = nil
			case "not-stored":
				f.store.snapshot.QUICCrashOperations = nil
			case "different-nonce":
				op.Nonce = strings.Repeat("c", 32)
			case "untrusted-boot":
				op.Managed.KernelBootSource = "untrusted"
			}
			if err := f.host.VerifyRecoveryHostAbsent(context.Background(), op); err == nil {
				t.Fatal("invalid recovery witness passed")
			}
			if calls != 0 || f.starts != 0 || f.stops != 0 {
				t.Fatal("invalid recovery advanced to unit inspection or effects")
			}
		})
	}
}

func TestManagedRecoveryRequiresCurrentVacancyEvenAfterRealLifetimeBoundary(t *testing.T) {
	for _, receiptMode := range []bool{false, true} {
		f := newManagedHostFixture(t)
		f.identity.BootID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		if receiptMode {
			f.store.snapshot.QUICCrashOperations = nil
			f.store.snapshot.QUICAbandonmentReceipts = []state.QUICAbandonmentReceipt{{Operation: f.op, Files: materialFiles(f.material.identity),
				ReconciledKernelBootID: f.identity.BootID, ReconciledKernelBootSource: hostidentity.VerifiedHostBootSourceV1}}
		}
		f.loaded = true // Any loaded unit blocks; no adoption or stop is allowed.
		if err := f.host.VerifyRecoveryHostAbsent(context.Background(), f.op); err == nil {
			t.Fatal("loaded helper was ignored after boot boundary")
		}
		if f.starts != 0 || f.stops != 0 || f.material.closed {
			t.Fatal("read-only recovery changed a process or material")
		}
		f.loaded = false // The still-present guard independently blocks before WG queries.
		if err := f.host.VerifyRecoveryHostAbsent(context.Background(), f.op); err == nil {
			t.Fatal("remaining ingress guard was ignored")
		}
	}
}

func TestManagedOldBootJournalCannotReplayIntoNewEffectScope(t *testing.T) {
	f := newManagedHostFixture(t)
	f.identity.BootID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if _, release, err := f.host.Begin(f.context(t), f.link, nil); err == nil {
		release()
		t.Fatal("old operation journal was replayed into a later boot")
	}
	if f.starts != 0 || f.stops != 0 {
		t.Fatal("old-boot refusal performed an effect")
	}
}
