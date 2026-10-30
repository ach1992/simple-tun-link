package quicwgorigin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/quicguard"
	"golang.org/x/sys/unix"
)

func TestOriginalWGHelperObservationCarriesExactPrivateFileWitnesses(t *testing.T) {
	root, wg := testInputs(t)
	ops := mockOps(&mockKernel{})
	if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err != nil {
		t.Fatal(err)
	}
	before, err := inspectWithinAdmission(context.Background(), root, testID, testNonce, testPort, wg.LocalPublicKey, ops)
	if err != nil {
		t.Fatal(err)
	}
	var receiptStat, keyStat unix.Stat_t
	if err := unix.Stat(filepath.Join(root, "credentials", receiptDir, receiptName(testID)), &receiptStat); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "credentials", string(testID)+".wgkey")
	if err := unix.Stat(keyPath, &keyStat); err != nil {
		t.Fatal(err)
	}
	guard := originalGuard()
	if before.ReceiptDevice != uint64(receiptStat.Dev) || before.ReceiptInode != receiptStat.Ino ||
		before.GuardReceiptDevice != guard.ReceiptDevice || before.GuardReceiptInode != guard.ReceiptInode ||
		before.KeyDevice != uint64(keyStat.Dev) || before.KeyInode != keyStat.Ino {
		t.Fatal("helper observation omitted exact receipt or key inode evidence")
	}
	// Separate consistent shape checks cannot prove kernel lifetime, but
	// callers can detect same-byte file replacement across helper activation.
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(keyPath, keyPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := inspectWithinAdmission(context.Background(), root, testID, testNonce, testPort, wg.LocalPublicKey, ops)
	if err != nil {
		t.Fatal(err)
	}
	if before == after || before.KeyInode == after.KeyInode || before.IfIndex != after.IfIndex {
		t.Fatal("same-byte key replacement was hidden by equal kernel shape")
	}
}

func TestOriginalWGHelperObservationRejectsGuardReceiptDriftDuringRead(t *testing.T) {
	root, wg := testInputs(t)
	ops := mockOps(&mockKernel{})
	if err := createWithReceipt(context.Background(), root, testID, testNonce, wg, ops); err != nil {
		t.Fatal(err)
	}
	reads := 0
	ops.guard = func(context.Context, string, domain.LinkID, string, uint16) (quicguard.OriginalGuardObservation, error) {
		reads++
		guard := originalGuard()
		if reads == 2 {
			guard.ReceiptInode++
		}
		return guard, nil
	}
	observed, err := inspectWithinAdmission(context.Background(), root, testID, testNonce, testPort, wg.LocalPublicKey, ops)
	if err == nil || observed != (OriginalObservation{}) || reads != 2 {
		t.Fatalf("guard receipt replacement across WG reads was accepted: %+v %v", observed, err)
	}
}
