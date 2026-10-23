package backend

import (
	"context"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestWSSOriginalDeletionWitnessBindsNonceAndLink(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	other := domain.LinkID("lnk_abcdef0123456789abcdef0123456789")
	if _, err := WithWSSWGDeleted(context.Background(), id); err == nil {
		t.Fatal("guard deletion witness minted without original creation identity")
	}
	original, err := WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	witnessed, err := WithWSSWGDeleted(original, id)
	if err != nil {
		t.Fatal(err)
	}
	if !HasWSSWGDeletionWitness(witnessed, id) ||
		HasWSSWGDeletionWitness(witnessed, other) ||
		HasWSSWGDeletionWitness(original, id) {
		t.Fatal("kernel-deletion proof crossed Link ID or escaped its transaction")
	}
	rotated, err := WithWSSOrigin(witnessed, "ffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	if HasWSSWGDeletionWitness(rotated, id) {
		t.Fatal("kernel-deletion proof survived a changed original-generation nonce")
	}
}

func TestWSSColdBootWitnessIsScopedAndCannotForgeDeletion(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	other := domain.LinkID("lnk_abcdef0123456789abcdef0123456789")
	if _, err := WithWSSColdBootExtinct(context.Background(), id); err == nil {
		t.Fatal("missing original creation nonce allowed cold-boot witness")
	}
	original, err := WithWSSOrigin(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	witnessed, err := WithWSSColdBootExtinct(original, id)
	if err != nil {
		t.Fatal(err)
	}
	if !HasWSSColdBootExtinctionWitness(witnessed, id) ||
		HasWSSColdBootExtinctionWitness(original, id) ||
		HasWSSColdBootExtinctionWitness(witnessed, other) {
		t.Fatal("cold-boot witness crossed original transaction Link identity")
	}
	if HasWSSWGDeletionWitness(witnessed, id) {
		t.Fatal("cold-boot old-generation extinction erroneously authorizes live guard deletion")
	}
	changed, err := WithWSSOrigin(witnessed, "ffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	if HasWSSColdBootExtinctionWitness(changed, id) {
		t.Fatal("cold-boot witness survived changed original generation nonce")
	}
}
