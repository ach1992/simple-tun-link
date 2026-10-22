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
