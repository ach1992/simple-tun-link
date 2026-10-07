package linux

import (
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestOwnerTagRoundTrip(t *testing.T) {
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	tag, err := OwnerTag(id)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ParseOwnerTag(tag)
	if !ok || got != id {
		t.Fatalf("ParseOwnerTag(%q) = %q, %v; want %q, true", tag, got, ok, id)
	}
}

func TestRequireOwnedRequiresExactIdentityNotOverlap(t *testing.T) {
	id, _ := domain.NewLinkID()
	owned := []domain.ResourceClaim{{Kind: domain.ResourceLinkSubnet, Key: "10.80.20.0/31"}}
	if err := RequireOwned(id, owned[0], owned); err != nil {
		t.Fatalf("exact ownership rejected: %v", err)
	}
	overlapping := domain.ResourceClaim{Kind: domain.ResourceLinkAddress, Key: "10.80.20.1"}
	if err := RequireOwned(id, overlapping, owned); err == nil {
		t.Fatal("overlapping resource was incorrectly accepted as ownership proof")
	}
}
