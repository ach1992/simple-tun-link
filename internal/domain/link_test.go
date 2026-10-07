package domain

import (
	"net/netip"
	"testing"
)

func TestNewLinkIDIsStableIdentityShape(t *testing.T) {
	first, err := NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("generated Link IDs collided")
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("generated ID invalid: %v", err)
	}
}

func TestLinkValidateSeparatesUnderlayAndLinkAddresses(t *testing.T) {
	id, _ := NewLinkID()
	link := Link{
		ID: id,
		Underlay: Underlay{
			Local: netip.MustParseAddr("192.0.2.10"),
			Peer:  netip.MustParseAddr("198.51.100.20"),
		},
		Addresses: LinkAddresses{
			Local: netip.MustParsePrefix("10.80.20.0/31"),
			Peer:  netip.MustParsePrefix("10.80.20.1/31"),
		},
		Backend:       BackendGRE,
		Encapsulation: EncapNative,
	}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
}
