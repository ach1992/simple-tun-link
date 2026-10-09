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

func TestGREEncapsulationPortValidation(t *testing.T) {
	id, _ := NewLinkID()
	base := Link{
		ID:        id,
		Underlay:  Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("198.51.100.20")},
		Addresses: LinkAddresses{Local: netip.MustParsePrefix("10.80.20.0/31"), Peer: netip.MustParsePrefix("10.80.20.1/31")},
		Backend:   BackendGRE,
	}
	cases := []struct {
		name string
		link Link
	}{
		{"native_with_udp_port", func() Link { l := base; l.Encapsulation = EncapNative; l.GRE.UDPPort = 5555; return l }()},
		{"fou_without_udp_port", func() Link { l := base; l.Encapsulation = EncapFOU; return l }()},
		{"gue_without_udp_port", func() Link { l := base; l.Encapsulation = EncapGUE; return l }()},
		{"unkeyed_with_key_value", func() Link { l := base; l.Encapsulation = EncapNative; l.GRE.Key = 7; return l }()},
		{"fixed_ttl_with_disabled_pmtud", func() Link {
			l := base
			l.Encapsulation = EncapNative
			l.GRE.TTL = 64
			l.GRE.DisablePMTUD = true
			return l
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.link.Validate(); err == nil {
				t.Fatal("invalid GRE configuration accepted")
			}
		})
	}
}
