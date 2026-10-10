package domain

import (
	"bytes"
	"encoding/base64"
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

func TestIPIPEncapsulationAndUnderlayValidation(t *testing.T) {
	link := Link{
		ID: LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Underlay: Underlay{
			Local: netip.MustParseAddr("192.0.2.10"),
			Peer:  netip.MustParseAddr("198.51.100.20"),
		},
		Addresses: LinkAddresses{
			Local: netip.MustParsePrefix("10.80.20.0/31"),
			Peer:  netip.MustParsePrefix("10.80.20.1/31"),
		},
		Backend: BackendIPIP,
	}
	for _, encap := range []Encapsulation{EncapNative, EncapFOU, EncapGUE} {
		link.Encapsulation = encap
		if err := link.Validate(); err != nil {
			t.Fatalf("supported IPIP encapsulation %s rejected: %v", encap, err)
		}
	}
	link.Encapsulation = EncapUDP
	if err := link.Validate(); err == nil {
		t.Fatal("unsupported IPIP encapsulation accepted")
	}
	link.Encapsulation = EncapNative
	link.Underlay.Local = netip.MustParseAddr("2001:db8::1")
	if err := link.Validate(); err == nil {
		t.Fatal("IPv6 IPIP underlay accepted in v0.1")
	}
}

func TestWireGuardPublicOptionsAndBackendIsolation(t *testing.T) {
	a := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	b := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	link := Link{
		ID:      LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Backend: BackendWireGuard, Encapsulation: EncapUDP,
		Underlay:  Underlay{Local: netip.MustParseAddr("192.0.2.10"), Peer: netip.MustParseAddr("198.51.100.20")},
		Addresses: LinkAddresses{Local: netip.MustParsePrefix("10.80.20.0/31"), Peer: netip.MustParsePrefix("10.80.20.1/31")},
		WireGuard: WireGuardOptions{LocalPublicKey: a, PeerPublicKey: b, ListenPort: 51820, PeerPort: 51821, PeerKeepalive: 25},
	}
	if err := link.Validate(); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		edit func(*Link)
	}{
		{"same keys", func(l *Link) { l.WireGuard.PeerPublicKey = a }},
		{"missing peer public key", func(l *Link) { l.WireGuard.PeerPublicKey = "" }},
		{"noncanonical peer public key", func(l *Link) { l.WireGuard.PeerPublicKey = b[:len(b)-1] }},
		{"all-zero public key", func(l *Link) { l.WireGuard.PeerPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"wrong encapsulation", func(l *Link) { l.Encapsulation = EncapNative }},
		{"wireguard options on GRE", func(l *Link) { l.Backend = BackendGRE; l.Encapsulation = EncapNative }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			bad := link
			tc.edit(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("unsafe WireGuard identity accepted")
			}
		})
	}
	// Old WireGuard offers without public options can still be decoded for
	// redacted previews, but the v2 pairing exporter refuses new such offers.
	legacy := link
	legacy.WireGuard = WireGuardOptions{}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy preview-only Link was discarded: %v", err)
	}
}
