package main

import (
	"crypto/rand"
	"net/netip"
	"testing"

	spoofcarrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/spoofhost"
)

func TestSpoofLocalNATBindIndependentOfPairingAndOtherEndpoint(t *testing.T) {
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	creatorPrivate, creatorPublic, err := spoofcarrier.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap [32]byte
	if _, err := rand.Read(bootstrap[:]); err != nil {
		t.Fatal(err)
	}
	offer, err := pairing.NewSpoofSetup(id,
		netip.MustParseAddrPort("198.51.100.8:48001"),
		netip.MustParseAddrPort("203.0.113.6:48002"),
		netip.MustParseAddr("10.245.80.1"), netip.MustParseAddr("10.245.80.2"), creatorPublic)
	if err != nil {
		t.Fatal(err)
	}
	offer, err = offer.WithAlternates(
		[]netip.AddrPort{netip.MustParseAddrPort("198.51.100.9:48801")},
		[]netip.AddrPort{netip.MustParseAddrPort("203.0.113.7:48802")})
	if err != nil {
		t.Fatal(err)
	}
	confidential, err := offer.EncodeSensitive()
	if err != nil {
		t.Fatal(err)
	}
	materialA, err := spoofhost.NewMaterial(id, "creator", creatorPrivate, offer.Secret())
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivate, _, err := spoofcarrier.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	materialB, err := spoofhost.NewMaterial(id, "recipient", recipientPrivate, offer.Secret())
	if err != nil {
		t.Fatal(err)
	}
	a, err := spoofLinkFromSetup(offer, materialA, "/root/stl/spoof/sources.txt", "outA", "", 0, 0,
		domain.MTUPolicy{Mode: domain.MTUAuto}, true,
		spoofLocalNetwork{BindIPv4: "10.11.0.3", BindPort: 58001,
			BindAlternates: "10.11.0.4:58801", IngressInterface: "inA"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := spoofLinkFromSetup(offer, materialB, "/root/stl/spoof/sources.txt", "outB", "", 0, 0,
		domain.MTUPolicy{Mode: domain.MTUAuto}, true,
		spoofLocalNetwork{BindIPv4: "10.22.0.6", BindPort: 58002,
			BindAlternates: "10.22.0.7:58802", IngressInterface: "inB"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Underlay.Local.String() != "198.51.100.8" || b.Underlay.Local.String() != "203.0.113.6" ||
		a.Spoof.BindIPv4.String() != "10.11.0.3" || b.Spoof.BindIPv4.String() != "10.22.0.6" ||
		a.Spoof.ListenPort != 48001 || b.Spoof.ListenPort != 48002 ||
		a.Spoof.BindPort != 58001 || b.Spoof.BindPort != 58002 ||
		a.Spoof.Interface != "outA" || b.Spoof.Interface != "outB" ||
		a.Spoof.IngressInterface != "inA" || b.Spoof.IngressInterface != "inB" {
		t.Fatalf("local bind/ingress and advertised endpoints coupled: A=%+v B=%+v", a.Spoof, b.Spoof)
	}
	if a.Spoof.PeerAlternates != "203.0.113.7:48802" ||
		b.Spoof.PeerAlternates != "198.51.100.9:48801" {
		t.Fatal("paired advertised alternate destinations lost")
	}
	roundTrip, err := pairing.DecodeSensitiveSpoofSetup(confidential)
	if err != nil || roundTrip.CreatorEndpoint() != offer.CreatorEndpoint() ||
		roundTrip.RecipientEndpoint() != offer.RecipientEndpoint() {
		t.Fatal("changing local NAT options altered the original confidential Code")
	}
}

func TestSpoofLocalNATInvalidBindingsRejectedBeforeProvision(t *testing.T) {
	id, _ := domain.NewLinkID()
	priv, pub, _ := spoofcarrier.GenerateIdentity()
	offer, err := pairing.NewSpoofSetup(id, netip.MustParseAddrPort("192.0.2.2:47001"),
		netip.MustParseAddrPort("198.51.100.2:47002"),
		netip.MustParseAddr("10.245.10.1"), netip.MustParseAddr("10.245.10.2"), pub)
	if err != nil {
		t.Fatal(err)
	}
	m, err := spoofhost.NewMaterial(id, "creator", priv, offer.Secret())
	if err != nil {
		t.Fatal(err)
	}
	for _, local := range []spoofLocalNetwork{
		{BindIPv4: "::1"},
		{BindIPv4: "10.0.0.3", BindAlternates: "wrong"},
		{BindIPv4: "192.0.2.2", IngressInterface: "../../bad"},
	} {
		if _, err := spoofLinkFromSetup(offer, m, "/root/stl/spoof/sources.txt", "",
			"", 0, 0, domain.MTUPolicy{Mode: domain.MTUAuto}, true, local); err == nil {
			t.Fatalf("invalid local configuration admitted: %+v", local)
		}
	}
}
