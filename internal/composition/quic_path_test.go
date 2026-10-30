package composition

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func managedQUICPair() (domain.Link, domain.Link) {
	dial, _, listen, _ := wssPeerFixture()
	dial.Backend, listen.Backend = domain.BackendWireGuardQUIC, domain.BackendWireGuardQUIC
	dial.QUIC = domain.QUICOptions{Role: "dial", UDPPort: 443, ForwardUDPPort: 51321}
	listen.QUIC = domain.QUICOptions{Role: "listen", UDPPort: 443}
	return dial, listen
}

func TestManagedQUICPairSeparatesPhysicalPrivateAndKernelEndpoints(t *testing.T) {
	dial, listen := managedQUICPair()
	dial.MTU = domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1280}
	listen.MTU = domain.MTUPolicy{Mode: domain.MTUAuto}
	if err := ValidateQUICPeerPair(dial, CarrierForLink(dial), listen, CarrierForLink(listen)); err != nil {
		t.Fatal(err)
	}
	dp, err := Build(dial, CarrierForLink(dial))
	if err != nil {
		t.Fatal(err)
	}
	lp, err := Build(listen, CarrierForLink(listen))
	if err != nil {
		t.Fatal(err)
	}
	if dp.WGPeerEndpoint.String() != "127.0.0.1:51321" || lp.WGPeerEndpoint.IsValid() ||
		dp.QUIC.Physical != netip.AddrPortFrom(listen.Underlay.Local, 443) || dp.QUIC.Physical != lp.QUIC.Physical ||
		dp.QUIC.Local.RemoteWGUDPPort != listen.WireGuard.ListenPort || lp.QUIC.Local.RemoteWGUDPPort != 0 ||
		dp.TLSName != listen.Underlay.Local.String() || dp.Physical != dial.Underlay || dp.Private != dial.Addresses {
		t.Fatalf("QUIC endpoint planes were conflated: dial=%+v listen=%+v", dp, lp)
	}
	if slices.Contains(dp.CarrierClaims(), domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: "443"}) ||
		!slices.Contains(lp.CarrierClaims(), domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: "443"}) {
		t.Fatal("remote QUIC destination was reserved locally or physical listener was not reserved")
	}
	for _, link := range []domain.Link{dial, listen} {
		if _, err := Build(link, Carrier{}); err == nil {
			t.Fatal("managed QUIC silently fell back to direct WireGuard")
		}
	}
}

func TestManagedQUICRejectsUnsupportedOrConflictingTopology(t *testing.T) {
	cases := []struct {
		name string
		edit func(*domain.Link, *domain.Link)
	}{
		{"remote-key", func(_ *domain.Link, b *domain.Link) { b.WireGuard.PeerPublicKey = b.WireGuard.LocalPublicKey }},
		{"wrong-listener", func(_ *domain.Link, b *domain.Link) { b.QUIC.UDPPort++ }},
		{"wrong-tls", func(_ *domain.Link, b *domain.Link) { b.QUIC.TLSServerName = "other.example" }},
		{"mismatched-obfuscation", func(a *domain.Link, _ *domain.Link) { a.QUIC.Obfuscation = domain.QUICObfuscationSalamander }},
		{"unknown-obfuscation", func(a *domain.Link, b *domain.Link) {
			a.QUIC.Obfuscation, b.QUIC.Obfuscation = "automatic", "automatic"
		}},
		{"tls-ip-override", func(a *domain.Link, _ *domain.Link) { a.QUIC.TLSServerName = "192.0.2.9" }},
		{"wireguard-helper-collision", func(a *domain.Link, _ *domain.Link) { a.QUIC.ForwardUDPPort = a.WireGuard.ListenPort }},
		{"listener-wireguard-collision", func(_ *domain.Link, b *domain.Link) { b.QUIC.UDPPort = b.WireGuard.ListenPort }},
		{"listener-forwarder", func(_ *domain.Link, b *domain.Link) { b.QUIC.ForwardUDPPort = 51322 }},
		{"private-route-captures-loopback", func(a *domain.Link, _ *domain.Link) { a.Addresses.Local = netip.MustParsePrefix("126.0.0.1/7") }},
		{"private-route-captures-physical", func(a *domain.Link, _ *domain.Link) { a.Addresses.Local = netip.PrefixFrom(a.Underlay.Peer, 24) }},
		{"foreign-wss-fields", func(a *domain.Link, _ *domain.Link) {
			a.WSS = domain.WSSOptions{Role: "dial", TCPPort: 443, ForwardUDPPort: 51322}
		}},
		{"native-backend-with-quic-options", func(a *domain.Link, _ *domain.Link) { a.Backend = domain.BackendWireGuard }},
		{"ipv6-physical", func(a *domain.Link, _ *domain.Link) { a.Underlay.Local = netip.MustParseAddr("2001:db8::1") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dial, listen := managedQUICPair()
			tc.edit(&dial, &listen)
			if err := ValidateQUICPeerPair(dial, CarrierForLink(dial), listen, CarrierForLink(listen)); err == nil {
				t.Fatal("unsafe or incompatible QUIC topology accepted")
			}
		})
	}
}

func TestManagedQUICSalamanderPairKeepsExistingTopology(t *testing.T) {
	dial, listen := managedQUICPair()
	dial.QUIC.Obfuscation, listen.QUIC.Obfuscation = domain.QUICObfuscationSalamander, domain.QUICObfuscationSalamander
	if err := ValidateQUICPeerPair(dial, CarrierForLink(dial), listen, CarrierForLink(listen)); err != nil {
		t.Fatal(err)
	}
	for _, link := range []domain.Link{dial, listen} {
		got, err := Build(link, CarrierForLink(link))
		if err != nil {
			t.Fatal(err)
		}
		if got.QUIC.Obfuscation != domain.QUICObfuscationSalamander {
			t.Fatal("composition dropped the selected obfuscation mode")
		}
		plain := link
		plain.QUIC.Obfuscation = domain.QUICObfuscationPlain
		before, err := Build(plain, CarrierForLink(plain))
		if err != nil {
			t.Fatal(err)
		}
		if got.WGPeerEndpoint != before.WGPeerEndpoint || !slices.Equal(got.CarrierClaims(), before.CarrierClaims()) || got.QUIC.Local != before.QUIC.Local || got.QUIC.Physical != before.QUIC.Physical {
			t.Fatal("obfuscation changed physical, WireGuard or resource topology")
		}
	}
}
