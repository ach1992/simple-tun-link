package composition

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func testLink(backend domain.Backend, encap domain.Encapsulation) domain.Link {
	rawLocal, rawPeer := make([]byte, 32), make([]byte, 32)
	for i := range rawLocal {
		rawLocal[i], rawPeer[i] = 1, 2
	}
	l := domain.Link{
		ID:      domain.LinkID("lnk_0123456789abcdef0123456789abcdef"),
		Backend: backend, Encapsulation: encap,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("198.51.100.21"),
			Peer:  netip.MustParseAddr("203.0.113.34"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.91.0.1/30"),
			Peer:  netip.MustParsePrefix("10.91.0.2/30"),
		},
	}
	if backend == domain.BackendWireGuard {
		l.WireGuard = domain.WireGuardOptions{
			LocalPublicKey: base64.StdEncoding.EncodeToString(rawLocal),
			PeerPublicKey:  base64.StdEncoding.EncodeToString(rawPeer),
			ListenPort:     51820, PeerPort: 51821,
		}
	}
	if backend == domain.BackendGRE && (encap == domain.EncapFOU || encap == domain.EncapGUE) {
		l.GRE.UDPPort = 54001
	}
	return l
}

func TestNativePlansPreserveEveryRealBackendWireFormat(t *testing.T) {
	tests := []struct {
		backend domain.Backend
		encap   domain.Encapsulation
		payload Payload
	}{
		{domain.BackendGRE, domain.EncapNative, RawIPProtocol},
		{domain.BackendGRE, domain.EncapFOU, UDPDatagrams},
		{domain.BackendGRE, domain.EncapGUE, UDPDatagrams},
		{domain.BackendIPIP, domain.EncapNative, RawIPProtocol},
		{domain.BackendIPIP, domain.EncapFOU, UDPDatagrams},
		{domain.BackendIPIP, domain.EncapGUE, UDPDatagrams},
		{domain.BackendWireGuard, domain.EncapUDP, UDPDatagrams},
		{domain.BackendIPsec, domain.EncapESP, IPSecESP},
		{domain.BackendIPsec, domain.EncapNATT, UDPDatagrams},
	}
	for _, tt := range tests {
		t.Run(string(tt.backend)+"/"+string(tt.encap), func(t *testing.T) {
			link := testLink(tt.backend, tt.encap)
			if err := link.Validate(); err != nil {
				t.Fatal(err)
			}
			p, err := Build(link, Carrier{})
			if err != nil {
				t.Fatal(err)
			}
			if p.Kind != Direct || p.Payload != tt.payload ||
				p.Physical != link.Underlay || p.Private != link.Addresses ||
				p.Provider != link.Backend || p.Encapsulation != link.Encapsulation {
				t.Fatalf("native path changed: %+v", p)
			}
			if tt.backend == domain.BackendWireGuard {
				want := netip.AddrPortFrom(link.Underlay.Peer, link.WireGuard.PeerPort)
				if p.WGPeerEndpoint != want {
					t.Fatalf("native WG endpoint %v != %v", p.WGPeerEndpoint, want)
				}
			} else if p.WGPeerEndpoint.IsValid() {
				t.Fatalf("invented WG endpoint for %s", tt.backend)
			}
			if p.WSSLocalUDP.IsValid() || p.WSSLocalTCP.IsValid() || p.WSSPeerTCP.IsValid() {
				t.Fatalf("native backend unexpectedly gained WSS listener: %+v", p)
			}
		})
	}
}

func TestWSSRoleEndpointSeparationAndPerLinkIdentity(t *testing.T) {
	link := testLink(domain.BackendWireGuard, domain.EncapUDP)
	dial := Carrier{Kind: WSS, Role: Dial, PublicTCPPort: 443, LocalForwardUDP: 51321,
		TLSServerName: "server.example", CredentialOwner: link.ID}
	p, err := Build(link, dial)
	if err != nil {
		t.Fatal(err)
	}
	if p.WGPeerEndpoint.String() != "127.0.0.1:51321" ||
		p.WSSLocalUDP != p.WGPeerEndpoint ||
		p.WSSRemoteWGUDPPort != link.WireGuard.PeerPort ||
		p.WSSPeerTCP.String() != "203.0.113.34:443" ||
		p.WSSLocalTCP.IsValid() || p.TLSName != dial.TLSServerName ||
		p.Physical != link.Underlay || p.Private != link.Addresses {
		t.Fatalf("WSS dial incorrectly conflated physical/private/loopback: %+v", p)
	}

	listen := Carrier{Kind: WSS, Role: Listen, PublicTCPPort: 8443, CredentialOwner: link.ID}
	q, err := Build(link, listen)
	if err != nil {
		t.Fatal(err)
	}
	if q.WGPeerEndpoint.IsValid() || q.WSSLocalUDP.IsValid() ||
		q.WSSPeerTCP.IsValid() || q.WSSLocalTCP.String() != "198.51.100.21:8443" ||
		q.WSSRemoteWGUDPPort != link.WireGuard.ListenPort {
		t.Fatalf("WSS listening side invented a direct public WG target: %+v", q)
	}

	// These structs intentionally preserve Go's comparable value semantics;
	// persisted Link equality under locks must remain deterministic.
	_ = dial == dial
	_ = p == p
}

func TestWSSRejectsUnprovenProviderOrAmbiguousRoleAndAuthentication(t *testing.T) {
	wg := testLink(domain.BackendWireGuard, domain.EncapUDP)
	accepted := Carrier{Kind: WSS, Role: Dial, PublicTCPPort: 443, LocalForwardUDP: 51321,
		TLSServerName: "server.example", CredentialOwner: wg.ID}
	tests := []struct {
		name    string
		link    domain.Link
		carrier Carrier
	}{
		{"gre-native", testLink(domain.BackendGRE, domain.EncapNative), accepted},
		{"gre-fou-udp-still-unproven", testLink(domain.BackendGRE, domain.EncapFOU), accepted},
		{"ipip-gue-udp-still-unproven", testLink(domain.BackendIPIP, domain.EncapGUE), accepted},
		{"ipsec-natt-udp-still-unproven", testLink(domain.BackendIPsec, domain.EncapNATT), accepted},
		{"ipv6-underlay-not-yet-supported-by-kernel-wg-adapter", func() domain.Link {
			l := wg
			l.Underlay.Local = netip.MustParseAddr("2001:db8::11")
			l.Underlay.Peer = netip.MustParseAddr("2001:db8::22")
			return l
		}(), accepted},
		{"underlay-peer-maps-into-private-subnet", func() domain.Link {
			l := wg
			l.Underlay.Peer = netip.MustParseAddr("10.91.0.2")
			return l
		}(), accepted},
		{"underlay-source-maps-into-private-subnet", func() domain.Link {
			l := wg
			l.Underlay.Local = netip.MustParseAddr("10.91.0.1")
			return l
		}(), accepted},
		{"loopback-is-not-physical-wss-peer", func() domain.Link {
			l := wg
			l.Underlay.Peer = netip.MustParseAddr("127.0.0.2")
			return l
		}(), accepted},
		{"unknown-carrier", wg, Carrier{Kind: "unknown"}},
		{"native-with-shadow-port", wg, Carrier{Kind: Direct, PublicTCPPort: 443}},
		{"missing-owner", wg, func() Carrier { v := accepted; v.CredentialOwner = ""; return v }()},
		{"wrong-link-owner", wg, func() Carrier { v := accepted; v.CredentialOwner = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; return v }()},
		{"unrunnable-distinct-ip-sni-override", wg, func() Carrier {
			v := accepted
			v.TLSServerName = "192.0.2.200"
			return v
		}()},
		{"url-instead-of-name", wg, func() Carrier { v := accepted; v.TLSServerName = "https://server.example/"; return v }()},
		{"shell-instead-of-name", wg, func() Carrier { v := accepted; v.TLSServerName = "host.example;true"; return v }()},
		{"mixed-case-identity", wg, func() Carrier { v := accepted; v.TLSServerName = "Server.Example"; return v }()},
		{"missing-tcp-port", wg, func() Carrier { v := accepted; v.PublicTCPPort = 0; return v }()},
		{"missing-loopback-port", wg, func() Carrier { v := accepted; v.LocalForwardUDP = 0; return v }()},
		{"wg-and-wss-udp-socket-collision", wg, func() Carrier { v := accepted; v.LocalForwardUDP = wg.WireGuard.ListenPort; return v }()},
		{"role-unknown", wg, func() Carrier { v := accepted; v.Role = "reverse"; return v }()},
		{"listen-with-client-forwarder", wg, func() Carrier {
			v := accepted
			v.Role = Listen
			v.LocalForwardUDP = 40000
			v.TLSServerName = ""
			return v
		}()},
		{"listen-with-unrelated-ip-san", wg, func() Carrier {
			v := accepted
			v.Role = Listen
			v.LocalForwardUDP = 0
			v.TLSServerName = "192.0.2.9"
			return v
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Build(tt.link, tt.carrier); err == nil {
				t.Fatalf("unsafe/unproven composition unexpectedly accepted: %+v", tt.carrier)
			}
		})
	}
}

func TestWSSDoesNotRequireWireGuardOnOtherNativePaths(t *testing.T) {
	// Carrier compatibility must be evaluated per chosen Link rather than
	// making every native backend depend on the WSS/wg helper.
	for _, l := range []domain.Link{
		testLink(domain.BackendGRE, domain.EncapNative),
		testLink(domain.BackendIPIP, domain.EncapFOU),
		testLink(domain.BackendIPsec, domain.EncapESP),
	} {
		if _, err := Build(l, Carrier{}); err != nil {
			t.Fatalf("independent native %s rejected: %v", l.Backend, err)
		}
	}
}

func TestCarrierClaimsAreScopedAndNeverConfuseLocksWithOwnership(t *testing.T) {
	l := testLink(domain.BackendWireGuard, domain.EncapUDP)
	cases := []struct {
		name     string
		carrier  Carrier
		portKind string
		portKey  string
	}{
		{"dial", Carrier{Kind: WSS, Role: Dial, PublicTCPPort: 443, LocalForwardUDP: 51321,
			TLSServerName: "server.example", CredentialOwner: l.ID}, domain.ResourceUDPListenPort, "51321"},
		{"listen", Carrier{Kind: WSS, Role: Listen, PublicTCPPort: 8443, CredentialOwner: l.ID},
			domain.ResourceTCPListenPort, "8443"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Build(l, tt.carrier)
			if err != nil {
				t.Fatal(err)
			}
			claims := p.CarrierClaims()
			if len(claims) != 3 {
				t.Fatalf("expected helper, TLS identity, one socket claim: %+v", claims)
			}
			for i, c := range claims {
				if err := c.Validate(); err != nil {
					t.Fatalf("invalid claim %+v: %v", c, err)
				}
				for j := 0; j < i; j++ {
					conflict, err := domain.ResourceClaimsConflict(c, claims[j])
					if err != nil || conflict {
						t.Fatalf("plan has overlapping claims: %+v %+v", c, claims[j])
					}
				}
				if i < 2 && (c.Kind != domain.ResourceBackendID || !strings.Contains(c.Key, string(l.ID))) {
					t.Fatalf("credential/process claim has no exact Link binding: %+v", c)
				}
			}
			if claims[2].Kind != tt.portKind || claims[2].Key != tt.portKey {
				t.Fatalf("wrong listener kind/port: %+v", claims[2])
			}
		})
	}
	if claims := mustDirectPath(t, l).CarrierClaims(); len(claims) != 0 {
		t.Fatalf("native WG acquired a WSS-only claim: %+v", claims)
	}
}

func mustDirectPath(t *testing.T, l domain.Link) Path {
	t.Helper()
	p, err := Build(l, Carrier{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
