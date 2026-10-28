package quic

import (
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func claimedUDP(port uint16) domain.ResourceClaim {
	return domain.ResourceClaim{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(port))}
}

func claimsOverlap(t *testing.T, a, b []domain.ResourceClaim) bool {
	t.Helper()
	for _, left := range a {
		for _, right := range b {
			conflict, err := domain.ResourceClaimsConflict(left, right)
			if err != nil {
				t.Fatal(err)
			}
			if conflict {
				return true
			}
		}
	}
	return false
}

func TestQUICCarrierClaimsExactRoleSpecificHostReservations(t *testing.T) {
	dial := fixturePlan(Dial)
	dial.LocalForwardUDPPort = 52211
	dial.PeerWGUDPPort = 51820
	listen := fixturePlan(Listen)
	listen.LocalWGUDPPort = 51820
	tests := []struct {
		name      string
		plan      Plan
		wgPort    uint16
		helperUDP uint16
	}{
		{"dial", dial, 51821, 52211},
		{"listen", listen, 51820, 443},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := tt.plan.CarrierClaims(tt.wgPort)
			if err != nil {
				t.Fatal(err)
			}
			id := string(tt.plan.LinkID)
			want := []domain.ResourceClaim{
				{Kind: domain.ResourceBackendID, Key: "quic/helper/" + id},
				{Kind: domain.ResourceBackendID, Key: "quic/tls-identity/" + id},
				{Kind: domain.ResourceFirewall, Key: "quic/nft/" + id},
				claimedUDP(tt.wgPort),
				claimedUDP(tt.helperUDP),
			}
			if !reflect.DeepEqual(claims, want) {
				t.Fatalf("incomplete or incorrect QUIC local claims: got %v, want %v", claims, want)
			}
			for _, claim := range claims {
				if err := claim.Validate(); err != nil {
					t.Fatal("noncanonical claim", claim, err)
				}
			}
			// The peer destination is NOT a local owned listener. On Dial,
			// only the separate local WG and helper UDP ports are reserved.
			if tt.plan.Role == Dial && slices.Contains(claims, claimedUDP(tt.plan.PeerWGUDPPort)) {
				t.Fatal("reserved remote peer WG destination as a local port")
			}
		})
	}
}

func TestQUICCarrierClaimsRejectImpossibleOrAmbiguousPortTopologies(t *testing.T) {
	dial := fixturePlan(Dial)
	dial.LocalForwardUDPPort = 52211
	dial.PeerWGUDPPort = 51820
	listen := fixturePlan(Listen)
	listen.LocalWGUDPPort = 51820
	for _, tc := range []struct {
		name string
		p    Plan
		wg   uint16
	}{
		{"missing-local-wg", dial, 0},
		{"dial-helper-same-as-local-wg", dial, 52211},
		{"dial-missing-forwarder", func() Plan { p := dial; p.LocalForwardUDPPort = 0; return p }(), 51821},
		{"dial-missing-remote-destination", func() Plan { p := dial; p.PeerWGUDPPort = 0; return p }(), 51821},
		{"dial-mixed-local-listen-port", func() Plan { p := dial; p.LocalWGUDPPort = 51821; return p }(), 51821},
		{"listen-wg-mismatch", listen, 51822},
		{"listen-physical-same-as-local-wg", func() Plan { p := listen; p.Underlay = netip.MustParseAddrPort("203.0.113.45:51820"); return p }(), 51820},
		{"listen-missing-local-wg", func() Plan { p := listen; p.LocalWGUDPPort = 0; return p }(), 51820},
		{"listen-mixed-forwarder", func() Plan { p := listen; p.LocalForwardUDPPort = 53000; return p }(), 51820},
		{"listen-mixed-remote-destination", func() Plan { p := listen; p.PeerWGUDPPort = 53000; return p }(), 51820},
		{"invalid-identity", func() Plan { p := dial; p.LinkID = "not-a-link"; return p }(), 51821},
		{"invalid-underlay", func() Plan { p := dial; p.Underlay = netip.AddrPort{}; return p }(), 51821},
		{"invalid-TLS-name", func() Plan { p := dial; p.TLSName = "https://example.com"; return p }(), 51821},
		{"unsupported-role", func() Plan { p := dial; p.Role = "other"; return p }(), 51821},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := tc.p.CarrierClaims(tc.wg)
			if err == nil || len(claims) != 0 {
				t.Fatalf("unsafe QUIC topology yielded host reservations: %v, %v", claims, err)
			}
		})
	}
	// Renderer and claim validator must agree about the on-host two-port
	// conflict; a JSON artifact cannot bypass the future admission rule.
	p := listen
	p.Underlay = netip.MustParseAddrPort("203.0.113.45:51820")
	if _, err := Build(p, "/opt/stl/hysteria", "/var/lib/simple-tun-link", fixtureToken); err == nil {
		t.Fatal("renderer accepted physically impossible QUIC listen/WG port overlap")
	}
}

func TestQUICCarrierClaimsCollideWithExistingUDPAndKeepIndependentLinks(t *testing.T) {
	idA := domain.LinkID("lnk_11111111111111111111111111111111")
	idB := domain.LinkID("lnk_22222222222222222222222222222222")
	serverA := fixturePlan(Listen)
	serverA.LinkID = idA
	serverA.LocalWGUDPPort = 51820
	a, err := serverA.CarrierClaims(51820)
	if err != nil {
		t.Fatal(err)
	}
	if !claimsOverlap(t, a, []domain.ResourceClaim{claimedUDP(443)}) ||
		!claimsOverlap(t, a, []domain.ResourceClaim{claimedUDP(51820)}) {
		t.Fatal("QUIC server must collide with existing native/WSS UDP reservations")
	}
	// A TCP WSS listener on the same numeric port has a distinct protocol
	// socket identity. Conservatively serialized UDP claims should not
	// manufacture a cross-protocol conflict.
	if claimsOverlap(t, a, []domain.ResourceClaim{{Kind: domain.ResourceTCPListenPort, Key: "443"}}) {
		t.Fatal("UDP and TCP port reservations collided")
	}
	serverB := serverA
	serverB.LinkID = idB
	serverB.Underlay = netip.MustParseAddrPort("198.51.100.22:443")
	serverB.LocalWGUDPPort = 51822
	b, err := serverB.CarrierClaims(51822)
	if err != nil {
		t.Fatal(err)
	}
	if !claimsOverlap(t, a, b) {
		t.Fatal("two QUIC listeners on the same host reused one physical UDP port")
	}
	serverB.Underlay = netip.MustParseAddrPort("198.51.100.22:8443")
	b, err = serverB.CarrierClaims(51822)
	if err != nil {
		t.Fatal(err)
	}
	if claimsOverlap(t, a, b) {
		t.Fatal("independent QUIC server Links with distinct ports collided")
	}

	dialA := fixturePlan(Dial)
	dialA.LinkID = idA
	dialA.LocalForwardUDPPort = 52211
	dialA.PeerWGUDPPort = 51820
	da, err := dialA.CarrierClaims(51821)
	if err != nil {
		t.Fatal(err)
	}
	if !claimsOverlap(t, da, []domain.ResourceClaim{claimedUDP(52211)}) ||
		!claimsOverlap(t, da, []domain.ResourceClaim{claimedUDP(51821)}) {
		t.Fatal("QUIC Dial must reserve both local helper and local kernel WG ports")
	}
	dialB := dialA
	dialB.LinkID = idB
	dialB.LocalForwardUDPPort = 52212
	db, err := dialB.CarrierClaims(51823)
	if err != nil {
		t.Fatal(err)
	}
	if claimsOverlap(t, da, db) {
		t.Fatal("two independent QUIC Dial Links incorrectly blocked by one remote endpoint")
	}
	// Local TLS/helper/nft identities still conflict when two plans attempt
	// to mutate the SAME Link under different roles and local port values.
	dialB.LinkID = idA
	db, err = dialB.CarrierClaims(51823)
	if err != nil {
		t.Fatal(err)
	}
	if !claimsOverlap(t, da, db) {
		t.Fatal("same Link reuses a helper/credential/guard identity")
	}
}

func TestQUICLocalAdmissionProjectsExactlyTheValidatedCarrierClaims(t *testing.T) {
	for _, role := range []Role{Dial, Listen} {
		p := fixturePlan(role)
		wgPort := uint16(51820)
		if role == Dial {
			p.LocalForwardUDPPort = 52211
			p.PeerWGUDPPort = 51830
		} else {
			p.LocalWGUDPPort = wgPort
		}
		projection, err := p.LocalAdmission(wgPort)
		if err != nil {
			t.Fatal(err)
		}
		projected, err := projection.CarrierClaims()
		if err != nil {
			t.Fatal(err)
		}
		direct, err := p.CarrierClaims(wgPort)
		if err != nil || !reflect.DeepEqual(projected, direct) {
			t.Fatalf("role %s projected claims diverge from renderer: %v / %v / %v", role, projected, direct, err)
		}
	}
}

func TestQUICHostPlanBindsExactPublicPhysicalRoleAndTLS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    Role
		localWG uint16
	}{
		{"dial", Dial, 51821},
		{"listen", Listen, 51820},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePlan(tc.role)
			switch tc.role {
			case Dial:
				p.LocalForwardUDPPort, p.PeerWGUDPPort = 52211, 51820
			case Listen:
				p.LocalWGUDPPort = tc.localWG
			}
			bound, err := p.HostPlan(tc.localWG)
			if err != nil || bound.Physical != p.Underlay || bound.TLSName != p.TLSName ||
				bound.Local.LinkID != p.LinkID || bound.Local.Role != composition.Role(tc.role) {
				t.Fatalf("physical/TLS QUIC Plan lost: %+v %v", bound, err)
			}
			if _, err := bound.Local.CarrierClaims(); err != nil {
				t.Fatal(err)
			}
			bad := p
			bad.Underlay = netip.MustParseAddrPort("127.0.0.1:443")
			if _, err := bad.HostPlan(tc.localWG); err == nil {
				t.Fatal("host-effect journal admitted a loopback physical underlay")
			}
			bad = p
			bad.TLSName = "203.0.113.46"
			if _, err := bad.HostPlan(tc.localWG); err == nil {
				t.Fatal("host-effect journal omitted exact physical TLS SAN binding")
			}
		})
	}
}
