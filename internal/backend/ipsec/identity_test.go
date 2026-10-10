package ipsec

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const fixtureID domain.LinkID = "lnk_11223344556677889900aabbccddeeff"

func testIPsecLink(t *testing.T, encap domain.Encapsulation) domain.Link {
	t.Helper()
	return domain.Link{
		ID: fixtureID, Backend: domain.BackendIPsec, Encapsulation: encap,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("192.0.2.10"),
			Peer:  netip.MustParseAddr("192.0.2.11"),
		},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.99.0.0/31"),
			Peer:  netip.MustParsePrefix("10.99.0.1/31"),
		},
	}
}

func TestProfileIdentityStableAndPeerInverse(t *testing.T) {
	for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
		t.Run(string(encap), func(t *testing.T) {
			link := testIPsecLink(t, encap)
			a, err := NewProfile(link)
			if err != nil {
				t.Fatal(err)
			}
			b, err := NewProfile(invertTestLink(link))
			if err != nil {
				t.Fatal(err)
			}
			if a.ConnectionName != b.ConnectionName || a.ChildName != b.ChildName ||
				a.SecretName != b.SecretName || a.InterfaceName != b.InterfaceName ||
				a.InterfaceID != b.InterfaceID || a.InterfaceID == 0 {
				t.Fatal("both peers must negotiate exactly one stable Link-scoped identity")
			}
			if a.LocalIKEID != b.PeerIKEID || a.PeerIKEID != b.LocalIKEID ||
				a.LocalIKEID == a.PeerIKEID {
				t.Fatal("symmetric role inversion did not produce matching peer IKE identities")
			}
			if len(a.InterfaceName) > 15 || !strings.HasPrefix(a.ConnectionName, "stl-ipsec-") ||
				!strings.HasPrefix(a.SecretName, "stl-psk-") {
				t.Fatal("unsafe or noncanonical owned resource name")
			}
			local, remote := a.LinkHostSelectors()
			if local.String() != "10.99.0.0/32" || remote.String() != "10.99.0.1/32" {
				t.Fatal("IPsec policy must target only exact host Link addresses")
			}
			localB, remoteB := b.LinkHostSelectors()
			if local != remoteB || remote != localB {
				t.Fatal("opposite side Link host selectors do not invert")
			}
			claims := a.ResourceClaims()
			for _, claim := range claims {
				if err := claim.Validate(); err != nil {
					t.Fatalf("unsafe generated resource claim %q: %v", claim.Kind, err)
				}
				if strings.Contains(claim.Key, "secret") || strings.Contains(claim.Key, "PRIVATE") {
					t.Fatal("resource claim contains credential data")
				}
			}
			for _, resource := range []string{domain.ResourceXFRMID, domain.ResourceInterface,
				domain.ResourceBackendID, domain.ResourceLinkSubnet} {
				if !slices.ContainsFunc(claims, func(c domain.ResourceClaim) bool { return c.Kind == resource }) {
					t.Errorf("missing essential collision claim %s", resource)
				}
			}
		})
	}
}

func TestProfileRejectsUnsupportedOrAmbiguousPolicyBeforeIO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*domain.Link)
	}{
		{"GRE masquerading as IPsec", func(l *domain.Link) { l.Backend = domain.BackendGRE }},
		{"UDP is not IPsec", func(l *domain.Link) { l.Encapsulation = domain.EncapUDP }},
		{"IPv6 underlay", func(l *domain.Link) {
			l.Underlay.Local = netip.MustParseAddr("2001:db8::1")
			l.Underlay.Peer = netip.MustParseAddr("2001:db8::2")
		}},
		{"arbitrary full prefix", func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("10.99.0.0/24")
			l.Addresses.Peer = netip.MustParsePrefix("10.99.0.1/24")
		}},
		{"disconnected subnets", func(l *domain.Link) {
			l.Addresses.Peer = netip.MustParsePrefix("10.99.0.3/31")
		}},
		{"invalid Link ID", func(l *domain.Link) { l.ID = "../../foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testIPsecLink(t, domain.EncapESP)
			tc.alter(&l)
			if _, err := NewProfile(l); err == nil {
				t.Fatal("unsafe IPsec profile accepted")
			}
		})
	}
}

func TestIPsecPSKIsRandomAndNeverImplicitlyJSONEncoded(t *testing.T) {
	a, err := GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(a)
	defer clear(b)
	if len(a) != 32 || len(b) != 32 || bytes.Equal(a, b) {
		t.Fatal("IPsec Quick Link PSK is not a fresh 256-bit value")
	}
	profile, err := NewProfile(testIPsecLink(t, domain.EncapNATT))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, a) || bytes.Contains(raw, b) {
		t.Fatal("public Profile serialized credential material")
	}
}

func invertTestLink(l domain.Link) domain.Link {
	l.Underlay.Local, l.Underlay.Peer = l.Underlay.Peer, l.Underlay.Local
	l.Addresses.Local, l.Addresses.Peer = l.Addresses.Peer, l.Addresses.Local
	return l
}
