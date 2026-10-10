package ipsec

import (
	"bytes"
	"context"
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

// R2 regression: unspecified, loopback, link-local, multicast and broadcast
// IPv4 are not concrete peer endpoints nor meaningful IPsec host selectors.
// RFC1918 and TEST-NET unicast addresses remain usable for disposable netns.
func TestProfileRejectsNonConcreteIPv4WithoutVICIAccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*domain.Link)
	}{
		{"unspecified local underlay", func(l *domain.Link) {
			l.Underlay.Local = netip.MustParseAddr("0.0.0.0")
		}},
		{"unspecified peer underlay", func(l *domain.Link) {
			l.Underlay.Peer = netip.MustParseAddr("0.0.0.0")
		}},
		{"nonzero 0/8 peer underlay", func(l *domain.Link) {
			l.Underlay.Peer = netip.MustParseAddr("0.1.2.3")
		}},
		{"reserved 240/4 peer underlay", func(l *domain.Link) {
			l.Underlay.Peer = netip.MustParseAddr("240.0.0.1")
		}},
		{"multicast local underlay", func(l *domain.Link) {
			l.Underlay.Local = netip.MustParseAddr("224.0.0.1")
		}},
		{"multicast peer underlay", func(l *domain.Link) {
			l.Underlay.Peer = netip.MustParseAddr("239.1.2.3")
		}},
		{"loopback local underlay", func(l *domain.Link) {
			l.Underlay.Local = netip.MustParseAddr("127.0.0.1")
		}},
		{"link-local peer underlay", func(l *domain.Link) {
			l.Underlay.Peer = netip.MustParseAddr("169.254.1.2")
		}},
		{"limited broadcast peer underlay", func(l *domain.Link) {
			l.Underlay.Peer = netip.MustParseAddr("255.255.255.255")
		}},
		{"unspecified Link Address pair", func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("0.0.0.0/31")
			l.Addresses.Peer = netip.MustParsePrefix("0.0.0.1/31")
		}},
		{"nonzero 0/8 Link Address pair", func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("0.1.2.2/31")
			l.Addresses.Peer = netip.MustParsePrefix("0.1.2.3/31")
		}},
		{"reserved 240/4 Link Address pair", func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("240.0.0.0/31")
			l.Addresses.Peer = netip.MustParsePrefix("240.0.0.1/31")
		}},
		{"multicast Link Address pair", func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("224.0.0.0/31")
			l.Addresses.Peer = netip.MustParsePrefix("224.0.0.1/31")
		}},
		{"loopback Link Address pair", func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("127.0.0.0/31")
			l.Addresses.Peer = netip.MustParsePrefix("127.0.0.1/31")
		}},
		{"link-local Link Address pair", func(l *domain.Link) {
			l.Addresses.Local = netip.MustParsePrefix("169.254.0.0/31")
			l.Addresses.Peer = netip.MustParsePrefix("169.254.0.1/31")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := testIPsecLink(t, domain.EncapESP)
			tc.alter(&link)
			if _, err := NewProfile(link); err == nil {
				t.Fatal("IPsec accepted a non-concrete unicast IPv4 endpoint/selector")
			}
			// Even a manually forged Profile cannot produce public VICI intent,
			// and the reader must reject it before invoking the injected dialer.
			forged := Profile{Link: link}
			if _, err := forged.ConnectionRequest(); err == nil {
				t.Fatal("invalid address profile produced a VICI request")
			}
			dialed := false
			r := readerWithTestSession(func(context.Context) (Session, error) {
				dialed = true
				return &fakeSession{}, nil
			})
			if _, err := r.Inspect(context.Background(), forged); err == nil || dialed {
				t.Fatal("invalid address profile reached VICI or falsely succeeded")
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
