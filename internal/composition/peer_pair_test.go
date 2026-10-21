package composition

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func wssPeerFixture() (domain.Link, Carrier, domain.Link, Carrier) {
	dial := testLink(domain.BackendWireGuard, domain.EncapUDP)
	listen := dial
	listen.Underlay.Local, listen.Underlay.Peer = dial.Underlay.Peer, dial.Underlay.Local
	listen.Addresses.Local, listen.Addresses.Peer = dial.Addresses.Peer, dial.Addresses.Local
	listen.WireGuard.LocalPublicKey, listen.WireGuard.PeerPublicKey =
		dial.WireGuard.PeerPublicKey, dial.WireGuard.LocalPublicKey
	listen.WireGuard.ListenPort, listen.WireGuard.PeerPort =
		dial.WireGuard.PeerPort, dial.WireGuard.ListenPort

	dialCarrier := Carrier{
		Kind: WSS, Role: Dial, PublicTCPPort: 8443,
		LocalForwardUDP: 51321, TLSServerName: "server.example",
		CredentialOwner: dial.ID,
	}
	listenCarrier := Carrier{
		Kind: WSS, Role: Listen, PublicTCPPort: 8443,
		TLSServerName: "server.example", CredentialOwner: listen.ID,
	}
	return dial, dialCarrier, listen, listenCarrier
}

func TestValidateWSSPeerPairAcceptsReciprocalTopologyWithoutRequiringSymmetricLocalPolicies(t *testing.T) {
	dial, dc, listen, lc := wssPeerFixture()
	dial.MTU = domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1350}
	listen.MTU = domain.MTUPolicy{Mode: domain.MTUUnmanagedExplicit}
	dial.DisplayName, listen.DisplayName = "caller", "receiver"
	if err := ValidateWSSPeerPair(dial, dc, listen, lc); err != nil {
		t.Fatal(err)
	}
	// Endpoint-local policy is not a wire/pairing identity. A direct native
	// Link must not be dragged into the optional WSS pair requirement.
	if _, err := Build(dial, Carrier{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWSSPeerPairRejectsPeerMismatchBeforeHostEffects(t *testing.T) {
	tests := []struct {
		name string
		edit func(*domain.Link, *Carrier, *domain.Link, *Carrier)
		want string
	}{
		{"two-dialers", func(_ *domain.Link, _ *Carrier, _ *domain.Link, peer *Carrier) {
			peer.Role = Dial
			peer.LocalForwardUDP = 51322
		}, "exactly one dial"},
		{"native-peer-is-not-a-WSS-peer", func(_ *domain.Link, _ *Carrier, _ *domain.Link, peer *Carrier) {
			*peer = Carrier{}
		}, "exactly one dial"},
		{"different-link-id", func(_ *domain.Link, _ *Carrier, l *domain.Link, peer *Carrier) {
			l.ID = domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			peer.CredentialOwner = l.ID
		}, "Link ID"},
		{"underlay-advertises-another-source", func(_ *domain.Link, _ *Carrier, l *domain.Link, _ *Carrier) {
			l.Underlay.Peer = netip.MustParseAddr("192.0.2.77")
		}, "physical endpoints"},
		{"private-addresses-crossed", func(_ *domain.Link, _ *Carrier, l *domain.Link, _ *Carrier) {
			l.Addresses.Peer = netip.MustParsePrefix("10.91.0.3/30")
		}, "private Link Addresses"},
		{"wrong-wireguard-remote-key", func(_ *domain.Link, _ *Carrier, l *domain.Link, _ *Carrier) {
			l.WireGuard.PeerPublicKey = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
		}, "WireGuard peer identities"},
		{"wrong-wireguard-listener-port", func(_ *domain.Link, _ *Carrier, l *domain.Link, _ *Carrier) {
			l.WireGuard.ListenPort = 51999
		}, "WireGuard UDP ports"},
		{"wrong-wireguard-peer-port", func(_ *domain.Link, _ *Carrier, l *domain.Link, _ *Carrier) {
			l.WireGuard.PeerPort = 51998
		}, "WireGuard UDP ports"},
		{"server-certificate-name-mismatch", func(_ *domain.Link, _ *Carrier, _ *domain.Link, peer *Carrier) {
			peer.TLSServerName = "other.example"
		}, "TLS server identity"},
		{"wrong-listener-tcp-port", func(_ *domain.Link, _ *Carrier, _ *domain.Link, peer *Carrier) {
			peer.PublicTCPPort = 8444
		}, "TCP endpoint"},
		{"listener-credential-owned-by-foreign-link", func(_ *domain.Link, _ *Carrier, _ *domain.Link, peer *Carrier) {
			peer.CredentialOwner = "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "WSS listen peer is invalid"},
		{"unproven-gre-over-wss", func(l *domain.Link, _ *Carrier, _ *domain.Link, _ *Carrier) {
			l.Backend, l.Encapsulation = domain.BackendGRE, domain.EncapNative
			l.WireGuard = domain.WireGuardOptions{}
		}, "WSS dial peer is invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dial, dc, listen, lc := wssPeerFixture()
			tt.edit(&dial, &dc, &listen, &lc)
			err := ValidateWSSPeerPair(dial, dc, listen, lc)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q rejection, got %v", tt.want, err)
			}
		})
	}
}

func TestWSSPrivateLinkRoutesRejectLocalOnlyAndReservedAddressSpace(t *testing.T) {
	tests := []struct {
		name        string
		local, peer string
		shouldPass  bool
	}{
		{"rfc1918", "10.91.0.1/30", "10.91.0.2/30", true},
		{"carrier-grade-nat-space", "100.64.1.1/30", "100.64.1.2/30", true},
		{"documentation-lab-range", "192.0.2.1/30", "192.0.2.2/30", true},
		{"loopback-addresses", "127.0.0.1/30", "127.0.0.2/30", false},
		{"loopback-route-even-with-nonloopback-host", "126.0.0.1/7", "126.0.0.2/7", false},
		{"nonroutable-zero-network", "0.0.0.1/30", "0.0.0.2/30", false},
		{"link-local", "169.254.3.1/30", "169.254.3.2/30", false},
		{"multicast", "224.0.0.1/30", "224.0.0.2/30", false},
		{"reserved-class-e", "240.0.0.1/30", "240.0.0.2/30", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dial, dc, listen, lc := wssPeerFixture()
			dial.Addresses.Local = netip.MustParsePrefix(tt.local)
			dial.Addresses.Peer = netip.MustParsePrefix(tt.peer)
			listen.Addresses.Local, listen.Addresses.Peer = dial.Addresses.Peer, dial.Addresses.Local
			for _, peer := range []struct {
				link    domain.Link
				carrier Carrier
			}{{dial, dc}, {listen, lc}} {
				_, err := Build(peer.link, peer.carrier)
				if (err == nil) != tt.shouldPass {
					t.Fatalf("WSS single-peer admission for %s/%s: pass=%v, error=%v", tt.local, tt.peer, tt.shouldPass, err)
				}
				// The check is scoped to WSS: existing Native path
				// validation is not silently tightened.
				if _, err := Build(peer.link, Carrier{}); err != nil {
					t.Fatalf("native plan changed by WSS address policy: %v", err)
				}
			}
			err := ValidateWSSPeerPair(dial, dc, listen, lc)
			if (err == nil) != tt.shouldPass {
				t.Fatalf("WSS two-peer admission for %s/%s: pass=%v, error=%v", tt.local, tt.peer, tt.shouldPass, err)
			}
		})
	}
}

func TestValidateWSSPeerPairKeepsSamePhysicalPeersButDifferentLinkIDsIndependent(t *testing.T) {
	firstDial, firstDC, firstListen, firstLC := wssPeerFixture()
	secondDial, secondDC, secondListen, secondLC := wssPeerFixture()

	// These Links have exactly the same underlay peers, but all exclusive
	// WG and WSS identities are independent on their respective hosts.
	otherID := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secondDial.ID, secondListen.ID = otherID, otherID
	secondDC.CredentialOwner, secondLC.CredentialOwner = otherID, otherID

	secondDial.Addresses.Local = netip.MustParsePrefix("10.92.0.1/30")
	secondDial.Addresses.Peer = netip.MustParsePrefix("10.92.0.2/30")
	secondListen.Addresses.Local, secondListen.Addresses.Peer =
		secondDial.Addresses.Peer, secondDial.Addresses.Local

	secondDial.WireGuard.LocalPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	secondDial.WireGuard.PeerPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	secondListen.WireGuard.LocalPublicKey, secondListen.WireGuard.PeerPublicKey =
		secondDial.WireGuard.PeerPublicKey, secondDial.WireGuard.LocalPublicKey
	secondDial.WireGuard.ListenPort, secondDial.WireGuard.PeerPort = 52820, 52821
	secondListen.WireGuard.ListenPort, secondListen.WireGuard.PeerPort =
		secondDial.WireGuard.PeerPort, secondDial.WireGuard.ListenPort

	secondDC.PublicTCPPort, secondLC.PublicTCPPort = 9443, 9443
	secondDC.LocalForwardUDP = 51322

	if firstDial.Underlay != secondDial.Underlay || firstListen.Underlay != secondListen.Underlay {
		t.Fatal("fixture no longer tests multiple Links to the same physical peer")
	}
	for _, pair := range []struct {
		dial   domain.Link
		dc     Carrier
		listen domain.Link
		lc     Carrier
	}{{firstDial, firstDC, firstListen, firstLC}, {secondDial, secondDC, secondListen, secondLC}} {
		if err := ValidateWSSPeerPair(pair.dial, pair.dc, pair.listen, pair.lc); err != nil {
			t.Fatalf("independent same-peer Link rejected: %v", err)
		}
	}

	// Compare the same exclusive resource kinds reserved by the existing
	// WG backend plus the WSS carrier. Claims are checked per host, not
	// across distinct peers on different machines. This is plan-identity
	// evidence, not proof of live host ownership or usable private IP.
	hostClaims := func(link domain.Link, carrier Carrier) []domain.ResourceClaim {
		t.Helper()
		path, err := Build(link, carrier)
		if err != nil {
			t.Fatal(err)
		}
		claims := []domain.ResourceClaim{
			{Kind: domain.ResourceInterface, Key: "stlwg" + string(link.ID)[4:14]},
			{Kind: domain.ResourceLinkAddress, Key: link.Addresses.Local.Addr().String()},
			{Kind: domain.ResourceLinkSubnet, Key: link.Addresses.Local.Masked().String()},
			{Kind: domain.ResourceUDPListenPort, Key: strconv.Itoa(int(link.WireGuard.ListenPort))},
			{Kind: domain.ResourceBackendID, Key: "wireguard/local-public/" + link.WireGuard.LocalPublicKey},
		}
		return append(claims, path.CarrierClaims()...)
	}
	for _, host := range []struct {
		name    string
		first   domain.Link
		firstC  Carrier
		second  domain.Link
		secondC Carrier
	}{
		{"dial host", firstDial, firstDC, secondDial, secondDC},
		{"listen host", firstListen, firstLC, secondListen, secondLC},
	} {
		for _, left := range hostClaims(host.first, host.firstC) {
			for _, right := range hostClaims(host.second, host.secondC) {
				conflict, err := domain.ResourceClaimsConflict(left, right)
				if err != nil {
					t.Fatalf("%s invalid proposed claim %v against %v: %v", host.name, left, right, err)
				}
				if conflict {
					t.Fatalf("%s exclusive resource collision across distinct Links: %+v and %+v", host.name, left, right)
				}
			}
		}
	}
}
