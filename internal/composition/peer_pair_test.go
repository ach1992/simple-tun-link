package composition

import (
	"net/netip"
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

func TestValidateWSSPeerPairKeepsSamePhysicalPeersButDifferentLinkIDsIndependent(t *testing.T) {
	a, ac, b, bc := wssPeerFixture()
	if err := ValidateWSSPeerPair(a, ac, b, bc); err != nil {
		t.Fatal(err)
	}
	otherID := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	a.ID, b.ID = otherID, otherID
	ac.CredentialOwner, bc.CredentialOwner = otherID, otherID
	ac.LocalForwardUDP++
	ac.PublicTCPPort, bc.PublicTCPPort = 9443, 9443
	if err := ValidateWSSPeerPair(a, ac, b, bc); err != nil {
		t.Fatalf("independent same-peer Link rejected: %v", err)
	}
}
