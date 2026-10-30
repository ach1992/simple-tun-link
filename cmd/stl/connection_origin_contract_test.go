package main

import (
	"net/netip"
	"testing"

	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// A setup creator is not necessarily the public dialer. Exercise both
// possible creator hosts and both public orientations without host effects.
func TestManagedCarrierCreatorIsIndependentOfPublicDialer(t *testing.T) {
	localKey, localPublic, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer localKey.Zeroize()
	peerKey, peerPublic, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer peerKey.Zeroize()

	for _, carrier := range []string{"wss", "quic"} {
		for _, creator := range []string{"endpoint-a", "endpoint-b"} {
			for _, origin := range []string{"creator", "receiver"} {
				t.Run(carrier+"/"+creator+"/"+origin, func(t *testing.T) {
					creatorRole := "listen"
					if origin == "creator" {
						creatorRole = "dial"
					}
					var sender, receiver domain.Link
					var publicPort uint16
					switch carrier {
					case "wss":
						request := testWSSCreateRequest()
						request.Role = creatorRole
						if creator == "endpoint-b" {
							request.Underlay.Local, request.Underlay.Peer = request.Underlay.Peer, request.Underlay.Local
							request.Addresses.Local, request.Addresses.Peer = request.Addresses.Peer, request.Addresses.Local
						}
						request.LocalForwardUDPPort, request.RemoteForwardUDPPort = 0, 0
						if creatorRole == "dial" {
							request.LocalForwardUDPPort = 53001
						} else {
							request.RemoteForwardUDPPort = 53001
						}
						publicPort = request.TCPPort
						sender, receiver, err = makeWSSPair(request, request.LinkID, localPublic, peerPublic)
					case "quic":
						request := testQUICCreateRequest()
						request.Role = creatorRole
						if creator == "endpoint-b" {
							request.Underlay.Local, request.Underlay.Peer = request.Underlay.Peer, request.Underlay.Local
							request.Addresses.Local, request.Addresses.Peer = request.Addresses.Peer, request.Addresses.Local
						}
						request.LocalForwardUDPPort, request.RemoteForwardUDPPort = 0, 0
						if creatorRole == "dial" {
							request.LocalForwardUDPPort = 53001
						} else {
							request.RemoteForwardUDPPort = 53001
						}
						publicPort = request.UDPPort
						sender, receiver, err = makeQUICPair(request, request.LinkID, localPublic, peerPublic)
					}
					if err != nil {
						t.Fatalf("pair rejected creator role %q: %v", creatorRole, err)
					}

					dial, listen := sender, receiver
					if creatorRole == "listen" {
						dial, listen = receiver, sender
					}
					if dial.ID != listen.ID || dial.Underlay.Peer != listen.Underlay.Local ||
						dial.Underlay.Local != listen.Underlay.Peer ||
						dial.Addresses.Local != listen.Addresses.Peer ||
						dial.Addresses.Peer != listen.Addresses.Local ||
						dial.WireGuard.PeerPublicKey != listen.WireGuard.LocalPublicKey ||
						listen.WireGuard.PeerPublicKey != dial.WireGuard.LocalPublicKey ||
						dial.WireGuard.ListenPort != listen.WireGuard.PeerPort ||
						listen.WireGuard.ListenPort != dial.WireGuard.PeerPort {
						t.Fatal("roles did not preserve reciprocal Link and WireGuard identities")
					}

					dialPlan, err := composition.Build(dial, composition.CarrierForLink(dial))
					if err != nil {
						t.Fatal(err)
					}
					listenPlan, err := composition.Build(listen, composition.CarrierForLink(listen))
					if err != nil {
						t.Fatal(err)
					}
					publicListener := netip.AddrPortFrom(listen.Underlay.Local, publicPort)
					if dialPlan.TLSName != listen.Underlay.Local.String() {
						t.Fatal("TLS listener identity was derived from creator rather than selected listener")
					}
					switch carrier {
					case "wss":
						if sender.WSS.Role != creatorRole || dial.WSS.Role != "dial" ||
							listen.WSS.Role != "listen" || dial.WSS.ForwardUDPPort != 53001 ||
							listen.WSS.ForwardUDPPort != 0 ||
							dialPlan.WSSPeerTCP != publicListener ||
							listenPlan.WSSLocalTCP != publicListener {
							t.Fatal("WSS public direction or selected physical endpoint was inverted")
						}
					case "quic":
						if sender.QUIC.Role != creatorRole || dial.QUIC.Role != "dial" ||
							listen.QUIC.Role != "listen" || dial.QUIC.ForwardUDPPort != 53001 ||
							listen.QUIC.ForwardUDPPort != 0 ||
							dialPlan.QUIC.Physical != publicListener ||
							listenPlan.QUIC.Physical != publicListener {
							t.Fatal("QUIC public direction or selected physical endpoint was inverted")
						}
					}
				})
			}
		}
	}
}
