package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	wg "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func testWSSCreateRequest() wssCreateRequest {
	return wssCreateRequest{
		SchemaVersion: 1, LinkID: domain.LinkID("lnk_0123456789abcdef0123456789abcdef"),
		Underlay:   desiredUnderlayV1{Local: netip.MustParseAddr("198.51.100.21"), Peer: netip.MustParseAddr("203.0.113.34")},
		Addresses:  desiredLinkAddressesV1{Local: netip.MustParsePrefix("10.75.0.1/30"), Peer: netip.MustParsePrefix("10.75.0.2/30")},
		ListenPort: 51821, PeerPort: 51822, Role: "listen", TCPPort: 59443,
		RemoteForwardUDPPort: 53001, LocalKeepalive: 25, PeerKeepalive: 25,
	}
}
func TestR1WSSOfferRoundTripAndSecretsStayOutOfState(t *testing.T) {
	r := testWSSCreateRequest()
	senderKey, senderPub, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer senderKey.Zeroize()
	peerKey, peerPub, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer peerKey.Zeroize()
	sender, peer, err := makeWSSPair(r, r.LinkID, senderPub, peerPub)
	if err != nil {
		t.Fatalf("wss pairing: %v", err)
	}
	serverBundle, clientBundle, err := wss.GeneratePair(r.LinkID, "198.51.100.21")
	if err != nil {
		t.Fatal(err)
	}
	defer serverBundle.Clear()
	defer clientBundle.Clear()
	offer := wssOffer{SchemaVersion: 1, Sender: sender, Receiver: peer,
		ReceiverWGKey: peerKey.SecretWireValue(), ReceiverTLS: clientBundle}
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, contents, err := decodeWSSOffer(bytes.NewReader(append(raw, '\n')))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	defer rebuilt.clear()
	if string(raw) != string(contents) || rebuilt.Sender != sender || rebuilt.Receiver != peer {
		t.Fatal("WSS handoff identity mismatch")
	}
	generic, _ := json.Marshal(sender)
	if bytes.Contains(generic, []byte(peerKey.SecretWireValue())) ||
		bytes.Contains(generic, clientBundle["client-key.pem"]) ||
		strings.Contains(string(generic), "authorization-headers") {
		t.Fatal("secret material leaked to public desired State")
	}
	tampered := rebuilt
	tampered.Receiver.WireGuard.ListenPort++
	if tampered.validate() == nil {
		t.Fatal("accepted a nonreciprocal WSS peer port")
	}
	other := testWSSCreateRequest()
	other.Role = "dial"
	other.LocalForwardUDPPort = 53004
	other.RemoteForwardUDPPort = 53006
	if _, _, err = makeWSSPair(other, other.LinkID, senderPub, peerPub); err == nil {
		t.Fatal("accepted remote listening side with an irrelevant UDP forwarder")
	}
}
