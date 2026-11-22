//go:build linux

package spoofhost

import (
	"crypto/rand"
	"net/netip"
	"testing"

	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Regression: an old Source remains in sources.txt while the actual path
// silently fails. A fresh authenticated-enrollment attempt MUST not reply
// exclusively via the old selected Source. The first response is probed over
// the bounded local inventory; only an authenticated ack can pin a successor.
func TestFreshCreatorHandshakeDiscardsStaleSelectedSource(t *testing.T) {
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	aPriv, aPub, err := carrier.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bPriv, _, err := carrier.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	material, err := NewMaterial(id, "creator", aPriv, secret)
	if err != nil {
		t.Fatal(err)
	}
	link := domain.Link{
		ID: id,
		Underlay: domain.Underlay{
			Local: netip.MustParseAddr("10.244.62.207"),
			Peer:  netip.MustParseAddr("10.244.62.198")},
		Addresses: domain.LinkAddresses{
			Local: netip.MustParsePrefix("10.245.62.1/32"),
			Peer:  netip.MustParsePrefix("10.245.62.2/32")},
		Spoof: domain.SpoofOptions{ListenPort: 42001, PeerPort: 42002},
	}
	a := newAgent(t.TempDir(), link, material, nil)
	a.inventory = carrier.Inventory{Addresses: []netip.Addr{
		netip.MustParseAddr("198.18.0.11"), netip.MustParseAddr("198.18.0.99")}}
	// The dummy sender cannot send and requires no socket/root; receipt of a
	// valid first Noise frame still updates the pure local handshake state.
	a.sender = &carrier.RawSender{}
	a.chosen = netip.MustParseAddr("198.18.0.11")
	attempt, err := carrier.NewAttempt()
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.handshakeConfig(attempt)
	cfg.Role = carrier.RoleRecipient
	cfg.LocalPrivateKey = bPriv
	cfg.PeerPublicKey = aPub[:]
	initiator, err := carrier.NewHandshake(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.Start()
	if err != nil {
		t.Fatal(err)
	}
	frame := carrier.Frame{LinkID: id, Attempt: attempt, Kind: carrier.KindHandshake1, Payload: first}
	_ = a.received(frame, netip.MustParseAddrPort("198.18.0.12:42002"))
	if a.handshake == nil || a.pendingKind != carrier.KindHandshake2 {
		t.Fatal("valid fresh session request not adopted")
	}
	if a.chosen.IsValid() {
		t.Fatalf("old selected Source leaked into fresh handshake: %s", a.chosen)
	}
	if a.connected || a.session != nil {
		t.Fatal("fresh attempt incorrectly inherited old established session")
	}
}
