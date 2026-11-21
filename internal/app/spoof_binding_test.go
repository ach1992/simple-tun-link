package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func spoofBindingSession(t *testing.T, id domain.LinkID, aPriv, bPriv [32]byte, aPub [32]byte) *spoof.Session {
	t.Helper()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	attempt, err := spoof.NewAttempt()
	if err != nil {
		t.Fatal(err)
	}
	c := spoof.HandshakeConfig{
		Role: spoof.RoleCreator, LinkID: id, Attempt: attempt,
		CreatorEndpoint:    netip.MustParseAddrPort("198.51.100.10:22501"),
		RecipientEndpoint:  netip.MustParseAddrPort("203.0.113.11:22502"),
		CreatorPrivateIP:   netip.MustParseAddr("10.34.5.0"),
		RecipientPrivateIP: netip.MustParseAddr("10.34.5.1"),
		LocalPrivateKey:    aPriv, BootstrapSecret: secret,
	}
	a, err := spoof.NewHandshake(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Role = spoof.RoleRecipient
	c.LocalPrivateKey = bPriv
	c.PeerPublicKey = aPub[:]
	b, err := spoof.NewHandshake(c)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := b.Start()
	if err != nil {
		t.Fatal(err)
	}
	m2, _, err := a.Handle(m1)
	if err != nil {
		t.Fatal(err)
	}
	m3, _, err := b.Handle(m2)
	if err != nil {
		t.Fatal(err)
	}
	_, auth, err := a.Handle(m3)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestSpoofPeerFirstEnrollmentIsEngineOwnedAndImmutable(t *testing.T) {
	engine, store := newEngine(t, newFakeBackend())
	aPriv, aPub, err := spoof.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bPriv, bPub, err := spoof.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	link := domain.Link{
		ID: id, Backend: domain.BackendSpoof, Encapsulation: domain.EncapUDP,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("198.51.100.10"), Peer: netip.MustParseAddr("203.0.113.11")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.34.5.0/32"), Peer: netip.MustParsePrefix("10.34.5.1/32")},
		Spoof: domain.SpoofOptions{Role: "creator", SourceFile: "/root/stl/spoof/sources.txt",
			ListenPort: 22501, PeerPort: 22502, LocalPublicKey: base64.RawURLEncoding.EncodeToString(aPub[:]),
			MaterialSHA256: strings.Repeat("a", 64)},
	}
	err = store.Update(context.Background(), func(s *state.Snapshot) error {
		s.Upsert(state.LinkRecord{Desired: link})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := spoofBindingSession(t, id, aPriv, bPriv, aPub)
	first, err := engine.BindAuthenticatedSpoofPeer(context.Background(), s)
	if err != nil || !first {
		t.Fatalf("first binding: %t %v", first, err)
	}
	repeated, err := engine.BindAuthenticatedSpoofPeer(context.Background(), s)
	if err != nil || repeated {
		t.Fatalf("repeat binding: %t %v", repeated, err)
	}
	saved, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	committed, _ := saved.Find(id)
	if committed.Desired.Spoof.PeerPublicKey != base64.RawURLEncoding.EncodeToString(bPub[:]) {
		t.Fatal("creator did not durably pin B identity")
	}
	otherPriv, _, err := spoof.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other := spoofBindingSession(t, id, aPriv, otherPriv, aPub)
	if changed, err := engine.BindAuthenticatedSpoofPeer(context.Background(), other); err == nil || changed {
		t.Fatal("a different B identity replaced pinned peer")
	}
	wrongPriv, wrongPub, err := spoof.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	faked := spoofBindingSession(t, id, wrongPriv, otherPriv, wrongPub)
	if changed, err := engine.BindAuthenticatedSpoofPeer(context.Background(), faked); err == nil || changed {
		t.Fatal("a session made without original A static secret was enrolled")
	}
}
