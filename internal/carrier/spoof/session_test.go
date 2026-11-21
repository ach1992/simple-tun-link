package spoof

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func pairForTest(t *testing.T) (*Handshake, *Handshake, *Session, *Session) {
	t.Helper()
	aPriv, aPub, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bPriv, bPub, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var shared [32]byte
	copy(shared[:], bytes.Repeat([]byte{0x65}, 32))
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	attempt, err := NewAttempt()
	if err != nil {
		t.Fatal(err)
	}
	config := HandshakeConfig{
		LinkID: id, Attempt: attempt, CreatorEndpoint: netip.MustParseAddrPort("198.51.100.9:34009"),
		RecipientEndpoint: netip.MustParseAddrPort("203.0.113.8:34008"),
		CreatorPrivateIP:  netip.MustParseAddr("10.99.4.0"), RecipientPrivateIP: netip.MustParseAddr("10.99.4.1"),
		BootstrapSecret: shared,
	}
	aConfig := config
	aConfig.Role, aConfig.LocalPrivateKey = RoleCreator, aPriv
	bConfig := config
	bConfig.Role, bConfig.LocalPrivateKey, bConfig.PeerPublicKey = RoleRecipient, bPriv, aPub[:]
	a, err := NewHandshake(aConfig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewHandshake(bConfig)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := b.Start()
	if err != nil {
		t.Fatal(err)
	}
	m2, early, err := a.Handle(m1)
	if err != nil || early != nil {
		t.Fatalf("creator m1: %v %+v", err, early)
	}
	m3, bs, err := b.Handle(m2)
	if err != nil || bs == nil {
		t.Fatalf("recipient m2: %v %+v", err, bs)
	}
	out, as, err := a.Handle(m3)
	if err != nil || as == nil || len(out) != 0 {
		t.Fatalf("creator m3: %v %+v", err, as)
	}
	if as.PeerPublicKey() != bPub || bs.PeerPublicKey() != aPub ||
		!bytes.Equal(as.ChannelBinding(), bs.ChannelBinding()) {
		t.Fatal("Noise identities or transcript differ")
	}
	return a, b, as, bs
}

func TestNoiseXKpsk0BilateralEncryptedDatagramsAndReplay(t *testing.T) {
	a, b, as, bs := pairForTest(t)
	_ = a
	_ = b
	raw, err := as.Seal(KindData, []byte("private IPv4 A to B"))
	if err != nil {
		t.Fatal(err)
	}
	kind, plain, err := bs.Open(raw)
	if err != nil || kind != KindData || string(plain) != "private IPv4 A to B" {
		t.Fatalf("A->B: %d %q %v", kind, plain, err)
	}
	if _, _, err = bs.Open(raw); err == nil {
		t.Fatal("replay must be rejected")
	}
	other, err := bs.Seal(KindKeepalive, []byte("challenge"))
	if err != nil {
		t.Fatal(err)
	}
	kind, plain, err = as.Open(other)
	if err != nil || kind != KindKeepalive || string(plain) != "challenge" {
		t.Fatalf("B->A: %d %q %v", kind, plain, err)
	}
	third, err := as.Seal(KindData, []byte("integrity"))
	if err != nil {
		t.Fatal(err)
	}
	third[len(third)-1] ^= 0x80
	if _, _, err = bs.Open(third); err == nil {
		t.Fatal("ciphertext tampering must fail")
	}
	third[len(third)-1] ^= 0x80
	if _, plain, err = bs.Open(third); err != nil || string(plain) != "integrity" {
		t.Fatalf("failed integrity must not consume sequence: %q %v", plain, err)
	}
	if _, _, err = bs.Open(raw); err == nil {
		t.Fatal("older authenticated duplicate must still fail")
	}
}

func TestNoisePacketsMayArriveOutOfOrderButNotBeReplayed(t *testing.T) {
	_, _, as, bs := pairForTest(t)
	var frames [][]byte
	for i := 0; i < 75; i++ {
		frame, err := as.Seal(KindData, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	for _, idx := range []int{73, 74, 72, 0} {
		kind, _, err := bs.Open(frames[idx])
		if idx == 0 && err == nil {
			t.Fatal("packet outside replay window accepted")
		}
		if idx != 0 && (err != nil || kind != KindData) {
			t.Fatalf("reordered frame %d: %v", idx, err)
		}
	}
	if _, _, err := bs.Open(frames[72]); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestNoiseRejectsWrongPSKAndBoundIdentityChange(t *testing.T) {
	aPriv, aPub, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bPriv, _, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPub, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewAttempt()
	if err != nil {
		t.Fatal(err)
	}
	config := HandshakeConfig{
		LinkID:  domain.LinkID("lnk_0123456789abcdef0123456789abcdef"),
		Attempt: attempt, CreatorEndpoint: netip.MustParseAddrPort("192.0.2.10:14001"),
		RecipientEndpoint: netip.MustParseAddrPort("192.0.2.11:14002"),
		CreatorPrivateIP:  netip.MustParseAddr("10.1.1.0"), RecipientPrivateIP: netip.MustParseAddr("10.1.1.1"),
	}
	config.BootstrapSecret[0] = 7
	aConfig := config
	aConfig.Role, aConfig.LocalPrivateKey = RoleCreator, aPriv
	bConfig := config
	bConfig.Role, bConfig.LocalPrivateKey, bConfig.PeerPublicKey = RoleRecipient, bPriv, aPub[:]
	bConfig.BootstrapSecret[0] = 8
	a, err := NewHandshake(aConfig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewHandshake(bConfig)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := b.Start()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Handle(m1); err == nil {
		t.Fatal("wrong confidential bootstrap secret accepted")
	}

	bConfig.BootstrapSecret = aConfig.BootstrapSecret
	b, err = NewHandshake(bConfig)
	if err != nil {
		t.Fatal(err)
	}
	aConfig.PeerPublicKey = wrongPub[:]
	a, err = NewHandshake(aConfig)
	if err != nil {
		t.Fatal(err)
	}
	m1, err = b.Start()
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
	_, _, err = a.Handle(m3)
	if err == nil || !strings.Contains(err.Error(), "already-bound") {
		t.Fatalf("bound identity must not be replaced: %v", err)
	}
}

func TestSpoofEnvelopeValidation(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	f := Frame{LinkID: id, Kind: KindHandshake1, Payload: []byte("hello")}
	raw, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeFrame(raw)
	if err != nil || parsed.LinkID != id || string(parsed.Payload) != "hello" {
		t.Fatalf("round trip: %+v %v", parsed, err)
	}
	raw[4]++
	if _, err := DecodeFrame(raw); err == nil {
		t.Fatal("unknown wire version accepted")
	}
	raw[4]--
	if _, err := DecodeFrame(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated envelope accepted")
	}
}

func TestNoiseConfigRejectsRealEndpointAndSecretErrors(t *testing.T) {
	_, err := NewHandshake(HandshakeConfig{})
	if err == nil {
		t.Fatal("zero setup accepted")
	}
}
