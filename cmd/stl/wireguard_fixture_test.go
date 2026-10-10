package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// completeWireGuardFixture makes CLI redaction/denial tests exercise the
// current, complete public-identity pairing contract. No real credentials,
// host interface, or network mutations are used.
func completeWireGuardFixture(t *testing.T, link *domain.Link, receiverSecret string) {
	t.Helper()
	receiver, err := base64.StdEncoding.Strict().DecodeString(receiverSecret)
	if err != nil || len(receiver) != 32 {
		t.Fatal("invalid synthetic recipient key")
	}
	toPublic := func(secret []byte) string {
		t.Helper()
		key, err := ecdh.X25519().NewPrivateKey(secret)
		if err != nil {
			t.Fatal("invalid synthetic WireGuard key", err)
		}
		return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	link.WireGuard = domain.WireGuardOptions{
		LocalPublicKey: toPublic(bytes.Repeat([]byte{0x43}, 32)),
		PeerPublicKey:  toPublic(receiver),
		ListenPort:     51820,
		PeerPort:       51821,
		LocalKeepalive: 0,
		PeerKeepalive:  25,
	}
}
