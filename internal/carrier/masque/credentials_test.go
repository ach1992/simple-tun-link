package masque

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestGeneratedMASQUEIdentitiesAreAuthenticatedAndDistinct(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	pair, err := GeneratePair(id, "masque.private.example", 365)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Clear()
	if len(pair.ServerPrivateKey) == 0 || len(pair.ClientPrivateKey) == 0 || string(pair.ServerPrivateKey) == string(pair.ClientPrivateKey) {
		t.Fatal("MASQUE requires two distinct private identities")
	}
	server, err := tls.X509KeyPair(pair.ServerCertificate, pair.ServerPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	client, err := tls.X509KeyPair(pair.ClientCertificate, pair.ClientPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.ParseCertificate(client.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(pair.ClientSPKIBase64)
	if string(raw) != string(public.RawSubjectPublicKeyInfo) {
		t.Fatal("listener's authorized SPKI differs from client cert")
	}
	cfg := H2ListenConfig{
		ListenAddress: "127.0.0.1:443", TLSServerName: "masque.private.example",
		ServerCert: server, PeerSPKI: raw, LocalIPv4: netip.MustParseAddr("10.251.95.1"), PeerIPv4: netip.MustParseAddr("10.251.95.2"),
	}
	s, err := NewH2Server(cfg, &channelPrivatePipe{})
	if err != nil {
		t.Fatal(err)
	}
	if s.TLSConfig().MinVersion != tls.VersionTLS12 {
		t.Fatal("TLS minimum invalid")
	}
}

func TestMASQUEIssuerRejectsInvalidNameAndLifetime(t *testing.T) {
	id := domain.LinkID("lnk_0123456789abcdef0123456789abcdef")
	for _, days := range []int{0, -1, 36501} {
		if _, err := GeneratePair(id, "masque.example.com", days); err == nil {
			t.Fatalf("accepted invalid expiry %d", days)
		}
	}
	if _, err := GeneratePair("incorrect", "masque.example.com", 365); err == nil {
		t.Fatal("accepted invalid Link ID")
	}
}
