package quic

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func clearProtectedCopies(files map[string][]byte) {
	for name, value := range files {
		clear(value)
		delete(files, name)
	}
}

func verifyIssuedPair(t *testing.T, name string) (string, []byte, []byte) {
	t.Helper()
	id := domainTestLinkID()
	listen, dial, err := GeneratePair(id, name)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	if strings.Contains(fmt.Sprintf("%+v %#v", listen, dial), "PRIVATE KEY") ||
		!strings.Contains(fmt.Sprintf("%#v", listen), "REDACTED") {
		t.Fatal("credential bundle formatting must redact private fields")
	}
	marshaled, err := json.Marshal(listen)
	if err != nil || string(marshaled) != "{}" {
		t.Fatal("private bundle must not serialize as a public JSON object")
	}
	serverFiles := listen.ProtectedFiles()
	clientFiles := dial.ProtectedFiles()
	defer clearProtectedCopies(serverFiles)
	defer clearProtectedCopies(clientFiles)
	if len(serverFiles) != 4 || len(clientFiles) != 4 {
		t.Fatal("each QUIC role must receive exactly its four own private files")
	}
	for _, key := range []string{"server-cert.pem", "server-key.pem", "client-ca.pem", "authorization-token"} {
		if len(serverFiles[key]) == 0 {
			t.Fatalf("missing server-only %s", key)
		}
	}
	for _, key := range []string{"client-cert.pem", "client-key.pem", "server-ca.pem", "authorization-token"} {
		if len(clientFiles[key]) == 0 {
			t.Fatalf("missing client-only %s", key)
		}
	}
	token := strings.TrimSuffix(string(serverFiles["authorization-token"]), "\n")
	if len(token) != 64 || !validToken(token) ||
		!bytes.Equal(serverFiles["authorization-token"], clientFiles["authorization-token"]) ||
		bytes.Equal(serverFiles["client-ca.pem"], clientFiles["server-ca.pem"]) {
		t.Fatal("issued per-Link token/independent trust authorities invalid")
	}

	serverPair, err := tls.X509KeyPair(serverFiles["server-cert.pem"], serverFiles["server-key.pem"])
	if err != nil {
		t.Fatal("invalid server key pair:", err)
	}
	clientPair, err := tls.X509KeyPair(clientFiles["client-cert.pem"], clientFiles["client-key.pem"])
	if err != nil {
		t.Fatal("invalid client key pair:", err)
	}
	serverLeaf, err := x509.ParseCertificate(serverPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	serverRoots := x509.NewCertPool()
	clientRoots := x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(clientFiles["server-ca.pem"]) ||
		!clientRoots.AppendCertsFromPEM(serverFiles["client-ca.pem"]) {
		t.Fatal("issued CA trust is invalid PEM")
	}
	if _, err := serverLeaf.Verify(x509.VerifyOptions{
		Roots: serverRoots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatal("issued server SAN/identity is not trusted:", err)
	}
	if _, err := clientLeaf.Verify(x509.VerifyOptions{
		Roots: clientRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatal("issued client certificate is not trusted:", err)
	}
	if _, err := serverLeaf.Verify(x509.VerifyOptions{
		Roots: clientRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("client authority must not authorize a server")
	}
	if _, err := clientLeaf.Verify(x509.VerifyOptions{
		Roots: serverRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("server authority must not authorize a client")
	}

	// Caller-owned copies cannot mutate the original in-memory bundle.
	serverFiles["server-key.pem"][0] ^= 1
	second := listen.ProtectedFiles()
	if bytes.Equal(serverFiles["server-key.pem"], second["server-key.pem"]) {
		t.Fatal("secret material must be returned by independent allocation")
	}
	clearProtectedCopies(second)
	return token, append([]byte(nil), serverFiles["client-ca.pem"]...),
		append([]byte(nil), clientFiles["server-ca.pem"]...)
}

func TestIssuedQUICCredentialsDNSAndPhysicalIPSAN(t *testing.T) {
	for _, name := range []string{"quic-probe.invalid", "193.0.2.15", "127.0.0.1"} {
		t.Run(name, func(t *testing.T) {
			token1, clientCA1, serverCA1 := verifyIssuedPair(t, name)
			defer clear(clientCA1)
			defer clear(serverCA1)
			token2, clientCA2, serverCA2 := verifyIssuedPair(t, name)
			defer clear(clientCA2)
			defer clear(serverCA2)
			if token1 == token2 || bytes.Equal(clientCA1, clientCA2) || bytes.Equal(serverCA1, serverCA2) {
				t.Fatal("separately generated per-Link credential sets must not share secrets/trust")
			}
		})
	}
}

func TestRejectUntrustedQUICCredentialIssuance(t *testing.T) {
	for _, name := range []string{"", "example", "EXAMPLE.com", "-bad.example", "bad..example",
		"example.com.", "http://example.com", "2001:db8::1", "0.0.0.0", "bad name.invalid"} {
		t.Run(name, func(t *testing.T) {
			server, client, err := GeneratePair(domainTestLinkID(), name)
			if err == nil || len(server.ProtectedFiles()) != 0 || len(client.ProtectedFiles()) != 0 {
				t.Fatal("must refuse invalid QUIC TLS identity before generating credentials")
			}
		})
	}
	server, client, err := GeneratePair(domain.LinkID("foreign"), "quic-probe.invalid")
	if err == nil || len(server.ProtectedFiles()) != 0 || len(client.ProtectedFiles()) != 0 {
		t.Fatal("must refuse invalid Link owner")
	}
}

func TestIssuedTokenMatchesBuilderAndClear(t *testing.T) {
	server, client, err := GeneratePair(domainTestLinkID(), "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	secret := client.ProtectedFiles()
	defer clearProtectedCopies(secret)
	token := strings.TrimSuffix(string(secret["authorization-token"]), "\n")
	p := fixturePlan(Dial)
	p.LocalForwardUDPPort = 52010
	p.PeerWGUDPPort = 51820
	if _, err := Build(p, "/opt/stl/hysteria", "/var/lib/simple-tun-link", token); err != nil {
		t.Fatalf("separately issued credential rejected by builder: %v", err)
	}
	server.Clear()
	client.Clear()
	if len(server.ProtectedFiles()) != 0 || len(client.ProtectedFiles()) != 0 {
		t.Fatal("cleared bundles must not retain private file entries")
	}
	// A generator accepting arbitrary IP SANs must not circumvent Build's
	// exact peer IP binding when the actual underlay is selected.
	p.TLSName = netip.MustParseAddr("203.0.113.46").String()
	if _, err := Build(p, "/opt/stl/hysteria", "/var/lib/simple-tun-link", token); err == nil {
		t.Fatal("certificate issuance cannot override exact physical peer identity")
	}
}
