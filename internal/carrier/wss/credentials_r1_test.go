package wss

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestR1GeneratedPerLinkMTLSAndBearer(t *testing.T) {
	server := wssTestLink()
	server.Backend = domain.BackendWireGuardWSS
	server.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443, TLSServerName: "198.51.100.21"}
	client := server
	client.WSS = domain.WSSOptions{Role: "dial", TCPPort: 59443, ForwardUDPPort: 53001, TLSServerName: "198.51.100.21"}
	client.Underlay.Local, client.Underlay.Peer = server.Underlay.Peer, server.Underlay.Local
	client.Addresses.Local, client.Addresses.Peer = server.Addresses.Peer, server.Addresses.Local
	client.WireGuard.ListenPort, client.WireGuard.PeerPort = server.WireGuard.PeerPort, server.WireGuard.ListenPort
	client.WireGuard.LocalPublicKey, client.WireGuard.PeerPublicKey = server.WireGuard.PeerPublicKey, server.WireGuard.LocalPublicKey
	listen, dial, err := GeneratePair(server.ID, "198.51.100.21")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	// Issued leaves must reference the actual generated CA SubjectKeyId.
	// Without AuthorityKeyId, strict OpenSSL/Python rejects the chain even
	// though Go and some pinned TLS stacks accept it.
	parseIssued := func(raw []byte) *x509.Certificate {
		t.Helper()
		block, trailing := pem.Decode(raw)
		if block == nil || len(trailing) != 0 || block.Type != "CERTIFICATE" {
			t.Fatal("invalid generated certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	ca := parseIssued(listen["client-ca.pem"])
	if len(ca.SubjectKeyId) == 0 || !bytes.Equal(listen["client-ca.pem"], dial["server-ca.pem"]) {
		t.Fatal("trust authority identity differs across paired WSS endpoints")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, example := range []struct {
		leaf    []byte
		usage   x509.ExtKeyUsage
		dnsName string
	}{
		{listen["server-cert.pem"], x509.ExtKeyUsageServerAuth, "198.51.100.21"},
		{dial["client-cert.pem"], x509.ExtKeyUsageClientAuth, ""},
	} {
		leaf := parseIssued(example.leaf)
		if len(leaf.AuthorityKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
			t.Fatal("WSS leaf lacks the matching issuer AuthorityKeyId")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{example.usage}, DNSName: example.dnsName}); err != nil {
			t.Fatalf("WSS issued leaf chain or name invalid: %v", err)
		}
	}
	if bytes.Equal(listen["server-key.pem"], dial["client-key.pem"]) {
		t.Fatal("mTLS peers share private signing material")
	}
	for _, tc := range []struct {
		link  domain.Link
		files PrivateBundle
	}{{server, listen}, {client, dial}} {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := Stage(root, tc.link, tc.files); err != nil {
			t.Fatalf("stage: %v", err)
		}
		fp, err := InspectCredentials(tc.link, composition.CarrierForLink(tc.link), root)
		if err != nil || fp.CertificateSHA256 == "" || fp.AuthorizationSHA256 == "" {
			t.Fatalf("inspect: %+v / %v", fp, err)
		}
		if err := Stage(root, tc.link, tc.files); err != nil {
			t.Fatalf("idempotent staging: %v", err)
		}
		secretPath := filepath.Join(root, "credentials", "wss", string(tc.link.ID))
		name := "client-key.pem"
		if tc.link.WSS.Role == "listen" {
			name = "server-key.pem"
		}
		if err := os.Chmod(filepath.Join(secretPath, name), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectCredentials(tc.link, composition.CarrierForLink(tc.link), root); err == nil {
			t.Fatal("accepted publicly readable WSS private key")
		}
	}
}

func TestR1PrivateNoReplaceRejectsClobber(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "config")
	if err := WritePrivateNoReplace(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateNoReplace(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateNoReplace(p, []byte("different")); err == nil {
		t.Fatal("overwrote protected credential")
	}
	original, err := os.ReadFile(p)
	if err != nil || string(original) != "one" {
		t.Fatalf("credential mutated: %v", err)
	}
	_ = context.Background()
}
