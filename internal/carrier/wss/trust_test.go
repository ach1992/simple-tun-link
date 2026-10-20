package wss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

type fixtureTLS struct{ ca, cert, key []byte }

func issueFixtureTLS(t *testing.T, cn string, isServer, expired bool) fixtureTLS {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "STL test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if expired {
		leaf.NotBefore, leaf.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	if isServer {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		leaf.IPAddresses = []net.IP{net.ParseIP("198.51.100.21")}
		leaf.DNSNames = []string{"server.example"}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureTLS{
		ca:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	}
}

func writeTLSFixture(t *testing.T, root string, id domain.LinkID, role composition.Role, f fixtureTLS) string {
	t.Helper()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "credentials", "wss", string(id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{filepath.Join(root, "credentials"), filepath.Join(root, "credentials", "wss"), dir} {
		if err := os.Chmod(component, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{}
	if role == composition.Dial {
		files = map[string][]byte{"server-ca.pem": f.ca, "client-cert.pem": f.cert, "client-key.pem": f.key}
	} else {
		files = map[string][]byte{"client-ca.pem": f.ca, "server-cert.pem": f.cert, "server-key.pem": f.key}
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func carrierForTLS(l domain.Link, role composition.Role) composition.Carrier {
	c := composition.Carrier{Kind: composition.WSS, Role: role, PublicTCPPort: 59443, CredentialOwner: l.ID}
	if role == composition.Dial {
		c.LocalForwardUDP = 53001
	}
	return c
}

func TestInspectCredentialsRejectsUnsafeMaterials(t *testing.T) {
	for _, role := range []composition.Role{composition.Dial, composition.Listen} {
		t.Run(string(role)+"-valid", func(t *testing.T) {
			l := wssTestLink()
			cn := clientCN(l.ID)
			if role == composition.Listen {
				cn = "stl-server"
			}
			root := t.TempDir()
			writeTLSFixture(t, root, l.ID, role, issueFixtureTLS(t, cn, role == composition.Listen, false))
			got, err := InspectCredentials(l, carrierForTLS(l, role), root)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.CertificateSHA256) != 64 || len(got.TrustCASHA256) != 64 {
				t.Fatal("bad secret-free fingerprints")
			}
		})
	}
	l := wssTestLink()
	dial := carrierForTLS(l, composition.Dial)
	for _, tc := range []struct {
		name      string
		fixtureCN string
		expired   bool
		mutate    func(*testing.T, string, string)
	}{
		{"wrong-CN", "stl-foreign", false, nil},
		{"expired", clientCN(l.ID), true, nil},
		{"wrong-tls-purpose", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			f := issueFixtureTLS(t, clientCN(l.ID), true, false)
			if err := os.WriteFile(filepath.Join(dir, "client-cert.pem"), f.cert, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "client-key.pem"), f.key, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong-private-key", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			other := issueFixtureTLS(t, "another", false, false)
			if err := os.WriteFile(filepath.Join(dir, "client-key.pem"), other.key, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"non-CA-trust", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			f := issueFixtureTLS(t, "not-a-ca", false, false)
			if err := os.WriteFile(filepath.Join(dir, "server-ca.pem"), f.cert, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-CA", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			if err := os.Remove(filepath.Join(dir, "server-ca.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{"key-exposed", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			if err := os.Chmod(filepath.Join(dir, "client-key.pem"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink-key", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			key := filepath.Join(dir, "client-key.pem")
			backup := filepath.Join(dir, "backup.pem")
			if err := os.Rename(key, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(backup, key); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink-key", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			if err := os.Link(filepath.Join(dir, "client-key.pem"), filepath.Join(dir, "other.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{"shared-directory", clientCN(l.ID), false, func(t *testing.T, dir, root string) {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := writeTLSFixture(t, root, l.ID, composition.Dial, issueFixtureTLS(t, tc.fixtureCN, false, tc.expired))
			if tc.mutate != nil {
				tc.mutate(t, dir, root)
			}
			if _, err := InspectCredentials(l, dial, root); err == nil {
				t.Fatal("accepted invalid protected TLS material")
			}
		})
	}
	t.Run("server-DNS-SAN-identity", func(t *testing.T) {
		root := t.TempDir()
		link := wssTestLink()
		f := issueFixtureTLS(t, "stl-server", true, false)
		role := carrierForTLS(link, composition.Listen)
		role.TLSServerName = "server.example"
		writeTLSFixture(t, root, link.ID, composition.Listen, f)
		if _, err := InspectCredentials(link, role, root); err != nil {
			t.Fatalf("valid explicitly selected server DNS SAN rejected: %v", err)
		}
		role.TLSServerName = "wrong.example"
		if _, err := InspectCredentials(link, role, root); err == nil {
			t.Fatal("server certificate without selected DNS SAN accepted")
		}
	})
	t.Run("server-SAN-mismatch", func(t *testing.T) {
		root := t.TempDir()
		link := wssTestLink()
		link.Underlay.Local = netip.MustParseAddr("192.0.2.20")
		writeTLSFixture(t, root, link.ID, composition.Listen, issueFixtureTLS(t, "stl-server", true, false))
		if _, err := InspectCredentials(link, carrierForTLS(link, composition.Listen), root); err == nil {
			t.Fatal("server identity mismatch admitted")
		}
	})
}

func TestInspectPinnedExecutableRequiresExactProtectedInode(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "wstunnel")
	raw := []byte("#!/bin/sh\necho test\n")
	if err := os.WriteFile(filename, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	identity, err := InspectPinnedExecutable(filename, digest)
	if err != nil {
		t.Fatal(err)
	}
	if identity.SHA256 != digest || identity.Inode == 0 {
		t.Fatalf("wrong identity: %+v", identity)
	}
	if _, err := InspectPinnedExecutable(filename, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest admitted")
	}
	if err := os.Chmod(filename, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectPinnedExecutable(filename, digest); err == nil {
		t.Fatal("foreign-writable binary admitted")
	}
	if err := os.Chmod(filename, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filename, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectPinnedExecutable(filename, digest); err == nil {
		t.Fatal("hardlinked binary admitted")
	}
	if err := os.Remove(filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filename, filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectPinnedExecutable(filepath.Join(root, "symlink"), digest); err == nil {
		t.Fatal("symlink binary admitted")
	}
}

func TestPinnedOfficialWstunnelV11BinaryWhenAvailable(t *testing.T) {
	binary := os.Getenv("STL_WSTUNNEL_V11_BIN")
	if binary == "" {
		t.Skip("pinned upstream test is opt-in")
	}
	pin := "6a1d6ab8f4537823d0a8157416b264fa1313253574143e3900eba93e17c6de49"
	if _, err := InspectPinnedExecutable(binary, pin); err != nil {
		t.Fatal(err)
	}
}
