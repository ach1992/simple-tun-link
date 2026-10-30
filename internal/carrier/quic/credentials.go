// Package quic keeps credentials separate from public QUIC topology.
// Generating a bundle has no host side effects and does not authorize
// installation, persistence, pairing, or starting an external helper.
package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// CredentialBundle is secret-bearing, even on the server role. Callers must
// place its contents only in the exact Link's protected 0600 directory or
// an explicitly secured pairing handoff. Neither bundle nor its file bytes
// belong in public Link State, logs, argv or machine responses.
type CredentialBundle struct {
	files map[string][]byte
}

func (b CredentialBundle) String() string   { return "QUIC credentials [REDACTED]" }
func (b CredentialBundle) GoString() string { return b.String() }

// ProtectedFiles returns independently allocated sensitive bytes. The caller
// owns the copies and must clear them after protected use. No filesystem I/O
// occurs here; staging requires the existing Engine's owner/Link lock and
// checked descriptor-relative 0600, no-replace file operations.
func (b CredentialBundle) ProtectedFiles() map[string][]byte {
	out := make(map[string][]byte, len(b.files))
	for name, raw := range b.files {
		out[name] = append([]byte(nil), raw...)
	}
	return out
}

// Clear zeroes this bundle's sensitive byte slices and discards their names.
// Do not retain a duplicate bundle value: copies share the underlying map.
func (b *CredentialBundle) Clear() {
	for name, raw := range b.files {
		clear(raw)
		delete(b.files, name)
	}
	b.files = nil
}

// GeneratePair issues two independently signed per-Link TLS identities and
// one unrelated cryptographically random 256-bit authorization token.
// Server and client CA private signing keys are NEVER exported or persisted.
// Neither peer receives the other's leaf private key. The helper's TLS
// handshake and bearer authentication must still be checked at runtime.
//
// The issuing server identity is syntax-validated here; Build separately
// binds any IP SAN to the physical endpoint. This function does not write
// private files, install packages or change host state.
func GeneratePair(id domain.LinkID, tlsName string) (listen, dial CredentialBundle, err error) {
	return GeneratePairWithObfuscation(id, tlsName, domain.QUICObfuscationPlain)
}

// GeneratePairWithObfuscation adds an independently generated 256-bit shared
// Salamander password only for that explicitly selected mode. TLS identities
// and bearer authentication retain the same independent issuance policy.
func GeneratePairWithObfuscation(id domain.LinkID, tlsName, mode string) (listen, dial CredentialBundle, err error) {
	if id.Validate() != nil || !validIssuingName(tlsName) || !domain.ValidQUICObfuscation(mode) {
		return CredentialBundle{}, CredentialBundle{}, errors.New("invalid QUIC Link owner, TLS identity or obfuscation mode")
	}

	now := time.Now()
	serverCA, serverCAKey, serverCAPEM, err := generateCA("STL QUIC server CA", now)
	if err != nil {
		return CredentialBundle{}, CredentialBundle{}, fmt.Errorf("issue QUIC server authority: %w", err)
	}
	clientCA, clientCAKey, clientCAPEM, err := generateCA("STL QUIC client CA", now)
	if err != nil {
		clear(serverCAPEM)
		return CredentialBundle{}, CredentialBundle{}, fmt.Errorf("issue QUIC client authority: %w", err)
	}
	serverCert, serverKey, err := generateLeaf(serverCA, serverCAKey,
		"STL QUIC server "+string(id), tlsName, x509.ExtKeyUsageServerAuth, now)
	if err != nil {
		clear(serverCAPEM)
		clear(clientCAPEM)
		return CredentialBundle{}, CredentialBundle{}, fmt.Errorf("issue QUIC server identity: %w", err)
	}
	clientCert, clientKey, err := generateLeaf(clientCA, clientCAKey,
		"STL QUIC client "+string(id), "", x509.ExtKeyUsageClientAuth, now)
	if err != nil {
		clear(serverCAPEM)
		clear(clientCAPEM)
		clear(serverCert)
		clear(serverKey)
		return CredentialBundle{}, CredentialBundle{}, fmt.Errorf("issue QUIC client identity: %w", err)
	}
	var randomToken [32]byte
	if _, err := rand.Read(randomToken[:]); err != nil {
		clear(serverCAPEM)
		clear(clientCAPEM)
		clear(serverCert)
		clear(serverKey)
		clear(clientCert)
		clear(clientKey)
		return CredentialBundle{}, CredentialBundle{}, errors.New("could not issue QUIC authorization secret")
	}
	token := []byte(hex.EncodeToString(randomToken[:]))
	clear(randomToken[:])
	listen = CredentialBundle{files: map[string][]byte{
		"server-cert.pem":     serverCert,
		"server-key.pem":      serverKey,
		"client-ca.pem":       clientCAPEM,
		"authorization-token": append(append([]byte(nil), token...), '\n'),
	}}
	dial = CredentialBundle{files: map[string][]byte{
		"client-cert.pem":     clientCert,
		"client-key.pem":      clientKey,
		"server-ca.pem":       serverCAPEM,
		"authorization-token": append(append([]byte(nil), token...), '\n'),
	}}
	if mode == domain.QUICObfuscationSalamander {
		var randomObfs [32]byte
		if _, err := rand.Read(randomObfs[:]); err != nil {
			clear(randomObfs[:])
			clear(token)
			listen.Clear()
			dial.Clear()
			return CredentialBundle{}, CredentialBundle{}, errors.New("could not issue QUIC obfuscation secret")
		}
		secret := []byte(hex.EncodeToString(randomObfs[:]))
		clear(randomObfs[:])
		if string(secret) == string(token) {
			clear(secret)
			clear(token)
			listen.Clear()
			dial.Clear()
			return CredentialBundle{}, CredentialBundle{}, errors.New("QUIC secrets must be independent")
		}
		listen.files[obfuscationSecretFile] = append(append([]byte(nil), secret...), '\n')
		dial.files[obfuscationSecretFile] = append(append([]byte(nil), secret...), '\n')
		clear(secret)
	}
	clear(token)
	return listen, dial, nil
}

func validIssuingName(name string) bool {
	// A DNS SAN may be different from the selected physical IPv4 endpoint.
	// An IP SAN will be constrained to that endpoint by Build at admission.
	peer := netip.MustParseAddr("127.0.0.1")
	if ip, err := netip.ParseAddr(name); err == nil {
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
		peer = ip
	}
	return validTLSName(name, peer)
}

func generateCA(name string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomCertSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 3, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		MaxPathLen:            0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func randomCertSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
}

func generateLeaf(ca *x509.Certificate, signingKey *ecdsa.PrivateKey,
	commonName, serverSAN string, usage x509.ExtKeyUsage, now time.Time) ([]byte, []byte, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomCertSerial()
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 2, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if serverSAN != "" {
		if ip, err := netip.ParseAddr(serverSAN); err == nil {
			leaf.IPAddresses = []net.IP{net.IP(ip.AsSlice())}
		} else {
			leaf.DNSNames = []string{serverSAN}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafKey.Public(), signingKey)
	if err != nil {
		return nil, nil, err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})
	clear(encodedKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}
