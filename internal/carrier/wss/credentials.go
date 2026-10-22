package wss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"

	"path/filepath"
	"time"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// PrivateBundle is secret-bearing and must only be stored under the selected
// per-Link private credential directory or an explicitly protected handoff.
type PrivateBundle map[string][]byte

func (b PrivateBundle) Clear() {
	for k, v := range b {
		clear(v)
		delete(b, k)
	}
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
}

func issueSigned(parent *x509.Certificate, issuer *ecdsa.PrivateKey,
	cert *x509.Certificate) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cert.PublicKey = key.Public()
	der, err := x509.CreateCertificate(rand.Reader, cert, parent, key.Public(), issuer)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

// GeneratePair creates exactly one new Link-scoped mTLS trust authority,
// independent TLS identities, and a 256-bit bearer. The authority's signing
// key is intentionally NOT persisted or sent in the pairing handoff.
// Trusting the client CA does not by itself authorize tunnel destinations.
func GeneratePair(id domain.LinkID, serverName string) (PrivateBundle, PrivateBundle, error) {
	if err := id.Validate(); err != nil {
		return nil, nil, err
	}
	if serverName == "" {
		return nil, nil, fmt.Errorf("missing WSS server TLS identity")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	caSerial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "STL per-Link WSS CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 3, 0),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverSerial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	server := &x509.Certificate{
		SerialNumber: serverSerial, Subject: pkix.Name{CommonName: "STL WSS server"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 2, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if addr, err := netip.ParseAddr(serverName); err == nil {
		server.IPAddresses = []net.IP{net.IP(addr.AsSlice())}
	} else {
		if len(serverName) > 253 {
			return nil, nil, fmt.Errorf("invalid WSS certificate hostname")
		}
		server.DNSNames = []string{serverName}
	}
	serverPEM, serverKey, err := issueSigned(ca, caKey, server)
	if err != nil {
		return nil, nil, err
	}
	clientSerial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	client := &x509.Certificate{
		SerialNumber: clientSerial, Subject: pkix.Name{CommonName: clientCN(id)},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 2, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientPEM, clientKey, err := issueSigned(ca, caKey, client)
	if err != nil {
		return nil, nil, err
	}
	var token [32]byte
	if _, err = rand.Read(token[:]); err != nil {
		return nil, nil, err
	}
	t := hex.EncodeToString(token[:])
	clear(token[:])
	listen := PrivateBundle{
		"server-cert.pem": serverPEM, "server-key.pem": serverKey,
		"client-ca.pem":       append([]byte(nil), caPEM...),
		"authorization-token": []byte(t + "\n"),
	}
	dial := PrivateBundle{
		"client-cert.pem": clientPEM, "client-key.pem": clientKey,
		"server-ca.pem":         append([]byte(nil), caPEM...),
		"authorization-headers": []byte("Authorization: Bearer " + t + "\n"),
	}
	return listen, dial, nil
}

// Stage writes ONLY the role's four approved files, using exact-content
// no-replace retry semantics. The caller must hold the Engine's Link lock.
// No private key is admitted to public desired State or process arguments.
func Stage(root string, link domain.Link, bundle PrivateBundle) error {
	if link.Backend != domain.BackendWireGuardWSS || link.ID.Validate() != nil {
		return fmt.Errorf("invalid WSS credential owner")
	}
	expected := []string{"client-cert.pem", "client-key.pem", "server-ca.pem", "authorization-headers"}
	if link.WSS.Role == "listen" {
		expected = []string{"server-cert.pem", "server-key.pem", "client-ca.pem", "authorization-token"}
	} else if link.WSS.Role != "dial" {
		return fmt.Errorf("invalid WSS certificate role")
	}
	if len(bundle) != len(expected) {
		return fmt.Errorf("wrong WSS credential file count")
	}
	for _, name := range expected {
		raw, ok := bundle[name]
		if !ok || len(raw) == 0 || len(raw) > 1<<20 {
			return fmt.Errorf("missing or oversized WSS credential material")
		}
	}
	fd, err := credentials.OpenProtected(root, true)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	for _, component := range []string{"wss", string(link.ID)} {
		if err := unix.Mkdirat(fd, component, 0o700); err != nil && err != unix.EEXIST {
			return fmt.Errorf("create WSS protected directory: %w", err)
		}
		next, err := openOwnedPrivateDir(fd, component)
		if err != nil {
			return err
		}
		if err := unix.Fsync(fd); err != nil {
			unix.Close(next)
			return err
		}
		unix.Close(fd)
		fd = next
	}
	base := filepath.Join(root, "credentials", "wss", string(link.ID))
	for _, name := range expected {
		if err := WritePrivateNoReplace(filepath.Join(base, name), bundle[name]); err != nil {
			return err
		}
	}
	if _, err := InspectCredentials(link, composition.CarrierForLink(link), root); err != nil {
		return err
	}
	return nil
}
