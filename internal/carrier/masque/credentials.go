package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// PairMaterial belongs to one unreleased, per-Link mTLS issuance. CA signing
// private keys never leave this function. No peer receives the other peer's
// TLS private key. The authenticated server pins the exact client's SPKI;
// clients pin the issuer CA and verify the intended DNS/IP SAN.
type PairMaterial struct {
	ServerCertificate []byte
	ServerPrivateKey  []byte
	ServerCA          []byte
	ClientCertificate []byte
	ClientPrivateKey  []byte
	ClientSPKIBase64  string
}

func (p *PairMaterial) Clear() {
	if p == nil {
		return
	}
	clear(p.ServerCertificate)
	clear(p.ServerPrivateKey)
	clear(p.ServerCA)
	clear(p.ClientCertificate)
	clear(p.ClientPrivateKey)
	*p = PairMaterial{}
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

func issueECDSAKey() (*ecdsa.PrivateKey, []byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// GeneratePair issues fresh P-256 identities. Validity is an explicit
// operator/CLI choice; no hidden renewal daemon or global credential policy.
// Rotation uses a new Link identity and an explicit peer handoff.
func GeneratePair(id domain.LinkID, tlsName string, validityDays int) (bundle PairMaterial, err error) {
	if id.Validate() != nil || tlsName == "" || len(tlsName) > 253 || validityDays < 1 || validityDays > 36500 {
		return PairMaterial{}, errors.New("invalid MASQUE Link/TLS name or certificate lifetime")
	}
	now := time.Now().UTC()
	before := now.Add(-5 * time.Minute)
	expire := now.AddDate(0, 0, validityDays)
	serial, err := randomSerial()
	if err != nil {
		return bundle, err
	}
	issuerKey, _, err := issueECDSAKey()
	if err != nil {
		return bundle, err
	}
	ca := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "STL MASQUE root " + string(id)},
		NotBefore: before, NotAfter: expire.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		return bundle, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return bundle, err
	}
	bundle.ServerCA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	serverKey, serverKeyPEM, err := issueECDSAKey()
	if err != nil {
		bundle.Clear()
		return bundle, err
	}
	serial, err = randomSerial()
	if err != nil {
		bundle.Clear()
		return bundle, err
	}
	server := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "STL MASQUE server " + string(id)},
		NotBefore: before, NotAfter: expire,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(tlsName); ip != nil {
		server.IPAddresses = []net.IP{ip}
	} else {
		server.DNSNames = []string{tlsName}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, caCert, &serverKey.PublicKey, issuerKey)
	if err != nil {
		bundle.Clear()
		return bundle, err
	}
	bundle.ServerCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	bundle.ServerCertificate = append(bundle.ServerCertificate, bundle.ServerCA...)
	bundle.ServerPrivateKey = serverKeyPEM

	clientKey, clientKeyPEM, err := issueECDSAKey()
	if err != nil {
		bundle.Clear()
		return bundle, err
	}
	serial, err = randomSerial()
	if err != nil {
		bundle.Clear()
		return bundle, err
	}
	client := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "STL MASQUE client " + string(id)},
		NotBefore: before, NotAfter: expire,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, client, client, &clientKey.PublicKey, clientKey)
	if err != nil {
		bundle.Clear()
		return bundle, err
	}
	clientLeaf, err := x509.ParseCertificate(clientDER)
	if err != nil {
		bundle.Clear()
		return bundle, err
	}
	bundle.ClientCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	bundle.ClientPrivateKey = clientKeyPEM
	bundle.ClientSPKIBase64 = base64.StdEncoding.EncodeToString(clientLeaf.RawSubjectPublicKeyInfo)

	identity, err := tls.X509KeyPair(bundle.ServerCertificate, bundle.ServerPrivateKey)
	if err != nil {
		bundle.Clear()
		return bundle, fmt.Errorf("MASQUE new server identity invalid: %w", err)
	}
	clientIdentity, err := tls.X509KeyPair(bundle.ClientCertificate, bundle.ClientPrivateKey)
	if err != nil {
		bundle.Clear()
		return bundle, fmt.Errorf("MASQUE new client identity invalid: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle.ServerCA) {
		bundle.Clear()
		return bundle, errors.New("MASQUE generated server CA unusable")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil || leaf.VerifyHostname(tlsName) != nil {
		bundle.Clear()
		return bundle, errors.New("MASQUE generated server TLS name invalid")
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: tlsName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		bundle.Clear()
		return bundle, fmt.Errorf("MASQUE generated TLS chain invalid: %w", err)
	}
	if _, err = x509.ParseCertificate(clientIdentity.Certificate[0]); err != nil {
		bundle.Clear()
		return bundle, errors.New("MASQUE generated client certificate invalid")
	}
	return bundle, nil
}
