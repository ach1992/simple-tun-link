package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func createLabIdentity(dir string) error {
	// New, private, exclusive directory: never overwrite or adopt unknown credentials.
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("identity directory must be new and private: %w", err)
	}
	now := time.Now().UTC()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "STL Spoof Diagnostics DISPOSABLE local lab CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:     true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		return err
	}
	if err := writeLabPEM(dir, "ca.crt", "CERTIFICATE", caDER, 0644); err != nil {
		return err
	}
	caPrivate, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return err
	}
	if err := writeLabPEM(dir, "ca.key", "PRIVATE KEY", caPrivate, 0600); err != nil {
		return err
	}
	for _, role := range []string{"A", "B"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		serial, err := randomSerial()
		if err != nil {
			return err
		}
		dns := "spoofdiag-" + string(role[0]+('a'-'A')) + ".local"
		leaf := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
			NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(12 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := writeLabPEM(dir, role+".crt", "CERTIFICATE", leafDER, 0644); err != nil {
			return err
		}
		if err := writeLabPEM(dir, role+".key", "PRIVATE KEY", keyDER, 0600); err != nil {
			return err
		}
	}
	return nil
}

func writeLabPEM(dir, name, kind string, b []byte, mode os.FileMode) error {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b})); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func loadLabCredential(certFile, keyFile string) (tls.Certificate, error) {
	stat, err := os.Lstat(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	if !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		return tls.Certificate{}, errors.New("node private key must be a regular file without group/other permissions")
	}
	c, err := readSmallRegular(certFile, 16384)
	if err != nil {
		return tls.Certificate{}, err
	}
	k, err := readSmallRegular(keyFile, 16384)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(c, k)
}

func checkPeerName(st tls.ConnectionState, expected string) error {
	if len(st.PeerCertificates) != 1 {
		return errors.New("expected one authenticated peer leaf")
	}
	for _, v := range st.PeerCertificates[0].DNSNames {
		if v == expected {
			return nil
		}
	}
	return fmt.Errorf("unrecognized peer identity (expected %s)", expected)
}

func serverLabTLS(certificate tls.Certificate, roots *x509.CertPool, clientName string) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{certificate},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        roots,
		VerifyConnection: func(st tls.ConnectionState) error { return checkPeerName(st, clientName) },
	}
}

func clientLabTLS(certificate tls.Certificate, roots *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
	}
}
