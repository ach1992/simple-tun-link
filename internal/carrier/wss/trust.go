package wss

// Read-only private-material and identity inspection for the unreleased
// STL-managed WSS+kernel-WireGuard candidate. This file does not provision
// keys or spawn processes; callers must hold canonical admission/owner
// locks, verify exact credential generation and reject unsafe host drift.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

const maxPEMBytes = 1 << 20

// CredentialIdentity contains only public fingerprint evidence. It is not
// certificate/key material, and by itself is not runtime TLS authorization.
type CredentialIdentity struct {
	CertificateSHA256   string
	TrustCASHA256       string
	AuthorizationSHA256 string
}

// InspectCredentials reads exactly the selected Link's protected TLS files,
// with no symlinks/hardlinks, no group/other access and only descriptor-relative
// traversal. It validates CA authority and expiration, the local key/cert
// pair, certificate lifetime/purpose and the exact intended per-Link identity.
// The *remote* participant must independently verify TLS and its peer's
// private material in a real handshake; a local inspection cannot prove that.
func InspectCredentials(link domain.Link, carrier composition.Carrier, stateRoot string) (CredentialIdentity, error) {
	path, err := composition.Build(link, carrier)
	if err != nil {
		return CredentialIdentity{}, err
	}
	if path.Kind != composition.WSS {
		return CredentialIdentity{}, fmt.Errorf("TLS material inspection requires an explicit WSS Carrier")
	}
	rootfd, err := credentials.OpenProtected(stateRoot, false)
	if err != nil {
		return CredentialIdentity{}, fmt.Errorf("protected credential state root is unavailable: %w", err)
	}
	defer unix.Close(rootfd)
	folderfd, err := openOwnedPrivateDir(rootfd, "wss")
	if err != nil {
		return CredentialIdentity{}, fmt.Errorf("protected WSS credential directory is unavailable: %w", err)
	}
	defer unix.Close(folderfd)
	linkfd, err := openOwnedPrivateDir(folderfd, string(link.ID))
	if err != nil {
		return CredentialIdentity{}, fmt.Errorf("this Link's protected TLS credential directory is unavailable: %w", err)
	}
	defer unix.Close(linkfd)

	var caName, certName, keyName string
	switch path.Role {
	case composition.Dial:
		caName, certName, keyName = "server-ca.pem", "client-cert.pem", "client-key.pem"
	case composition.Listen:
		caName, certName, keyName = "client-ca.pem", "server-cert.pem", "server-key.pem"
	default:
		return CredentialIdentity{}, fmt.Errorf("unsupported WSS role")
	}
	ca, err := readPrivateFile(linkfd, caName)
	if err != nil {
		return CredentialIdentity{}, err
	}
	defer clear(ca)
	certPEM, err := readPrivateFile(linkfd, certName)
	if err != nil {
		return CredentialIdentity{}, err
	}
	defer clear(certPEM)
	keyPEM, err := readPrivateFile(linkfd, keyName)
	if err != nil {
		return CredentialIdentity{}, err
	}
	defer clear(keyPEM)

	now := time.Now()
	if err := checkRootCAs(ca, now); err != nil {
		return CredentialIdentity{}, fmt.Errorf("invalid per-Link WSS trust CA: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return CredentialIdentity{}, fmt.Errorf("invalid per-Link TLS certificate/private key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return CredentialIdentity{}, fmt.Errorf("expired, not-yet-valid or non-leaf WSS certificate")
	}
	roleUsage := x509.ExtKeyUsageClientAuth
	if path.Role == composition.Listen {
		roleUsage = x509.ExtKeyUsageServerAuth
	}
	if !hasExtKeyUsage(leaf, roleUsage) {
		return CredentialIdentity{}, fmt.Errorf("WSS certificate has wrong TLS extended key usage")
	}
	// Both TLS 1.2 ECDHE and TLS 1.3 client/server authentication
	// require a signature-capable local leaf. Reject certificates that
	// explicitly restrict usage to encryption or key agreement despite
	// advertising a compatible TLS extended purpose.
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		// A zero Go KeyUsage is ambiguous: either no extension (no
		// restriction) or a present but empty extension (forbidden).
		// Check the original X.509 extension before admitting it.
		for _, extension := range leaf.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
				return CredentialIdentity{}, fmt.Errorf("WSS certificate key usage forbids TLS digital signatures")
			}
		}
	}
	if path.Role == composition.Dial {
		if leaf.Subject.CommonName != clientCN(link.ID) {
			return CredentialIdentity{}, fmt.Errorf("WSS client certificate identity does not match the exact Link")
		}
	} else {
		if err := leaf.VerifyHostname(path.TLSName); err != nil {
			return CredentialIdentity{}, fmt.Errorf("WSS server certificate SAN does not match its intended peer identity")
		}
		// STL's per-Link server-identity contract requires an exact DNS
		// SAN, not just a generic wildcard match accepted by TLS.
		if _, err := netip.ParseAddr(path.TLSName); err != nil {
			exact := false
			for _, dnsName := range leaf.DNSNames {
				if dnsName == path.TLSName {
					exact = true
					break
				}
			}
			if !exact {
				return CredentialIdentity{}, fmt.Errorf("WSS server certificate must contain the exact selected DNS SAN")
			}
		}
	}
	// The bearer is an independent per-Link authorization factor because
	// wstunnel v11 can skip CN-to-path matching for a missing-CN leaf.
	// Read it only from the same protected per-Link inode directory and
	// never expose the value in errors or public inspection results.
	authFile := "authorization-headers"
	if path.Role == composition.Listen {
		authFile = "authorization-token"
	}
	auth, err := readPrivateFile(linkfd, authFile)
	if err != nil {
		return CredentialIdentity{}, fmt.Errorf("protected per-Link WSS authorization material is unavailable: %w", err)
	}
	defer clear(auth)
	var token []byte
	if path.Role == composition.Dial {
		const prefix = "Authorization: Bearer "
		if !bytes.HasPrefix(auth, []byte(prefix)) || len(auth) != len(prefix)+64+1 ||
			auth[len(auth)-1] != '\n' {
			return CredentialIdentity{}, fmt.Errorf("invalid protected WSS client authorization header format")
		}
		token = auth[len(prefix) : len(auth)-1]
	} else {
		if len(auth) != 65 || auth[len(auth)-1] != '\n' {
			return CredentialIdentity{}, fmt.Errorf("invalid protected WSS server authorization secret format")
		}
		token = auth[:len(auth)-1]
	}
	if len(token) != 64 {
		return CredentialIdentity{}, fmt.Errorf("invalid per-Link WSS authorization secret")
	}
	for _, b := range token {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return CredentialIdentity{}, fmt.Errorf("invalid per-Link WSS authorization secret")
		}
	}
	certSum := sha256.Sum256(leaf.Raw)
	caSum := sha256.Sum256(ca)
	authSum := sha256.Sum256(token)
	return CredentialIdentity{
		CertificateSHA256:   hex.EncodeToString(certSum[:]),
		TrustCASHA256:       hex.EncodeToString(caSum[:]),
		AuthorizationSHA256: hex.EncodeToString(authSum[:]),
	}, nil
}

func openOwnedPrivateDir(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Uid != uint32(os.Geteuid()) ||
		st.Mode&0o777 != 0o700 {
		unix.Close(fd)
		return -1, fmt.Errorf("directory owner, identity or permission mismatch")
	}
	return fd, nil
}

func readPrivateFile(parent int, name string) ([]byte, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("protected WSS TLS file is not readable")
	}
	file := os.NewFile(uintptr(fd), "protected-wss-credential")
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o600 || st.Nlink != 1 ||
		st.Size < 1 || st.Size > maxPEMBytes {
		return nil, fmt.Errorf("WSS TLS material is not a regular singly-linked private file")
	}
	b, err := io.ReadAll(io.LimitReader(file, maxPEMBytes+1))
	if err != nil || len(b) == 0 || len(b) > maxPEMBytes {
		clear(b)
		return nil, fmt.Errorf("cannot read bounded private WSS TLS material")
	}
	return b, nil
}

func checkRootCAs(raw []byte, now time.Time) error {
	count := 0
	rest := bytes.TrimSpace(raw)
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("trust bundle contains unexpected PEM content")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.BasicConstraintsValid || !cert.IsCA ||
			cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return fmt.Errorf("trust bundle contains invalid or expired CA authority")
		}
		count++
		rest = bytes.TrimSpace(next)
	}
	if count == 0 {
		return fmt.Errorf("no trusted CA certificates")
	}
	return nil
}

func hasExtKeyUsage(cert *x509.Certificate, required x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == required {
			return true
		}
	}
	return false
}

// ExecutableIdentity is read-only fingerprint and inode evidence, never a
// permission to spawn the program after the descriptor has been closed.
type ExecutableIdentity struct {
	SHA256 string
	Device uint64
	Inode  uint64
}

// InspectPinnedExecutable refuses symlink paths, writable ancestor
// substitution opportunities, foreign-owned/linked binaries and hashes not
// matching the *externally approved* expected digest. Supplying a random
// digest is NOT an approved supply-chain pin: the caller must use a reviewed
// upstream release manifest and revalidate the identity at actual spawn time.
func InspectPinnedExecutable(binary, expectedSHA256 string) (ExecutableIdentity, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || binary == "/" ||
		len(expectedSHA256) != 64 || strings.Trim(expectedSHA256, "0123456789abcdef") != "" {
		return ExecutableIdentity{}, fmt.Errorf("pinned helper requires clean absolute path and exact lowercase SHA-256")
	}
	parts := strings.Split(strings.TrimPrefix(binary, "/"), "/")
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	defer func() {
		if parent >= 0 {
			unix.Close(parent)
		}
	}()
	for _, component := range parts[:len(parts)-1] {
		fd, err := unix.Openat(parent, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return ExecutableIdentity{}, fmt.Errorf("helper binary directory traversal is not trusted")
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil ||
			st.Mode&unix.S_IFMT != unix.S_IFDIR ||
			(st.Uid != 0 && st.Uid != uint32(os.Geteuid())) ||
			(st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			unix.Close(fd)
			return ExecutableIdentity{}, fmt.Errorf("helper binary path is not owner-controlled")
		}
		unix.Close(parent)
		parent = fd
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ExecutableIdentity{}, fmt.Errorf("trusted helper executable cannot be opened")
	}
	file := os.NewFile(uintptr(fd), "pinned-wstunnel-helper")
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Uid != uint32(os.Geteuid()) ||
		st.Mode&0o022 != 0 || st.Mode&0o111 == 0 || st.Mode&0o6000 != 0 ||
		st.Nlink != 1 || st.Size <= 0 || st.Size > 100<<20 {
		return ExecutableIdentity{}, fmt.Errorf("helper executable owner/mode/identity invalid")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(file, 100<<20+1)); err != nil {
		return ExecutableIdentity{}, fmt.Errorf("cannot hash pinned helper executable")
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expectedSHA256 {
		return ExecutableIdentity{}, fmt.Errorf("pinned helper executable SHA-256 mismatch")
	}
	return ExecutableIdentity{SHA256: actual, Device: uint64(st.Dev), Inode: st.Ino}, nil
}
