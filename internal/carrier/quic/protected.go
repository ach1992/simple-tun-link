package quic

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/netip"
	"time"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// CredentialIdentity is read-only fingerprint evidence of local files.
// It must eventually be committed by the canonical Engine transaction and
// re-compared on restore. It cannot by itself prove peer trust or safe launch.
type CredentialIdentity struct {
	CertificateSHA256   string
	TrustCASHA256       string
	AuthorizationSHA256 string
}

func roleFiles(role Role) ([4]string, error) {
	switch role {
	case Listen:
		return [4]string{"server-cert.pem", "server-key.pem", "client-ca.pem", "authorization-token"}, nil
	case Dial:
		return [4]string{"client-cert.pem", "client-key.pem", "server-ca.pem", "authorization-token"}, nil
	default:
		return [4]string{}, fmt.Errorf("invalid QUIC credential role")
	}
}

func validMaterialScope(plan Plan) error {
	if plan.LinkID.Validate() != nil || !plan.Underlay.IsValid() ||
		!plan.Underlay.Addr().Is4() || plan.Underlay.Port() == 0 ||
		plan.Underlay.Addr().IsUnspecified() || plan.Underlay.Addr().IsMulticast() ||
		!validTLSName(plan.TLSName, plan.Underlay.Addr()) {
		return fmt.Errorf("invalid QUIC credential Link or TLS endpoint")
	}
	_, err := roleFiles(plan.Role)
	return err
}

func clearRoleFiles(files map[string][]byte) {
	for name, raw := range files {
		clear(raw)
		delete(files, name)
	}
}

func parseSingleCA(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid QUIC trust certificate encoding")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	now := time.Now()
	if err != nil || !ca.BasicConstraintsValid || !ca.IsCA ||
		ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) ||
		ca.CheckSignatureFrom(ca) != nil {
		return nil, fmt.Errorf("invalid or expired QUIC trust authority")
	}
	return ca, nil
}

func validateRoleMaterial(plan Plan, files map[string][]byte) (CredentialIdentity, error) {
	names, err := roleFiles(plan.Role)
	if err != nil || len(files) != len(names) {
		return CredentialIdentity{}, fmt.Errorf("QUIC requires exactly its role's four private files")
	}
	for _, name := range names {
		if len(files[name]) < 1 || len(files[name]) > credentials.MaxPrivateFileBytes {
			return CredentialIdentity{}, fmt.Errorf("incomplete or oversized QUIC credential bundle")
		}
	}
	ca, err := parseSingleCA(files[names[2]])
	if err != nil {
		return CredentialIdentity{}, err
	}
	_ = ca // The remote peer performs the actual leaf-to-CA chain verification.
	pair, err := tls.X509KeyPair(files[names[0]], files[names[1]])
	if err != nil || len(pair.Certificate) != 1 {
		return CredentialIdentity{}, fmt.Errorf("invalid QUIC TLS leaf/key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	now := time.Now()
	if err != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return CredentialIdentity{}, fmt.Errorf("invalid or expired QUIC TLS leaf")
	}
	usage := x509.ExtKeyUsageClientAuth
	expectedCN := "STL QUIC client " + string(plan.LinkID)
	if plan.Role == Listen {
		usage = x509.ExtKeyUsageServerAuth
		expectedCN = "STL QUIC server " + string(plan.LinkID)
	}
	if leaf.Subject.CommonName != expectedCN || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != usage {
		return CredentialIdentity{}, fmt.Errorf("QUIC TLS leaf has incorrect purpose or Link identity")
	}
	if plan.Role == Listen {
		if err := leaf.VerifyHostname(plan.TLSName); err != nil {
			return CredentialIdentity{}, fmt.Errorf("QUIC server SAN does not bind selected peer identity")
		}
		if ip, err := netip.ParseAddr(plan.TLSName); err == nil {
			if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(ip.AsSlice()) || len(leaf.DNSNames) != 0 {
				return CredentialIdentity{}, fmt.Errorf("QUIC server IP SAN is not exact")
			}
		} else if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != plan.TLSName || len(leaf.IPAddresses) != 0 {
			return CredentialIdentity{}, fmt.Errorf("QUIC server DNS SAN is not exact")
		}
	} else if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		return CredentialIdentity{}, fmt.Errorf("QUIC client leaf carries unexpected server identities")
	}
	bearer := files[names[3]]
	if len(bearer) != 65 || bearer[64] != '\n' {
		return CredentialIdentity{}, fmt.Errorf("invalid QUIC authorization token file")
	}
	for _, b := range bearer[:64] {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return CredentialIdentity{}, fmt.Errorf("invalid QUIC authorization token")
		}
	}
	leafSHA := sha256.Sum256(leaf.Raw)
	caSHA := sha256.Sum256(files[names[2]])
	authSHA := sha256.Sum256(bearer[:64])
	return CredentialIdentity{
		CertificateSHA256:   hex.EncodeToString(leafSHA[:]),
		TrustCASHA256:       hex.EncodeToString(caSHA[:]),
		AuthorizationSHA256: hex.EncodeToString(authSHA[:]),
	}, nil
}

func openRoleDir(root string, id domain.LinkID, create bool) (int, error) {
	fd, err := credentials.OpenProtected(root, create)
	if err != nil {
		return -1, err
	}
	for _, name := range [...]string{"quic", string(id)} {
		next, e := credentials.OpenOwnedPrivateDir(fd, name, create)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}

// requireExclusiveRole refuses mixing client and server private identities
// under one Link directory. Peers must keep independent local State roots.
func requireExclusiveRole(fd int, role Role) error {
	var foreign [2]string
	switch role {
	case Listen:
		foreign = [2]string{"client-cert.pem", "client-key.pem"}
	case Dial:
		foreign = [2]string{"server-cert.pem", "server-key.pem"}
	default:
		return fmt.Errorf("invalid QUIC credential role")
	}
	for _, name := range foreign {
		var st unix.Stat_t
		err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil || err != unix.ENOENT {
			return fmt.Errorf("QUIC directory contains foreign or ambiguous role material")
		}
	}
	return nil
}

// StageCredentials is ONLY a protected-storage component for a future
// Engine-owned, journaled transaction. Callers must hold the canonical Link
// maintenance/resource locks. It neither issues replacement identities nor
// starts a helper. A partial/uncertain publication is deliberately preserved
// for owner-scoped reconciliation, never silently removed or overwritten.
func StageCredentials(root string, plan Plan, bundle CredentialBundle) (CredentialIdentity, error) {
	if err := validMaterialScope(plan); err != nil {
		return CredentialIdentity{}, err
	}
	files := bundle.ProtectedFiles()
	defer clearRoleFiles(files)
	expected, err := validateRoleMaterial(plan, files)
	if err != nil {
		return CredentialIdentity{}, err
	}
	fd, err := openRoleDir(root, plan.LinkID, true)
	if err != nil {
		return CredentialIdentity{}, err
	}
	defer unix.Close(fd)
	if err := requireExclusiveRole(fd, plan.Role); err != nil {
		return CredentialIdentity{}, err
	}
	names, _ := roleFiles(plan.Role)
	for _, name := range names {
		if err := credentials.WritePrivateNoReplace(fd, name, files[name]); err != nil {
			return CredentialIdentity{}, err
		}
	}
	readback, err := InspectCredentials(root, plan)
	if err != nil || expected != readback {
		return CredentialIdentity{}, fmt.Errorf("QUIC protected credential publication not verified")
	}
	return readback, nil
}

// InspectCredentials reads only the exact Link's role-restricted protected
// 0600 files, rejecting symlinks, hardlinks, invalid certs and role drift.
// It cannot prove the other peer shares the intended CA or bearer; the
// canonical Engine must bind these fingerprints into committed State.
func InspectCredentials(root string, plan Plan) (CredentialIdentity, error) {
	if err := validMaterialScope(plan); err != nil {
		return CredentialIdentity{}, err
	}
	fd, err := openRoleDir(root, plan.LinkID, false)
	if err != nil {
		return CredentialIdentity{}, err
	}
	defer unix.Close(fd)
	if err := requireExclusiveRole(fd, plan.Role); err != nil {
		return CredentialIdentity{}, err
	}
	names, _ := roleFiles(plan.Role)
	files := make(map[string][]byte, len(names))
	defer clearRoleFiles(files)
	for _, name := range names {
		raw, e := credentials.ReadPrivateFile(fd, name)
		if e != nil {
			return CredentialIdentity{}, e
		}
		files[name] = raw
	}
	return validateRoleMaterial(plan, files)
}
