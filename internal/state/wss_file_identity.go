package state

import (
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// WSSFileIdentity records issuance-time SHA-256 content identities for
// precisely the protected TLS/auth material of one endpoint. Public digests
// are not the credentials themselves. This struct is comparable so an
// immutable removal receipt can be compared atomically before retirement.
type WSSFileIdentity struct {
	Certificate   string `json:"certificate_sha256"`
	TLSKey        string `json:"tls_key_sha256"`
	TrustCA       string `json:"trust_ca_sha256"`
	Authorization string `json:"authorization_sha256"`
	Restrictions  string `json:"restrictions_sha256,omitempty"`
}

func (i WSSFileIdentity) Validate(role string) error {
	checks := []string{i.Certificate, i.TLSKey, i.TrustCA, i.Authorization}
	if role == "listen" {
		checks = append(checks, i.Restrictions)
	} else if role != "dial" || i.Restrictions != "" {
		return fmt.Errorf("invalid WSS credential file identity role")
	}
	for _, item := range checks {
		if len(item) != 64 {
			return fmt.Errorf("missing WSS issuance-time credential SHA-256")
		}
		raw, err := hex.DecodeString(item)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != item {
			return fmt.Errorf("invalid WSS credential SHA-256")
		}
	}
	return nil
}
func (i WSSFileIdentity) VerifyLink(link domain.Link) error {
	if link.Backend != domain.BackendWireGuardWSS {
		return fmt.Errorf("WSS credential identity assigned to non-WSS Link")
	}
	return i.Validate(link.WSS.Role)
}
