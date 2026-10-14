package state

import (
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// IPsecRemovalReceipt is a non-secret, durable after-Remove authorization
// for exact protected PSK retirement. It is atomically published with the
// canonical Link removal, before any key deletion. The full 256-bit key
// digest does not reveal the raw PSK; it cannot authorize daemon changes.
type IPsecRemovalReceipt struct {
	LinkID    domain.LinkID `json:"link_id"`
	PSKSHA256 string        `json:"psk_sha256"`
	Retired   bool          `json:"retired,omitempty"`
}

func (s Snapshot) FindIPsecRemovalReceipt(id domain.LinkID) (IPsecRemovalReceipt, bool) {
	for _, r := range s.IPsecRemovalReceipts {
		if r.LinkID == id {
			return r, true
		}
	}
	return IPsecRemovalReceipt{}, false
}

func validateIPsecRemovalReceipts(s Snapshot) error {
	seen := map[domain.LinkID]bool{}
	for _, r := range s.IPsecRemovalReceipts {
		if r.LinkID.Validate() != nil || len(r.PSKSHA256) != 64 || seen[r.LinkID] {
			return fmt.Errorf("invalid or duplicate IPsec key retirement receipt")
		}
		b, err := hex.DecodeString(r.PSKSHA256)
		if err != nil || len(b) != 32 || hex.EncodeToString(b) != r.PSKSHA256 {
			return fmt.Errorf("invalid IPsec key retirement digest")
		}
		if _, exists := s.Find(r.LinkID); exists {
			return fmt.Errorf("IPsec retired identity still committed")
		}
		if _, exists := s.FindPendingIPsec(r.LinkID); exists {
			return fmt.Errorf("IPsec retired identity overlaps protected pending intent")
		}
		if _, exists := s.FindPendingIPsec(r.LinkID); exists {
			return fmt.Errorf("IPsec retired identity overlaps protected pending intent")
		}
		if _, exists := s.FindPendingSender(r.LinkID); exists {
			return fmt.Errorf("IPsec retired identity overlaps WireGuard pending sender intent")
		}
		if _, exists := s.FindIPsecVICIOperation(r.LinkID); exists {
			return fmt.Errorf("IPsec retired identity overlaps daemon transaction")
		}
		if _, exists := s.FindIPsecReapplyOperation(r.LinkID); exists {
			return fmt.Errorf("IPsec retired identity overlaps reapply transaction")
		}
		seen[r.LinkID] = true
	}
	return nil
}
