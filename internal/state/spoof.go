package state

import (
	"errors"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// SpoofRemovalReceipt reserves an exact old Link ID after canonical Remove.
// Protected material is retired only after the same transaction proves the
// host's original helper and TUN are gone. It contains no secret bytes.
type SpoofRemovalReceipt struct {
	Link    domain.Link `json:"link"`
	Retired bool        `json:"retired,omitempty"`
}

func (s Snapshot) FindSpoofRemovalReceipt(id domain.LinkID) (SpoofRemovalReceipt, bool) {
	for _, r := range s.SpoofRemovalReceipts {
		if r.Link.ID == id {
			return r, true
		}
	}
	return SpoofRemovalReceipt{}, false
}
func validateSpoofReceipts(s Snapshot) error {
	seen := map[domain.LinkID]bool{}
	for _, r := range s.SpoofRemovalReceipts {
		if r.Link.Backend != domain.BackendSpoof || r.Link.Validate() != nil {
			return errors.New("invalid Spoof retirement original")
		}
		if seen[r.Link.ID] {
			return errors.New("duplicate Spoof retirement receipt")
		}
		seen[r.Link.ID] = true
		if _, exists := s.Find(r.Link.ID); exists {
			return fmt.Errorf("retired Spoof ID still committed")
		}
	}
	return nil
}
func validateSpoofReceiptTransition(before, after []SpoofRemovalReceipt) error {
	current := map[domain.LinkID]SpoofRemovalReceipt{}
	for _, r := range after {
		current[r.Link.ID] = r
	}
	for _, old := range before {
		next, ok := current[old.Link.ID]
		if !ok || next.Link != old.Link || (old.Retired && !next.Retired) {
			return errors.New("Spoof retirement receipt cannot be removed/reissued/rewritten")
		}
	}
	return nil
}
