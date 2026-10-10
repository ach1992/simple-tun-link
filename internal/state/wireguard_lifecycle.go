package state

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// PendingSender is PUBLIC, credential-free recovery intent in the ordinary,
// durable desired-state snapshot. HandoffSHA256 binds the precise SENSITIVE
// v3 URL without storing its recipient secret in ordinary state. Only the
// canonical Engine, under the maintenance and Link locks, may create or
// consume a pending transaction.
type PendingSender struct {
	Link          domain.Link `json:"link"`
	HandoffSHA256 string      `json:"handoff_sha256"`
}

// RemovalReceipt is a Link-specific historical authorization for the
// separately confirmed protected-key retirement operation. The receipt is
// published ONLY after the canonical Remove has durably completed, never on
// state publication uncertainty or orphan credential creation. A retired
// receipt is retained as a non-secret idempotency witness.
type RemovalReceipt struct {
	LinkID         domain.LinkID  `json:"link_id"`
	Backend        domain.Backend `json:"backend"`
	LocalPublicKey string         `json:"local_public_key"`
	Retired        bool           `json:"retired,omitempty"`
}

func (s Snapshot) FindPendingSender(id domain.LinkID) (PendingSender, bool) {
	for _, v := range s.PendingSenders {
		if v.Link.ID == id {
			return v, true
		}
	}
	return PendingSender{}, false
}
func (s *Snapshot) DeletePendingSender(id domain.LinkID) bool {
	for i, v := range s.PendingSenders {
		if v.Link.ID == id {
			s.PendingSenders = append(s.PendingSenders[:i], s.PendingSenders[i+1:]...)
			return true
		}
	}
	return false
}
func (s Snapshot) FindRemovalReceipt(id domain.LinkID) (RemovalReceipt, bool) {
	for _, v := range s.RemovalReceipts {
		if v.LinkID == id {
			return v, true
		}
	}
	return RemovalReceipt{}, false
}
func (s *Snapshot) DeleteRemovalReceipt(id domain.LinkID) bool {
	for i, v := range s.RemovalReceipts {
		if v.LinkID == id {
			s.RemovalReceipts = append(s.RemovalReceipts[:i], s.RemovalReceipts[i+1:]...)
			return true
		}
	}
	return false
}

func validateWireGuardLifecycle(s Snapshot) error {
	pending := make(map[domain.LinkID]bool, len(s.PendingSenders))
	for _, entry := range s.PendingSenders {
		link := entry.Link
		if err := link.Validate(); err != nil {
			return fmt.Errorf("invalid pending sender Link: %w", err)
		}
		if link.Backend != domain.BackendWireGuard || link.Encapsulation != domain.EncapUDP ||
			link.WireGuard.ListenPort == 0 || link.WireGuard.PeerPort == 0 ||
			!link.Underlay.Local.Is4() || !link.Underlay.Peer.Is4() {
			return fmt.Errorf("invalid WireGuard pending sender configuration")
		}
		if len(entry.HandoffSHA256) != 64 {
			return fmt.Errorf("invalid pending sender digest length")
		}
		decoded, err := hex.DecodeString(entry.HandoffSHA256)
		if err != nil || hex.EncodeToString(decoded) != entry.HandoffSHA256 {
			return fmt.Errorf("invalid pending sender handoff digest")
		}
		if pending[link.ID] {
			return fmt.Errorf("duplicate WireGuard pending sender")
		}
		if _, exists := s.Find(link.ID); exists {
			return fmt.Errorf("pending sender also exists as a committed Link")
		}
		pending[link.ID] = true
	}
	removed := make(map[domain.LinkID]bool, len(s.RemovalReceipts))
	for _, receipt := range s.RemovalReceipts {
		if receipt.LinkID.Validate() != nil || receipt.Backend != domain.BackendWireGuard ||
			!validReceiptPublicKey(receipt.LocalPublicKey) {
			return fmt.Errorf("invalid WireGuard removal receipt")
		}
		if removed[receipt.LinkID] {
			return fmt.Errorf("duplicate WireGuard removal receipt")
		}
		if _, exists := s.Find(receipt.LinkID); exists {
			return fmt.Errorf("removed Link still has committed desired state")
		}
		if pending[receipt.LinkID] {
			return fmt.Errorf("removed Link has pending sender recovery")
		}
		removed[receipt.LinkID] = true
	}
	return nil
}
func validReceiptPublicKey(value string) bool {
	if len(value) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value {
		return false
	}
	return slices.ContainsFunc(raw, func(b byte) bool { return b != 0 })
}
