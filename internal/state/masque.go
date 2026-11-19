package state

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// MASQUEOperation is a durable, credential-free pre-effect reservation.
// It precedes any new per-Link transient service or TUN operation, including
// a repair or removal. Its presence quarantines ordinary Ensure/Remove/Restore
// until the precise effect has been independently reconciled.
type MASQUEOperation struct {
	Intent           domain.Link            `json:"intent"`
	Operation        string                 `json:"operation"`
	Nonce            string                 `json:"nonce"`
	HadCommittedLink bool                   `json:"had_committed_link"`
	Resources        []domain.ResourceClaim `json:"resources"`
}

// MASQUERecoveryReceipt persists operator-confirmed, read-only absence
// evidence for a committed Link's interrupted Ensure before the corresponding
// pre-effect journal is consumed. It does not authorize foreign object deletion.
type MASQUERecoveryReceipt struct {
	LinkID         domain.LinkID `json:"link_id"`
	OriginalNonce  string        `json:"original_nonce"`
	Outcome        string        `json:"outcome"`
	MaterialSHA256 string        `json:"material_sha256"`
}

// MASQUERemovalReceipt is committed in the SAME transaction as Link removal.
// The original material remains until a separate exact receipt-bound
// retirement proves no original helper or TUN still exists.
type MASQUERemovalReceipt struct {
	Link           domain.Link `json:"link"`
	MaterialSHA256 string      `json:"material_sha256"`
	Retired        bool        `json:"retired,omitempty"`
	Purpose        string      `json:"purpose"`
}

func (s Snapshot) FindMASQUERecoveryReceipt(id domain.LinkID) (MASQUERecoveryReceipt, bool) {
	for _, r := range s.MASQUERecoveryReceipts {
		if r.LinkID == id {
			return r, true
		}
	}
	return MASQUERecoveryReceipt{}, false
}
func (s Snapshot) FindMASQUEOperation(id domain.LinkID) (MASQUEOperation, bool) {
	for _, op := range s.MASQUEOperations {
		if op.Intent.ID == id {
			return op, true
		}
	}
	return MASQUEOperation{}, false
}
func (s *Snapshot) DeleteMASQUEOperation(id domain.LinkID) bool {
	for i := range s.MASQUEOperations {
		if s.MASQUEOperations[i].Intent.ID == id {
			s.MASQUEOperations = append(s.MASQUEOperations[:i], s.MASQUEOperations[i+1:]...)
			return true
		}
	}
	return false
}
func (s Snapshot) FindMASQUERemovalReceipt(id domain.LinkID) (MASQUERemovalReceipt, bool) {
	for _, receipt := range s.MASQUERemovalReceipts {
		if receipt.Link.ID == id {
			return receipt, true
		}
	}
	return MASQUERemovalReceipt{}, false
}
func (s *Snapshot) DeleteMASQUERemovalReceipt(id domain.LinkID) bool {
	for i := range s.MASQUERemovalReceipts {
		if s.MASQUERemovalReceipts[i].Link.ID == id {
			s.MASQUERemovalReceipts = append(s.MASQUERemovalReceipts[:i], s.MASQUERemovalReceipts[i+1:]...)
			return true
		}
	}
	return false
}
func validMASQUEDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	raw, err := hex.DecodeString(v)
	return err == nil && hex.EncodeToString(raw) == v
}
func validateMASQUELifecycle(s Snapshot) error {
	ops := make(map[domain.LinkID]struct{}, len(s.MASQUEOperations))
	for _, op := range s.MASQUEOperations {
		if op.Intent.Backend != domain.BackendMASQUE || op.Intent.Validate() != nil ||
			(op.Operation != "ensure" && op.Operation != "remove") ||
			!validMASQUEDigest(op.Nonce) || len(op.Resources) == 0 {
			return errors.New("invalid pending MASQUE pre-effect operation")
		}
		if _, exists := ops[op.Intent.ID]; exists {
			return errors.New("duplicate MASQUE pre-effect operation")
		}
		ops[op.Intent.ID] = struct{}{}
		rec, present := s.Find(op.Intent.ID)
		if op.HadCommittedLink != present || op.Operation == "remove" && !present ||
			present && rec.Desired != op.Intent {
			return errors.New("MASQUE pending operation original State identity changed")
		}
		for i, c := range op.Resources {
			if err := c.Validate(); err != nil {
				return fmt.Errorf("MASQUE pending resource claim invalid: %w", err)
			}
			if i > 0 && op.Resources[i-1].Canonical() >= c.Canonical() {
				return errors.New("MASQUE pre-effect resource claims unsorted or duplicated")
			}
		}
	}
	recoveries := make(map[domain.LinkID]struct{}, len(s.MASQUERecoveryReceipts))
	for _, r := range s.MASQUERecoveryReceipts {
		if r.LinkID.Validate() != nil || !validMASQUEDigest(r.OriginalNonce) ||
			!validMASQUEDigest(r.MaterialSHA256) || r.Outcome != "ensure_host_absent" {
			return errors.New("MASQUE recovery receipt invalid")
		}
		if _, exists := recoveries[r.LinkID]; exists {
			return errors.New("duplicate MASQUE recovery receipt")
		}
		record, present := s.Find(r.LinkID)
		if present {
			if record.Desired.Backend != domain.BackendMASQUE ||
				record.Desired.MASQUE.MaterialSHA256 != r.MaterialSHA256 {
				return errors.New("MASQUE recovery receipt changed original committed Link")
			}
		} else {
			removed, exists := s.FindMASQUERemovalReceipt(r.LinkID)
			if !exists || removed.Link.MASQUE.MaterialSHA256 != r.MaterialSHA256 {
				return errors.New("MASQUE recovery receipt orphaned from original Link and removal")
			}
		}
		recoveries[r.LinkID] = struct{}{}
	}
	receipts := make(map[domain.LinkID]struct{}, len(s.MASQUERemovalReceipts))
	for _, r := range s.MASQUERemovalReceipts {
		if r.Link.Validate() != nil || r.Link.Backend != domain.BackendMASQUE ||
			(r.Purpose != "removed" && r.Purpose != "abandoned") ||
			r.Link.MASQUE.MaterialSHA256 != r.MaterialSHA256 || !validMASQUEDigest(r.MaterialSHA256) {
			return errors.New("MASQUE material retirement receipt invalid")
		}
		if _, exists := receipts[r.Link.ID]; exists {
			return errors.New("duplicate MASQUE material retirement receipt")
		}
		if _, exists := s.Find(r.Link.ID); exists {
			return errors.New("MASQUE receipt overlaps committed Link")
		}
		if _, exists := ops[r.Link.ID]; exists {
			return errors.New("MASQUE receipt overlaps pending effect")
		}
		receipts[r.Link.ID] = struct{}{}
	}
	return nil
}
func normalizeMASQUEOperation(op MASQUEOperation) MASQUEOperation {
	op.Resources = normalizeClaims(op.Resources)
	return op
}
func canonicalMASQUEOperations(ops []MASQUEOperation) []MASQUEOperation {
	// Keep untrusted order and duplicates visible to validation. New Engine
	// writers already emit canonical sorted claims before persistence.
	slices.SortFunc(ops, func(a, b MASQUEOperation) int {
		if a.Intent.ID < b.Intent.ID {
			return -1
		}
		if a.Intent.ID > b.Intent.ID {
			return 1
		}
		return 0
	})
	return ops
}

// Old State documents never authorize a new MASQUE service, private material
// or pending ownership simply by decoding against the newer Link struct.
func rejectLegacyMASQUEFields(raw []byte) error {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	var walk func(any) bool
	walk = func(value any) bool {
		switch current := value.(type) {
		case map[string]any:
			for k, v := range current {
				if strings.EqualFold(k, "masque") || strings.EqualFold(k, "masque_operations") ||
					strings.EqualFold(k, "masque_removal_receipts") {
					return true
				}
				if walk(v) {
					return true
				}
			}
		case []any:
			for _, v := range current {
				if walk(v) {
					return true
				}
			}
		}
		return false
	}
	if walk(doc) {
		return errors.New("legacy State cannot contain MASQUE Link identity or lifecycle records")
	}
	return nil
}

// The State Store cannot authenticate the host on its own. Therefore it
// permits journal consumption ONLY with the exact desired-state publication
// or removal receipt in that same atomic update. A later manual recovery
// requires a separate reviewed transition proof, not a nil/empty overwrite.
func validateMASQUEStateTransition(operations []MASQUEOperation, receipts []MASQUERemovalReceipt, recoveries []MASQUERecoveryReceipt, next Snapshot) error {
	for _, old := range operations {
		current, exists := next.FindMASQUEOperation(old.Intent.ID)
		if exists && reflect.DeepEqual(current, old) {
			continue
		}
		if !exists {
			if old.Operation == "ensure" {
				record, found := next.Find(old.Intent.ID)
				if found && record.Desired == old.Intent &&
					record.MASQUELastEffectNonce == old.Nonce &&
					slices.Equal(record.OwnedResources, old.Resources) {
					// Standard original Ensure/Restore commit.
					continue
				}
				receipt, abandoned := next.FindMASQUERemovalReceipt(old.Intent.ID)
				if !old.HadCommittedLink && !found && abandoned &&
					receipt.Link == old.Intent && receipt.Purpose == "abandoned" {
					continue
				}
				recovery, recovered := next.FindMASQUERecoveryReceipt(old.Intent.ID)
				if old.HadCommittedLink && recovered && recovery.OriginalNonce == old.Nonce &&
					recovery.MaterialSHA256 == old.Intent.MASQUE.MaterialSHA256 && found &&
					record.Desired == old.Intent {
					continue
				}
			} else if old.Operation == "remove" {
				receipt, found := next.FindMASQUERemovalReceipt(old.Intent.ID)
				if found && receipt.Link == old.Intent && receipt.MaterialSHA256 == old.Intent.MASQUE.MaterialSHA256 &&
					receipt.Purpose == "removed" {
					if _, present := next.Find(old.Intent.ID); !present {
						continue
					}
				}
			}
		}
		return fmt.Errorf("MASQUE pre-effect journal cannot be changed without exact Engine commit")
	}
	for _, old := range recoveries {
		current, found := next.FindMASQUERecoveryReceipt(old.LinkID)
		if !found || current != old {
			return fmt.Errorf("MASQUE original recovery receipt cannot be altered")
		}
	}
	for _, old := range receipts {
		current, found := next.FindMASQUERemovalReceipt(old.Link.ID)
		if !found || current.Link != old.Link || current.MaterialSHA256 != old.MaterialSHA256 ||
			current.Purpose != old.Purpose ||
			(old.Retired && !current.Retired) {
			return fmt.Errorf("MASQUE immutable retirement receipt changed")
		}
	}
	return nil
}
