package state

import (
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// IPsecReapplyOperation is a durable safety journal for restoring an ALREADY
// COMMITTED IPsec Link. It never authorizes retry of an indeterminate VICI call.
type IPsecReapplyOperation struct {
	Intent domain.Link `json:"intent"`
	Nonce  string      `json:"nonce"`
	Phase  string      `json:"phase"`
}

func (s Snapshot) FindIPsecReapplyOperation(id domain.LinkID) (IPsecReapplyOperation, bool) {
	for _, op := range s.IPsecReapplyOperations {
		if op.Intent.ID == id {
			return op, true
		}
	}
	return IPsecReapplyOperation{}, false
}

func (s *Snapshot) DeleteIPsecReapplyOperation(id domain.LinkID) bool {
	for i, op := range s.IPsecReapplyOperations {
		if op.Intent.ID == id {
			s.IPsecReapplyOperations = append(s.IPsecReapplyOperations[:i], s.IPsecReapplyOperations[i+1:]...)
			return true
		}
	}
	return false
}

func validVICIPhase(phase string) bool {
	switch phase {
	case IPsecVICIPrepared, IPsecVICIIssuingShared,
		IPsecVICISharedObserved, IPsecVICIIssuingConnection, IPsecVICIConnectionSeen:
		return true
	}
	return false
}

func validateIPsecReapplyOperations(s Snapshot) error {
	seen := make(map[domain.LinkID]bool, len(s.IPsecReapplyOperations))
	for _, op := range s.IPsecReapplyOperations {
		rec, present := s.Find(op.Intent.ID)
		if !present || rec.Desired.Backend != domain.BackendIPsec ||
			rec.Desired != op.Intent || !validIPsecVICINonce(op.Nonce) ||
			!validVICIPhase(op.Phase) || seen[op.Intent.ID] {
			return fmt.Errorf("invalid or orphaned IPsec reapply journal")
		}
		if _, pending := s.FindPendingIPsec(op.Intent.ID); pending {
			return fmt.Errorf("IPsec reapply journal overlaps pending intent")
		}
		if _, initial := s.FindIPsecVICIOperation(op.Intent.ID); initial {
			return fmt.Errorf("IPsec reapply and activation journal overlap")
		}
		seen[op.Intent.ID] = true
	}
	return nil
}
