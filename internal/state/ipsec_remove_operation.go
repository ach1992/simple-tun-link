package state

import (
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// IPsecRemoveOperation holds the original committed ownership and the last
// durable boundary of a scoped, potentially interrupted daemon/kernel Remove.
// Names alone never authorize deletion: a committed Link and precise resource
// claims must remain available until this journal reaches device-absent.
type IPsecRemoveOperation struct {
	Intent  domain.Link `json:"intent"`
	Nonce   string      `json:"nonce"`
	Phase   string      `json:"phase"`
	IfIndex int         `json:"if_index,omitempty"`
}

const (
	IPsecRemovePrepared          = "prepared"
	IPsecRemoveIssuingTerminate  = "issuing-terminate"
	IPsecRemoveTerminated        = "terminated"
	IPsecRemoveIssuingConnection = "issuing-unload-connection"
	IPsecRemoveConnectionAbsent  = "connection-absent"
	IPsecRemoveIssuingShared     = "issuing-unload-shared"
	IPsecRemoveSharedAbsent      = "shared-absent"
	IPsecRemoveIssuingDevice     = "issuing-device-delete"
	IPsecRemoveDeviceAbsent      = "device-absent"
)

var IPsecRemovePhases = []string{
	IPsecRemovePrepared, IPsecRemoveIssuingTerminate, IPsecRemoveTerminated,
	IPsecRemoveIssuingConnection, IPsecRemoveConnectionAbsent,
	IPsecRemoveIssuingShared, IPsecRemoveSharedAbsent,
	IPsecRemoveIssuingDevice, IPsecRemoveDeviceAbsent,
}

func IPsecRemoveNextPhase(from, to string) bool {
	for i := 0; i+1 < len(IPsecRemovePhases); i++ {
		if IPsecRemovePhases[i] == from && IPsecRemovePhases[i+1] == to {
			return true
		}
	}
	return false
}
func validIPsecRemovePhase(phase string) bool {
	for _, candidate := range IPsecRemovePhases {
		if phase == candidate {
			return true
		}
	}
	return false
}
func (s Snapshot) FindIPsecRemoveOperation(id domain.LinkID) (IPsecRemoveOperation, bool) {
	for _, op := range s.IPsecRemoveOperations {
		if op.Intent.ID == id {
			return op, true
		}
	}
	return IPsecRemoveOperation{}, false
}
func (s *Snapshot) DeleteIPsecRemoveOperation(id domain.LinkID) bool {
	for i, op := range s.IPsecRemoveOperations {
		if op.Intent.ID == id {
			s.IPsecRemoveOperations = append(s.IPsecRemoveOperations[:i], s.IPsecRemoveOperations[i+1:]...)
			return true
		}
	}
	return false
}

func validateIPsecRemoveOperations(s Snapshot) error {
	seen := make(map[domain.LinkID]bool, len(s.IPsecRemoveOperations))
	for _, op := range s.IPsecRemoveOperations {
		record, ok := s.Find(op.Intent.ID)
		if !ok || record.Desired != op.Intent || op.Intent.Backend != domain.BackendIPsec ||
			!validIPsecVICINonce(op.Nonce) || !validIPsecRemovePhase(op.Phase) ||
			op.IfIndex < 0 || seen[op.Intent.ID] {
			return fmt.Errorf("invalid or orphaned IPsec Remove journal")
		}
		if _, pending := s.FindPendingIPsec(op.Intent.ID); pending {
			return fmt.Errorf("Remove overlaps staged IPsec")
		}
		if _, vici := s.FindIPsecVICIOperation(op.Intent.ID); vici {
			return fmt.Errorf("Remove overlaps initial VICI journal")
		}
		if _, reapply := s.FindIPsecReapplyOperation(op.Intent.ID); reapply {
			return fmt.Errorf("Remove overlaps IPsec reapply")
		}
		if _, receipt := s.FindIPsecRemovalReceipt(op.Intent.ID); receipt {
			return fmt.Errorf("Remove overlaps retired IPsec identity")
		}
		seen[op.Intent.ID] = true
	}
	return nil
}
