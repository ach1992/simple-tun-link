package state

import (
	"fmt"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// IPsecXFRMOperation durably holds pre-effect device creation intent and the
// original observed ifindex BEFORE the non-atomic Linux ifalias mutation.
// An issuing-create phase with no ifindex is INDETERMINATE and confers no
// permission to adopt/delete a same-name or same-if_id kernel device.
type IPsecXFRMOperation struct {
	Intent  domain.Link `json:"intent"`
	Nonce   string      `json:"nonce"`
	Phase   string      `json:"phase"`
	IfIndex int         `json:"if_index,omitempty"`
}

const (
	IPsecXFRMPrepared      = "prepared"
	IPsecXFRMIssuingCreate = "issuing-create"
	IPsecXFRMIndexed       = "indexed"
	IPsecXFRMAliased       = "aliased"
	IPsecXFRMConfigured    = "configured"
	IPsecXFRMIssuingAbort  = "issuing-abort"
)

func validXFRMPhase(p string) bool {
	switch p {
	case IPsecXFRMPrepared, IPsecXFRMIssuingCreate, IPsecXFRMIndexed,
		IPsecXFRMAliased, IPsecXFRMConfigured, IPsecXFRMIssuingAbort:
		return true
	}
	return false
}
func IPsecXFRMNextPhase(from, to string) bool {
	switch {
	case from == IPsecXFRMPrepared && to == IPsecXFRMIssuingCreate:
	case from == IPsecXFRMIssuingCreate && to == IPsecXFRMIndexed:
	case from == IPsecXFRMIndexed && to == IPsecXFRMAliased:
	case from == IPsecXFRMAliased && to == IPsecXFRMConfigured:
	case (from == IPsecXFRMPrepared || from == IPsecXFRMIndexed ||
		from == IPsecXFRMAliased || from == IPsecXFRMConfigured) && to == IPsecXFRMIssuingAbort:
	default:
		return false
	}
	return true
}
func (s Snapshot) FindIPsecXFRMOperation(id domain.LinkID) (IPsecXFRMOperation, bool) {
	for _, op := range s.IPsecXFRMOperations {
		if op.Intent.ID == id {
			return op, true
		}
	}
	return IPsecXFRMOperation{}, false
}
func (s *Snapshot) DeleteIPsecXFRMOperation(id domain.LinkID) bool {
	for i, op := range s.IPsecXFRMOperations {
		if op.Intent.ID == id {
			s.IPsecXFRMOperations = append(s.IPsecXFRMOperations[:i], s.IPsecXFRMOperations[i+1:]...)
			return true
		}
	}
	return false
}
func validateIPsecXFRMOperations(s Snapshot) error {
	seen := make(map[domain.LinkID]bool, len(s.IPsecXFRMOperations))
	for _, op := range s.IPsecXFRMOperations {
		if op.Intent.Validate() != nil || op.Intent.Backend != domain.BackendIPsec ||
			!validIPsecVICINonce(op.Nonce) || !validXFRMPhase(op.Phase) || seen[op.Intent.ID] {
			return fmt.Errorf("untrusted XFRM creation journal")
		}
		if op.Phase == IPsecXFRMPrepared || op.Phase == IPsecXFRMIssuingCreate {
			if op.IfIndex != 0 {
				return fmt.Errorf("pre-index XFRM journal has spurious ifindex")
			}
		} else if op.IfIndex <= 0 {
			if op.Phase != IPsecXFRMIssuingAbort {
				return fmt.Errorf("XFRM creation journal lacks persistent ifindex")
			}
		}
		_, pending := s.FindPendingIPsec(op.Intent.ID)
		staged, _ := s.FindIPsecVICIOperation(op.Intent.ID)
		committed, active := s.Find(op.Intent.ID)
		reapply, _ := s.FindIPsecReapplyOperation(op.Intent.ID)
		if pending == active ||
			(pending && staged.Intent.Link != op.Intent) ||
			(active && (committed.Desired != op.Intent || !ipsecXFRMCommittedClaimsPresent(committed))) ||
			(active && reapply.Intent != op.Intent) {
			return fmt.Errorf("XFRM journal lost its exact staged/committed owner identity")
		}
		if _, removing := s.FindIPsecRemoveOperation(op.Intent.ID); removing {
			return fmt.Errorf("XFRM creation and Remove overlap")
		}
		seen[op.Intent.ID] = true
	}
	return nil
}
func ipsecXFRMCommittedClaimsPresent(rec LinkRecord) bool {
	return rec.Desired.Backend == domain.BackendIPsec && len(rec.OwnedResources) > 0
}
