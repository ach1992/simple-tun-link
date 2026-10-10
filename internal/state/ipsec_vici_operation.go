package state

import (
	"encoding/hex"
	"fmt"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// IPsecVICIOperation is a PUBLIC, crash-persistent operation journal, NOT
// ownership evidence or authorization to remove a daemon object. A step with
// "issuing" in its name means the corresponding VICI command MAY have reached
// the daemon, even if its response was lost. It is deliberately impossible to
// auto-retry or auto-unload such a step based only on a VICI name.
type IPsecVICIOperation struct {
	Intent PendingIPsec `json:"intent"`
	Nonce  string       `json:"nonce"`
	Phase  string       `json:"phase"`
}

const (
	IPsecVICIPrepared          = "prepared"
	IPsecVICIIssuingShared     = "issuing-shared"
	IPsecVICISharedObserved    = "shared-observed"
	IPsecVICIIssuingConnection = "issuing-connection"
	IPsecVICIConnectionSeen    = "connection-observed"
)

func (s Snapshot) FindIPsecVICIOperation(id domain.LinkID) (IPsecVICIOperation, bool) {
	for _, op := range s.IPsecVICIOperations {
		if op.Intent.Link.ID == id {
			return op, true
		}
	}
	return IPsecVICIOperation{}, false
}

func validIPsecVICINonce(nonce string) bool {
	if len(nonce) != 32 {
		return false
	}
	b, err := hex.DecodeString(nonce)
	if err != nil || hex.EncodeToString(b) != nonce {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}

func validateIPsecVICIOperations(s Snapshot) error {
	seen := make(map[domain.LinkID]bool, len(s.IPsecVICIOperations))
	for _, op := range s.IPsecVICIOperations {
		pending, ok := s.FindPendingIPsec(op.Intent.Link.ID)
		if !ok || pending != op.Intent || !validIPsecVICINonce(op.Nonce) ||
			seen[op.Intent.Link.ID] {
			return fmt.Errorf("invalid or orphaned IPsec VICI transaction")
		}
		seen[op.Intent.Link.ID] = true
		switch op.Phase {
		case IPsecVICIPrepared, IPsecVICIIssuingShared, IPsecVICISharedObserved,
			IPsecVICIIssuingConnection, IPsecVICIConnectionSeen:
		default:
			return fmt.Errorf("unknown IPsec VICI transaction phase")
		}
	}
	return nil
}
