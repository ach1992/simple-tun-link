package state

import (
	"fmt"
	"reflect"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

// QUICAbandonmentReceipt ends a fully staged but never committed managed
// attempt only after its recorded whole-kernel lifetime has ended and the
// Engine verified fresh vacancy. It deliberately has no invented original
// WG ifindex, guard handle or committed-generation authority. Its Link ID is
// reserved permanently; its exact material may be retired independently.
type QUICAbandonmentReceipt struct {
	Operation                  QUICCrashOperation `json:"operation"`
	Files                      QUICFileIdentity   `json:"files"`
	ReconciledKernelBootID     string             `json:"reconciled_kernel_boot_id"`
	ReconciledKernelBootSource string             `json:"reconciled_kernel_boot_source"`
	Retired                    bool               `json:"retired,omitempty"`
}

func (r QUICAbandonmentReceipt) Validate() error {
	op := r.Operation
	if op.Validate() != nil || op.Managed == nil || op.ValidateManaged() != nil ||
		op.Managed.HadCommittedLink || op.Managed.Operation != "ensure" ||
		!hostidentity.ValidBootID(r.ReconciledKernelBootID) || r.ReconciledKernelBootSource != hostidentity.VerifiedHostBootSourceV1 ||
		r.ReconciledKernelBootID == op.Managed.KernelBootID || r.Files.Validate() != nil ||
		r.Files.Certificate != op.CertificateSHA256 || r.Files.TrustCA != op.TrustCASHA256 ||
		r.Files.Authorization != op.AuthorizationSHA256 || r.Files.HelperConfig != op.HelperConfigSHA256 {
		return fmt.Errorf("invalid managed QUIC abandoned-attempt receipt")
	}
	return nil
}

func (s Snapshot) FindQUICAbandonmentReceipt(id domain.LinkID) (QUICAbandonmentReceipt, bool) {
	for _, r := range s.QUICAbandonmentReceipts {
		if r.Operation.Plan.Local.LinkID == id {
			return cloneQUICAbandonment(r), true
		}
	}
	return QUICAbandonmentReceipt{}, false
}

func cloneQUICAbandonment(r QUICAbandonmentReceipt) QUICAbandonmentReceipt {
	r.Operation.Resources = append([]domain.ResourceClaim(nil), r.Operation.Resources...)
	if r.Operation.Managed != nil {
		m := *r.Operation.Managed
		r.Operation.Managed = &m
	}
	return r
}

func validateQUICAbandonmentReceipts(s Snapshot) error {
	seen := make(map[domain.LinkID]bool, len(s.QUICAbandonmentReceipts))
	for _, r := range s.QUICAbandonmentReceipts {
		if err := r.Validate(); err != nil {
			return err
		}
		id := r.Operation.Plan.Local.LinkID
		if seen[id] {
			return fmt.Errorf("duplicate QUIC abandoned Link identity")
		}
		seen[id] = true
		if _, ok := s.Find(id); ok {
			return fmt.Errorf("abandoned QUIC identity is committed")
		}
		if _, ok := s.FindQUICCrashOperation(id); ok {
			return fmt.Errorf("abandoned QUIC identity is still pending")
		}
		if _, ok := s.FindPendingSender(id); ok {
			return fmt.Errorf("abandoned QUIC identity overlaps pending WireGuard")
		}
		if _, ok := s.FindPendingIPsec(id); ok {
			return fmt.Errorf("abandoned QUIC identity overlaps pending IPsec")
		}
		if _, ok := s.FindWSSCrashOperation(id); ok {
			return fmt.Errorf("abandoned QUIC identity overlaps pending WSS")
		}
		if _, ok := s.FindRemovalReceipt(id); ok {
			return fmt.Errorf("abandoned QUIC identity overlaps a removal receipt")
		}
		if _, ok := s.FindIPsecRemovalReceipt(id); ok {
			return fmt.Errorf("abandoned QUIC identity overlaps an IPsec receipt")
		}
	}
	return nil
}

func validateQUICAbandonmentTransition(before []QUICAbandonmentReceipt, operations []QUICCrashOperation, after Snapshot) error {
	for _, old := range before {
		current, ok := after.FindQUICAbandonmentReceipt(old.Operation.Plan.Local.LinkID)
		if !ok || old.Retired && !current.Retired {
			return fmt.Errorf("QUIC abandonment receipt cannot be revoked")
		}
		current.Retired = old.Retired
		if !reflect.DeepEqual(old, current) {
			return fmt.Errorf("QUIC abandonment identity is immutable")
		}
	}
	for _, r := range after.QUICAbandonmentReceipts {
		existed := false
		for _, old := range before {
			if old.Operation.Plan.Local.LinkID == r.Operation.Plan.Local.LinkID {
				existed = true
				break
			}
		}
		if existed {
			continue
		}
		found := false
		for _, op := range operations {
			if reflect.DeepEqual(r.Operation, op) {
				found = true
				break
			}
		}
		if !found || r.Retired {
			return fmt.Errorf("new QUIC abandonment lacks its exact unresolved original attempt")
		}
	}
	return nil
}
