package stlerr

import "errors"

// OperationEvidence is a conservative, secret-free account of the stages
// reached by the canonical Engine. These optional fields do not change v1
// outcome or reconciliation_required semantics. A successful rollback call
// is not itself proof that all host resources match the prior observation.
type OperationEvidence struct {
	Stage        string `json:"stage"`
	HostMutation string `json:"host_mutation"`
	DesiredState string `json:"desired_state"`
	Rollback     string `json:"rollback"`
	// A protected credential may be staged before network Apply. Its
	// attempted persistence is separate from the host backend mutation.
	CredentialProvision string `json:"credential_provision,omitempty"`
}

// WithEvidence records known Engine stage transitions without serializing
// underlying operating-system errors, network observations or credentials.
func WithEvidence(source error, observation OperationEvidence) error {
	var original *Error
	if !errors.As(source, &original) {
		original = Wrap(CodeInternal, "", "", "", "operation failed", source)
	}
	copy := *original
	copy.Evidence = &observation
	copy.cause = source
	return &copy
}

// EvidenceOf returns only trusted, typed metadata; it does not infer host
// mutation from an error string or use an error category as stage evidence.
func EvidenceOf(source error) *OperationEvidence {
	var typed *Error
	if !errors.As(source, &typed) || typed.Evidence == nil {
		return nil
	}
	copy := *typed.Evidence
	return &copy
}
