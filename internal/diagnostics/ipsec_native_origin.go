package diagnostics

import "github.com/ach1992/simple-tun-link/internal/backend/ipsec"

// inspectNativeExclusiveConfigOrigin is strictly read-only. Even a matching
// STL-origin receipt is only a time-local configuration identity observation,
// not proof of daemon, service, VICI or kernel ownership.
func inspectNativeExclusiveConfigOrigin(inspect func() ipsec.NativeOriginAssessment) IPsecHostCheck {
	result := IPsecHostCheck{
		Name: "native_config_origin", Status: "unknown", ReasonCode: "native_config_origin_unverified",
		Summary:  "The private native IPsec configuration publication record could not be verified.",
		NextStep: "Inspect the private receipt and protected filesystem; do not infer ownership from filenames or matching bytes.",
	}
	if inspect == nil {
		return result
	}
	switch inspect() {
	case ipsec.NativeOriginVerified:
		result.Status = "observed"
		result.ReasonCode = "native_config_origin_observed"
		result.Summary = "The root-private origin receipt, configuration inode and publication token match at inspection time; operational ownership is unverified."
		result.NextStep = "Independently attest STL-only service, process, effective logging, VICI, ports and XFRM before activation."
	case ipsec.NativeOriginMissing:
		result.Status = "blocked"
		result.ReasonCode = "native_config_origin_not_provisioned"
		result.Summary = "No complete private native IPsec publication record was found. Matching configuration bytes alone do not establish STL ownership."
		result.NextStep = "Use a future verified no-clobber STL provisioner; never adopt a foreign configuration."
	case ipsec.NativeOriginConflict:
		result.Status = "blocked"
		result.ReasonCode = "native_config_origin_conflict"
		result.Summary = "The private native IPsec publication record or canonical file is incomplete, changed or untrusted."
		result.NextStep = "Reconcile pending or conflicting private artifacts manually; do not overwrite, adopt or automatically retry."
	}
	return result
}
