package diagnostics

import "github.com/ach1992/simple-tun-link/internal/backend/ipsec"

// inspectNativeExclusiveServiceUnitOrigin is a protected read-only receipt
// observation, not an effective systemd unit/process or VICI authorization.
func inspectNativeExclusiveServiceUnitOrigin(inspect func() ipsec.NativeOriginAssessment) IPsecHostCheck {
	check := IPsecHostCheck{
		Name:       "native_service_unit_origin",
		Status:     "unknown",
		ReasonCode: "native_service_unit_origin_unverified",
		Summary:    "The private IPsec service unit publication record could not be verified.",
		NextStep:   "Inspect protected STL-origin receipt and canonical unit identity; do not infer loaded systemd ownership.",
	}
	if inspect == nil {
		return check
	}
	switch inspect() {
	case ipsec.NativeOriginVerified:
		check.Status = "observed"
		check.ReasonCode = "native_service_unit_origin_observed"
		check.Summary = "The private origin receipt and service unit inode, exact bytes and token match at inspection time; effective systemd ownership remains unverified."
		check.NextStep = "Attest loaded unit, all drop-ins and generators, package/executable identity, actual environment, logging, VICI writers, IKE ports and XFRM before activation."
	case ipsec.NativeOriginMissing:
		check.Status = "blocked"
		check.ReasonCode = "native_service_unit_origin_not_provisioned"
		check.Summary = "No complete STL-private service publication receipt was found; matching unit bytes alone are not STL ownership."
		check.NextStep = ipsecCurrentPrepareGuidance + " No matching publication receipt means the existing unit cannot be adopted."
	case ipsec.NativeOriginConflict:
		check.Status = "blocked"
		check.ReasonCode = "native_service_unit_origin_conflict"
		check.Summary = "The native service publication is incomplete, changed or conflicts with existing systemd files."
		check.NextStep = "Manually reconcile the prepared receipt and file identities; never replace, adopt, delete or auto-retry ambiguous service files."
	}
	return check
}
