package diagnostics

import "github.com/ach1992/simple-tun-link/internal/backend/ipsec"

// inspectNativeExclusiveServiceUnit reports only protected canonical file
// content/identity. It never evaluates systemd's loaded unit, aliases,
// drop-ins, generator output, process, package ownership or effective logging.
func inspectNativeExclusiveServiceUnit(inspect func() ipsec.NativeServiceUnitAssessment) IPsecHostCheck {
	result := IPsecHostCheck{
		Name:       "native_service_unit",
		Status:     "unknown",
		ReasonCode: "native_service_unit_unverified",
		Summary:    "The proposed private IPsec systemd unit could not be verified.",
		NextStep:   "Inspect the unit's protected file path and permissions; do not infer ownership or effective settings.",
	}
	if inspect == nil {
		return result
	}
	switch inspect() {
	case ipsec.NativeServiceUnitExact:
		result.Status = "observed"
		result.ReasonCode = "native_service_unit_bytes_verified"
		result.Summary = "The proposed STL IPsec systemd unit matches reviewed bytes at inspection time; its origin and effective systemd behavior are unverified."
		result.NextStep = "Prove STL-origin publication and effective loaded unit, drop-ins, service, executable, STRONGSWAN_CONF, logger and VICI ownership before activation."
	case ipsec.NativeServiceUnitMissing:
		result.Status = "blocked"
		result.ReasonCode = "native_service_unit_not_provisioned"
		result.Summary = "The proposed STL-exclusive IPsec service unit is not installed."
		result.NextStep = ipsecCurrentPrepareGuidance + " Never adopt, overwrite or stop a distro strongSwan service without its separately verified, exact-unit authorization."
	case ipsec.NativeServiceUnitConflict:
		result.Status = "blocked"
		result.ReasonCode = "native_service_unit_untrusted"
		result.Summary = "The proposed STL-exclusive IPsec service file or parent path is changed or untrusted."
		result.NextStep = "Reconcile the conflicting service identity manually; never overwrite an existing unit, even with matching bytes."
	}
	return result
}
