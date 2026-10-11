package diagnostics

import "github.com/ach1992/simple-tun-link/internal/backend/ipsec"

// inspectNativeExclusiveConfig is a read-only, time-local artifact check.
// Exact bytes and private root ownership are prerequisites, never proof that
// STL created the inode, systemd selected it, logging is effective or a
// private VICI/service writer is exclusively controlled.
func inspectNativeExclusiveConfig(inspect func() ipsec.NativeConfigAssessment) IPsecHostCheck {
	check := IPsecHostCheck{
		Name: "native_config", Status: "unknown",
		ReasonCode: "native_config_unverified",
		Summary:    "The proposed native-exclusive strongSwan configuration could not be verified.",
		NextStep:   "Inspect root-private configuration identity and permissions; do not activate IPsec from partial evidence.",
	}
	if inspect == nil {
		return check
	}
	switch inspect() {
	case ipsec.NativeConfigExact:
		check.Status = "observed"
		check.ReasonCode = "native_config_bytes_verified"
		check.Summary = "The protected native-exclusive configuration matches reviewed bytes at inspection time; running service and effective logging remain unverified."
		check.NextStep = "Attest STL-origin publication, package/service/process identity, live logger policy, VICI access, ports and kernel ownership before activation."
	case ipsec.NativeConfigMissing:
		check.Status = "blocked"
		check.ReasonCode = "native_config_not_provisioned"
		check.Summary = "The proposed STL-private strongSwan configuration was not found."
		check.NextStep = "Use a future verified STL-only provisioner; do not copy or adopt foreign strongSwan configuration."
	case ipsec.NativeConfigConflict:
		check.Status = "blocked"
		check.ReasonCode = "native_config_untrusted"
		check.Summary = "The proposed native-exclusive strongSwan configuration or its path is unsafe or differs from the reviewed profile."
		check.NextStep = "Reconcile the untrusted file/path manually without overwriting or adopting a foreign configuration."
	}
	return check
}
