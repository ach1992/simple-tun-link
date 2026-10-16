package main

import "github.com/ach1992/simple-tun-link/internal/diagnostics"

// Fixed public descriptions of the production's read-only native preflight.
// Never forward an arbitrary lower-level error, path, command transcript,
// secret, or environment variable into the operator view / v1 diagnostic.
func ipsecReadinessCheck(err error) diagnostics.IPsecHostCheck {
	check := diagnostics.IPsecHostCheck{
		Name: "provisioning_readiness", Status: "blocked",
		ReasonCode: "ipsec_provisioning_unverified",
		Summary:    "A fresh native-exclusive service could not be safely prepared; no service was changed.",
		NextStep:   "Review systemd, strongSwan package identity, owner-private files and UDP 500/4500 read-only; do not retry PREPARE blindly.",
	}
	if err == nil {
		check.Status = "observed"
		check.ReasonCode = "ipsec_provisioning_prerequisites_verified"
		check.Summary = "A new STL-exclusive IPsec service currently passes read-only preflight. It has not been provisioned or started."
		check.NextStep = "Use the guided IPsec PREPARE with fresh administrator confirmation; repeat preflight under the installed maintenance lock."
		return check
	}
	switch err.Error() {
	case "root systemd host inspection unavailable":
		check.ReasonCode = "ipsec_provisioning_host_unverified"
		check.NextStep = "Run sudo stl menu on the local systemd host; inspect timeouts/permissions before retrying."
	case "root-owned strongSwan executable not verified":
		check.ReasonCode = "ipsec_provisioning_executable_unverified"
		check.NextStep = "Verify the distro-owned /usr/sbin/charon-systemd executable and parent permissions; do not replace a foreign binary."
	case "STL private IPsec publication already exists or is uncertain; never adopt/replace":
		check.ReasonCode = "ipsec_provisioning_private_publication_conflict"
		check.NextStep = "Inspect previously published STL private config/unit and ownership receipts; do not overwrite or clear unresolved state."
	case "native systemd loaded identity unavailable or occupied":
		check.ReasonCode = "ipsec_provisioning_private_unit_conflict"
		check.NextStep = "Inspect systemctl list-units and show simple-tun-link-ipsec.service, including aliases, generators and overrides; do not reset or adopt an unknown unit."
	case "foreign strongSwan process present or unverified":
		check.ReasonCode = "ipsec_provisioning_daemon_conflict"
		check.NextStep = "Inspect same-network-namespace charon processes and owners without stopping them."
	case "existing or unverified IKE UDP 500/4500 owner":
		check.ReasonCode = "ipsec_provisioning_ports_conflict"
		check.NextStep = "Inspect listeners on UDP 500/4500 read-only; never stop an unknown VPN to free these ports."
	case "vendor strongSwan service active or ambiguous":
		check.ReasonCode = "ipsec_provisioning_vendor_activity_unverified"
		check.NextStep = "Check systemctl is-active and show ActiveState for strongswan, strongswan-starter, charon-systemd and ipsec.service."
	case "vendor strongSwan service enabled or ambiguous":
		check.ReasonCode = "ipsec_provisioning_vendor_enablement_unverified"
		check.NextStep = "Check systemctl is-enabled and show UnitFileState/FragmentPath for each vendor service. An inactive/disabled unit does not need stopping."
	case "private VICI socket already present or cannot be inspected":
		check.ReasonCode = "ipsec_provisioning_vici_conflict"
		check.NextStep = "Inspect the STL-private VICI socket path and its owner; do not delete an unknown or retained socket."
	default:
		// Unknown nested/error text must not leak, including future
		// third-party tool output inadvertently wrapped in an error.
	}
	return check
}
