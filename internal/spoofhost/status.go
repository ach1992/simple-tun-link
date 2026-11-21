package spoofhost

import (
	"time"

	spoofbackend "github.com/ach1992/simple-tun-link/internal/backend/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// TrustedRuntimeStatus projects a helper report only when it belongs to the
// current, exactly identified systemd helper and is fresh. The status file is
// never a substitute for live unit/TUN/route ownership or for peer traffic.
func TrustedRuntimeStatus(root string, id domain.LinkID, host spoofbackend.HostObservation) RuntimeStatus {
	unknown := RuntimeStatus{SchemaVersion: 1, LinkID: id, State: "STOPPED_OR_UNVERIFIED"}
	if !host.RuntimeReady || !host.UnitActive || !host.UnitOwned || host.HelperPID <= 1 {
		return unknown
	}
	report, err := ReadRuntimeStatus(root, id)
	if err != nil || report.PID != host.HelperPID || report.UpdatedAt.IsZero() {
		return unknown
	}
	age := time.Since(report.UpdatedAt)
	if age > 6*time.Second || age < -2*time.Second {
		return unknown
	}
	// State is a claim made by the running helper, not independent evidence
	// of private application success. Never upgrade a contradictory report.
	if report.State == "CONNECTED" && (!report.Authenticated || !report.BilateralConfirmed) {
		return unknown
	}
	return report
}
