package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// All-Link uses the same per-Link limit as single-Link diagnosis. Its parent
// --timeout must still override a child and emit only unknown rows when it
// actually expires mid-observation, never a healthy or packet-loss reading.
func TestHealthCenterDeadlineDuringActiveProbeIsUnknown(t *testing.T) {
	root, backends, runner, links := fixtureHealthCenter(t)
	if diagnoseOperationTimeout != 35*time.Second ||
		diagnoseOperationTimeout-diagnostics.DefaultDiagnosticProbeBudget < 7*time.Second {
		t.Fatalf("per-Link deadline does not reserve time for inspection: %s", diagnoseOperationTimeout)
	}
	calls := 0
	services := healthCenterServices{
		observe: func(ctx context.Context, _ domain.Link, _ runtimeOptions) (linkDiagnostic, error) {
			calls++
			<-ctx.Done()
			return linkDiagnostic{}, ctx.Err()
		},
	}
	var stdout, stderr strings.Builder
	code := linkDiagnoseAllWithServices(
		[]string{"diagnose", "--all", "--timeout", "250ms", "--json"},
		&stdout, &stderr,
		&runtimeOptions{stateRoot: root, backends: backends, probeRunner: runner},
		services,
	)
	var report healthCenterResponse
	if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil {
		t.Fatalf("no versioned interrupted report: %v body=%s", err, stdout.String())
	}
	if code != 1 || stderr.Len() != 0 || calls != 1 ||
		report.Outcome != "interrupted" || report.Total != len(links) ||
		report.Observed != 0 || report.Unknown != len(links) || report.Blocked != 0 {
		t.Fatalf("parent deadline was not enforced per Link: code=%d calls=%d report=%+v stderr=%s", code, calls, report, stderr.String())
	}
	for _, check := range report.Checks {
		if check.Status != "unknown" || check.ReasonCode != "diagnostic_interrupted" ||
			check.Observed != nil || check.NextStep == "" {
			t.Fatalf("deadline became healthy or measured packet loss: %+v", check)
		}
	}
}
