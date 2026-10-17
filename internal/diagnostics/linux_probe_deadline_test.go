//go:build linux

package diagnostics

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

// This fake ping waits slightly longer than its -W 1 reply window to model
// process exit/scheduler overhead. It never sends real network traffic.
// A one-second child context would kill it before its trustworthy summary.
func TestLinuxQualityAllowsOneSecondPingNoReplySummary(t *testing.T) {
	pingPath := filepath.Join(t.TempDir(), "fake-ping")
	script := "#!/bin/sh\nsleep 1.1\nprintf '1 packets transmitted, 0 received, 100%% packet loss\\n'\nexit 1\n"
	if err := os.WriteFile(pingPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}

	link := diagnosticLink()
	prober, err := NewLinuxDFProber(link, LinuxProbeOptions{
		Runner:     linux.ExecRunner{},
		Interface:  "stltest0",
		PingBinary: pingPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := MeasureQuality(context.Background(), link, 1280, 1, prober)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != QualityMeasured || result.PacketsSent != 1 ||
		result.PacketsReceived != 0 || result.ProbeCalls != 1 ||
		result.Reason != QualityReasonNone || result.PacketLossPct == nil ||
		*result.PacketLossPct != 100 {
		t.Fatalf("one unanswered ping must be measured packet loss, got %+v", result)
	}
}
