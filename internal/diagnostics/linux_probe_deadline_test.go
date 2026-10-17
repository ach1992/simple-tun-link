//go:build linux

package diagnostics

import (
	"context"
	"fmt"
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

// mixedLinuxSummaryRunner does not invoke an OS process or use the network.
// It drives the real LinuxDFProber parsing boundary with a sequence of actual
// iputils-style success and no-reply exit-status/summary pairs.
type mixedLinuxSummaryRunner struct {
	calls int
}

func (r *mixedLinuxSummaryRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	if name != "env" || len(args) < 1 || args[0] != "LC_ALL=C" {
		return linux.CommandResult{}, fmt.Errorf("unexpected Linux probe invocation")
	}
	r.calls++
	if r.calls == 2 || r.calls == 4 {
		return linux.CommandResult{Stdout: []byte("1 packets transmitted, 0 received, 100% packet loss\n")},
			&linux.CommandError{Command: "env", ExitCode: 1}
	}
	return linux.CommandResult{Stdout: []byte(
		"64 bytes from 10.80.20.1: icmp_seq=1 ttl=64 time=49.123 ms\n" +
			"1 packets transmitted, 1 received, 0% packet loss\n")}, nil
}

func TestLinuxQualityMixedFiveSampleSummariesRemainMeasured(t *testing.T) {
	runner := &mixedLinuxSummaryRunner{}
	link := diagnosticLink()
	prober, err := NewLinuxDFProber(link, LinuxProbeOptions{
		Runner: runner, Interface: "stltest0", PingBinary: "/usr/bin/ping",
	})
	if err != nil {
		t.Fatal(err)
	}
	quality, err := MeasureQuality(context.Background(), link, 1280, 0, prober)
	if err != nil {
		t.Fatal(err)
	}
	if runner.calls != DefaultQualitySamples || quality.ProbeCalls != 5 ||
		quality.PacketsSent != 5 || quality.PacketsReceived != 3 ||
		quality.Status != QualityMeasured || quality.Reason != QualityReasonNone ||
		quality.PacketLossPct == nil || *quality.PacketLossPct != 40 {
		t.Fatalf("mixed iputils summaries did not complete the five-sample check: calls=%d result=%+v", runner.calls, quality)
	}
}
