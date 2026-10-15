package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func TestMenuFivePingResultIsNotCumulativeTrafficOrLongTermStability(t *testing.T) {
	zero, full := 0.0, 100.0
	minRTT, avgRTT, maxRTT, jitter := 10.5, 13.3, 18.1, 2.1
	rx, tx := uint64(23), uint64(41)
	mtu := diagnostics.MTUResult{SelectedMTU: 1280, Choice: diagnostics.MTUFallback}
	for _, tc := range []struct {
		name    string
		quality diagnostics.QualityResult
		want    []string
		absent  []string
	}{
		{
			name: "all five returned",
			quality: diagnostics.QualityResult{Status: diagnostics.QualityMeasured,
				PacketsSent: 5, PacketsReceived: 5, PacketLossPct: &zero,
				MinRTTMs: &minRTT, AvgRTTMs: &avgRTT, MaxRTTMs: &maxRTT, JitterMs: &jitter},
			want: []string{"[OK]  5/5 replies (0% packet loss)", "avg 13.3 ms",
				"min 10.5", "max 18.1", "2.1 ms between consecutive replies",
				"1280 bytes (conservative estimate; not peer-confirmed)", "RX/TX", "(cumulative)",
				"long-term stability is not proven"},
			absent: []string{"Connection permanently stable", "Peer disconnected"},
		},
		{
			name: "no peer response",
			quality: diagnostics.QualityResult{Status: diagnostics.QualityMeasured,
				PacketsSent: 5, PacketsReceived: 0, PacketLossPct: &full},
			want: []string{"[WARNING]  0/5 replies (100% packet loss)",
				"No peer ping replies.", "(cumulative)"},
			absent: []string{"[OK]  0/5", "avg 0.0"},
		},
		{
			name: "unable to send or verify probes",
			quality: diagnostics.QualityResult{Status: diagnostics.QualityUnavailable,
				Reason: diagnostics.QualityReasonProbeError},
			want: []string{"[UNKNOWN]  Not measured", "Probe error; ping result is unknown",
				"Ping was not measured."},
			absent: []string{"0/0 replies", "100% packet loss", "Peer disconnected"},
		},
		{
			name: "partial probe results",
			quality: diagnostics.QualityResult{Status: diagnostics.QualityPartial,
				PacketsSent: 3, PacketsReceived: 2, Reason: diagnostics.QualityReasonProbeError},
			want:   []string{"[WARNING]  2/3 replies", "test interrupted", "Some pings had no reply."},
			absent: []string{"5/5 replies", "Ping was not measured."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			menuHealthMeasurements(&out, mtu, tc.quality, &rx, &tx, "packets", nil)
			menuHealthNext(&out, tc.quality)
			rendered := out.String()
			for _, word := range tc.want {
				if !strings.Contains(rendered, word) {
					t.Fatalf("missing %q in: %s", word, rendered)
				}
			}
			for _, word := range tc.absent {
				if strings.Contains(rendered, word) {
					t.Fatalf("misleading %q in: %s", word, rendered)
				}
			}
			if strings.Contains(rendered, "\x1b[") {
				t.Fatal("redirected output unexpectedly contains ANSI")
			}
		})
	}
}

func TestMenuHealthUsesCanonicalFivePingObservationsAcrossBackends(t *testing.T) {
	root, implementations, runner, links := fixtureHealthCenter(t)
	opts := &runtimeOptions{stateRoot: root, backends: implementations, probeRunner: runner}
	var output, errors bytes.Buffer
	if code := menuCheckOneConnection(links[0].ID, &output, &errors, opts); code != 0 {
		t.Fatalf("per-Link check failed: %d %s", code, errors.String())
	}
	for _, term := range []string{"5/5 replies", "0% packet loss", "Latency", "Ping variation", "RX/TX", "cumulative"} {
		if !strings.Contains(output.String(), term) {
			t.Fatalf("missing five-ping evidence %q: %s", term, output.String())
		}
	}
	if strings.Contains(output.String(), "private_key") || strings.Contains(output.String(), "stl://") {
		t.Fatal("secret leaked in human health")
	}
	var all, errorsAll bytes.Buffer
	code := menuCheckAllConnections(&all, &errorsAll, opts)
	if code != 4 || !strings.Contains(all.String(), "Links in snapshot: 4") ||
		!strings.Contains(all.String(), "5/5 replies") ||
		!strings.Contains(all.String(), "ipsec_runtime_not_registered") ||
		!strings.Contains(all.String(), "Some links remain unknown, blocked") {
		t.Fatalf("mixed all-link health classification failed: code=%d out=%s err=%s", code, all.String(), errorsAll.String())
	}
	// A subsequent list/report read is intentionally state-only, not proof
	// that the remote tunnel was installed or pings will keep succeeding.
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snapshot.Links) != 4 {
		t.Fatalf("health changed the saved tunnel inventory: %+v %v", snapshot, err)
	}
}

func TestMenuTypePrechecksAreHintsAndUnavailablePrecedesPeerEntry(t *testing.T) {
	report := linux.CapabilityReport{
		linux.CapabilityGRENative: {Available: true},
		linux.CapabilityGREGUE:    {Available: false, Reason: "GUE capability unavailable"},
		linux.CapabilityIPsecXFRM: {Available: true},
	}
	label, _ := menuCapabilityHint(report, basicTunnelOptions["1"])
	if label != "[Precheck OK]" {
		t.Fatal(label)
	}
	label, _ = menuCapabilityHint(report, advancedTunnelOptions["2"])
	if label != "[Unavailable]" {
		t.Fatal(label)
	}
	label, _ = menuCapabilityHint(report, advancedTunnelOptions["5"])
	if label != "[Verify service]" {
		t.Fatal(label)
	}
	label, _ = menuCapabilityHint(nil, advancedTunnelOptions["5"])
	if label != "[Check needed]" {
		t.Fatal(label)
	}

	host := &guidedTestRunner{capabilityFail: true}
	fake := &guidedTestBackend{lifecycleFakeBackend: newLifecycleFake()}
	opts := guidedTestOptions(t.TempDir(), host, fake)
	code, out, errOut := runGuidedTest(opts, "1\n1\n8\n")
	if code != 0 || !strings.Contains(out, "[Unavailable]") ||
		!strings.Contains(errOut, "not available on this server") ||
		strings.Contains(out, "Other server's reachable IPv4") ||
		strings.Contains(out, "[FAILED] Action not confirmed") || len(fake.applies) != 0 {
		t.Fatalf("unsupported choice not explained early: code=%d out=%s err=%s", code, out, errOut)
	}
}
