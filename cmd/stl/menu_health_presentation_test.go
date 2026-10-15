package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

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
	for _, term := range []string{"5/5 replies", "0% packet loss", "Latency", "Ping variation", "21 / 22 packets (cumulative)"} {
		if !strings.Contains(output.String(), term) {
			t.Fatalf("missing five-ping evidence %q: %s", term, output.String())
		}
	}
	if strings.Contains(output.String(), "private_key") || strings.Contains(output.String(), "stl://") {
		t.Fatal("secret leaked in human health")
	}
	probeCount := func() int {
		count := 0
		for _, n := range runner.probes {
			count += n
		}
		return count
	}
	if probeCount() != 6 {
		t.Fatalf("Per-Link health must reuse one canonical 5-sample run and MTU probe; got %d calls", probeCount())
	}
	// Per-Link JSON deliberately has no backend counters. Verify the UI
	// obtains the optional cumulative values from canonical read-only Status
	// rather than displaying a fabricated 0/0 or claiming a live transfer.
	var wgOutput, wgErrors bytes.Buffer
	if code := menuCheckOneConnection(links[2].ID, &wgOutput, &wgErrors, opts); code != 0 {
		t.Fatalf("WireGuard per-Link check failed: %d %s", code, wgErrors.String())
	}
	if !strings.Contains(wgOutput.String(), "41 / 42 bytes (cumulative)") ||
		!strings.Contains(wgOutput.String(), "2023-11-14 22:13 UTC (historical)") {
		t.Fatalf("WireGuard counters/handshake were not correctly observed: %s", wgOutput.String())
	}
	if probeCount() != 12 {
		t.Fatalf("A separate read-only Status check must not send extra pings; got %d calls", probeCount())
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

// Narrow PTYs must show health details as deliberate rows, not accidental
// terminal wrapping that interleaves status, messages and next actions.
func TestMenuHealthNarrowTerminalHasReadableRows(t *testing.T) {
	master, slave := openMenuPTY(t)
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "xterm-256color")
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 48}); err != nil {
		t.Fatal(err)
	}
	menuHealthLine(slave, "Suggested MTU", "WARNING",
		"1280 bytes (conservative estimate; not peer-confirmed)")
	result := readMenuPTYUntil(t, master, "[WARNING]", "peer-confirmed)")
	if !strings.Contains(result, "Suggested MTU") || !strings.Contains(result, "\r\n      1280 bytes") ||
		strings.Contains(result, "\x1b[") {
		t.Fatalf("Narrow health output was not aligned/ANSI disabled: %q", result)
	}
	for _, line := range strings.Split(result, "\r\n") {
		if len(line) > 48 {
			t.Fatalf("Narrow health output exceeded 48 visible columns: %q", line)
		}
	}
	// A short field label is still padded to 16 columns; width estimation
	// must include that padding rather than measuring just the word "Ping".
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	menuHealthLine(slave, "Ping", "WARNING", "5/5 replies; only a short observational check was run")
	second := readMenuPTYUntil(t, master, "[WARNING]", "observational check was run")
	if !strings.Contains(second, "Ping             [WARNING]\r\n") {
		t.Fatalf("Long Ping detail should wrap after its status label: %q", second)
	}
}
