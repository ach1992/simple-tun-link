package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
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
		!strings.Contains(all.String(), "5/5") ||
		!strings.Contains(all.String(), "Replied") ||
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
	if label != "[Check needed]" {
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
	if code != 0 || !strings.Contains(out, "[Check needed]") ||
		!strings.Contains(out, "precheck did not pass") ||
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

// FOU and GUE have a shared prerequisite, so operator help must group
// four rows into one evidence-backed cause, with concrete read-only steps.
func TestMenuAvailabilityHelpGroupsSharedFailuresAndClearsPreviousPrompt(t *testing.T) {
	report := linux.CapabilityReport{
		linux.CapabilityGREFOU:    {ReasonCode: "fou_module_present_probe_failed", Reason: "FOU module is found on disk"},
		linux.CapabilityGREGUE:    {ReasonCode: "fou_module_present_probe_failed", Reason: "FOU module is found on disk"},
		linux.CapabilityIPIPFOU:   {ReasonCode: "fou_module_present_probe_failed", Reason: "FOU module is found on disk"},
		linux.CapabilityIPIPGUE:   {ReasonCode: "fou_module_present_probe_failed", Reason: "FOU module is found on disk"},
		linux.CapabilityIPsecXFRM: {ReasonCode: "swanctl_probe_unconfirmed", Reason: "swanctl check failed"},
	}
	var out bytes.Buffer
	menuCapabilityHelp(&out, report)
	result := out.String()
	for _, label := range []string{"AVAILABILITY / EXPLANATION", "FOU/GUE x4", "IPsec x2",
		"FOU module is found on disk", "swanctl check failed", "modinfo fou", "stl doctor ipsec --json",
		"permanent lack of support is NOT proven"} {
		if !strings.Contains(result, label) {
			t.Fatalf("missing operator explanation %s: %q", label, result)
		}
	}
	if strings.Count(result, "FOU module is found on disk") != 1 || strings.Contains(result, "ipip/gue") {
		t.Fatalf("shared prerequisite repeated as separate failures: %q", result)
	}
}

// Diagnostic next steps can be copyable commands. Displaying a long one in
// a narrow PTY must not insert characters or line breaks into the command.
func TestMenuDiagnosticNextStepKeepsExactCopyableCommand(t *testing.T) {
	command := "sudo stl doctor ipsec --json --some-very-long-option-that-must-stay-copyable"
	response, err := json.Marshal(linkReadErrorResponse{
		SchemaVersion: jsonSchemaVersion,
		Error: &stlerr.Error{
			Code:       stlerr.CodeInspect,
			Detail:     "Local observation is incomplete",
			ReasonCode: "observation_unverified",
			NextStep:   command,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	master, slave := openMenuPTY(t)
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 24, Col: 60}); err != nil {
		t.Fatal(err)
	}
	menuPublicDiagnosticFailure(slave, response)
	got := readMenuPTYUntil(t, master, command)
	if !strings.Contains(got, command) || strings.Contains(got, "\x1b[") {
		t.Fatalf("copyable diagnostic action corrupted by terminal formatting: %q", got)
	}
	var plain bytes.Buffer
	menuPublicDiagnosticFailure(&plain, response)
	if !strings.Contains(plain.String(), command+"\n") || strings.Contains(plain.String(), "\x1b[") {
		t.Fatalf("redirected diagnostic changed exact command: %q", plain.String())
	}
}

func TestCompactAllTunnelTablePreservesHonestStatusesAndActions(t *testing.T) {
	response := healthCenterResponse{SchemaVersion: jsonSchemaVersion, Operation: "link_diagnose_all",
		Total: 4, Observed: 1, Blocked: 1, Unknown: 2, Outcome: "complete",
		Checks: []healthLinkCheck{
			{
				Link:   linkSummary{Backend: "gre", Encapsulation: "native", PeerAddress: "10.80.1.1/31"},
				Status: "observed", ReasonCode: "link_peer_replied",
				Observed: &healthLinkObservation{Quality: diagnostics.QualityResult{Status: diagnostics.QualityMeasured,
					Reachable: true, PacketsSent: 5, PacketsReceived: 5}},
			},
			{
				Link:   linkSummary{Backend: "wireguard", Encapsulation: "udp", PeerAddress: "10.80.2.1/31"},
				Status: "unknown", ReasonCode: "link_probe_no_reply",
				NextStep: "Check the peer firewall.", Observed: &healthLinkObservation{Quality: diagnostics.QualityResult{
					Status: diagnostics.QualityMeasured, PacketsSent: 5, PacketsReceived: 0}},
			},
			{
				Link:   linkSummary{Backend: "ipsec", Encapsulation: "esp", PeerAddress: "10.80.3.1/31"},
				Status: "blocked", ReasonCode: "ipsec_runtime_not_registered",
				NextStep: "stl doctor ipsec",
			},
			{
				Link:   linkSummary{Backend: "gre", Encapsulation: "gue", PeerAddress: "10.80.4.1/31"},
				Status: "unknown", ReasonCode: "diagnostic_interrupted",
				NextStep: "Repeat the read-only check.",
			},
		}}
	var out bytes.Buffer
	menuAllCheckTable(&out, response)
	got := out.String()
	for _, term := range []string{
		"Tunnel", "Peer Link IP", "Ping", "Result",
		"gre/native", "wireguard/udp", "ipsec/esp", "gre/gue",
		"5/5", "0/5", "Replied", "No reply", "Blocked", "Interrupted",
		"ipsec_runtime_not_registered", "stl doctor ipsec",
		"Links in snapshot: 4 | peer replied: 1 | blocked: 1 | unknown: 2",
		"No ICMP reply does not prove",
	} {
		if !strings.Contains(got, term) {
			t.Fatalf("missing %q in compact all-tunnel table: %s", term, got)
		}
	}
	if strings.Count(got, "Peer Link IP") != 1 || strings.Contains(got, "Disconnected") ||
		strings.Contains(got, "Connected") || strings.Contains(got, "\x1b[") ||
		strings.Contains(got, "Suggested MTU") {
		t.Fatalf("compact view was misleading, decorated or verbose: %s", got)
	}
	// For a contradictory response, do not promote the human label to
	// peer-replied merely because a string claims it was observed.
	bad := response.Checks[0]
	bad.Observed.Quality.Reachable = false
	if label, kind := menuAllCheckResult(bad); label != "Unknown" || kind != "UNKNOWN" {
		t.Fatalf("inconsistent observation treated as peer reply: %s %s", label, kind)
	}
	bad.Observed.Quality.Reachable = true
	bad.Observed.Quality.PacketsReceived = 1
	if label, kind := menuAllCheckResult(bad); label != "Packet loss" || kind != "WARNING" {
		t.Fatalf("observed packet loss was colored fully healthy: %s %s", label, kind)
	}
}

func TestCompactAllTunnelTableUsesNarrowLayoutAndNoColor(t *testing.T) {
	master, slave := openMenuPTY(t)
	t.Setenv("NO_COLOR", "")
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 30, Col: 52}); err != nil {
		t.Fatal(err)
	}
	report := healthCenterResponse{Total: 1, Observed: 1, Outcome: "complete", Checks: []healthLinkCheck{{
		Link:   linkSummary{Backend: "gre", Encapsulation: "native", PeerAddress: "10.88.9.1/31"},
		Status: "observed", ReasonCode: "link_peer_replied",
		Observed: &healthLinkObservation{Quality: diagnostics.QualityResult{
			Status: diagnostics.QualityMeasured, Reachable: true, PacketsSent: 5, PacketsReceived: 5}},
	}}}
	menuAllCheckTable(slave, report)
	got := readMenuPTYUntil(t, master, "gre/native", "Ping:", "Replied")
	for _, expected := range []string{"10.88.9.1/31", "Ping:", "Result:", "5/5", "Replied"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("narrow layout missed %q: %s", expected, got)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("NO_COLOR rendered ANSI: %q", got)
	}
}

func TestCompactAllTunnelTableWrapsLargeSummaryWithoutBreakingColumns(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	master, slave := openMenuPTY(t)
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 30, Col: 68}); err != nil {
		t.Fatal(err)
	}
	// The renderer is independently tested with large counters; the caller
	// separately validates that totals match the canonical inventory.
	report := healthCenterResponse{
		Total: 1000000, Observed: 1000000, Outcome: "interrupted",
	}
	menuAllCheckTable(slave, report)
	got := readMenuPTYUntil(t, master, "unknown: 0", "run: interrupted")
	for _, line := range strings.Split(got, "\r\n") {
		if len(line) > 68 {
			t.Fatalf("summary wrapped unintentionally: %q\n%s", line, got)
		}
	}
}

func TestCompactAllTunnelTablePreservesCopyableNextAction(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	master, slave := openMenuPTY(t)
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 30, Col: 32}); err != nil {
		t.Fatal(err)
	}
	action := "stl doctor ipsec --json --include-all-read-only-checks"
	report := healthCenterResponse{Total: 1, Blocked: 1, Outcome: "complete", Checks: []healthLinkCheck{{
		Link:   linkSummary{Backend: "ipsec", Encapsulation: "esp", PeerAddress: "10.80.3.1/31"},
		Status: "blocked", ReasonCode: "ipsec_runtime_not_registered",
		NextStep: action,
	}}}
	menuAllCheckTable(slave, report)
	got := readMenuPTYUntil(t, master, action)
	if !strings.Contains(got, "\r\n"+action+"\r\n") {
		t.Fatalf("copyable action was split or decorated: %q", got)
	}
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("NO_COLOR added ANSI to a diagnostic action: %q", got)
	}
}

func TestCompactAllTunnelTableAvoidsAccidentalWrapOnNarrowPTY(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, tc := range []struct {
		name     string
		width    uint16
		peer     string
		received int
		label    string
	}{
		{"long_peer_52", 52, "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128", 5, "Replied"},
		{"packet_loss_28", 28, "10.88.9.1/31", 1, "Packet loss"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, slave := openMenuPTY(t)
			if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
				&unix.Winsize{Row: 30, Col: tc.width}); err != nil {
				t.Fatal(err)
			}
			report := healthCenterResponse{Total: 1, Observed: 1, Outcome: "complete", Checks: []healthLinkCheck{{
				Link:   linkSummary{Backend: "gre", Encapsulation: "native", PeerAddress: tc.peer},
				Status: "observed", ReasonCode: "link_peer_replied",
				Observed: &healthLinkObservation{Quality: diagnostics.QualityResult{
					Status: diagnostics.QualityMeasured, Reachable: true, PacketsSent: 5,
					PacketsReceived: tc.received}},
			}}}
			menuAllCheckTable(slave, report)
			got := readMenuPTYUntil(t, master, tc.peer, "Result: "+tc.label)
			if strings.Contains(got, "\x1b[") {
				t.Fatalf("NO_COLOR added ANSI: %q", got)
			}
			for _, line := range strings.Split(got, "\r\n") {
				if len(line) > int(tc.width) {
					t.Fatalf("rendered %d columns on %d-column PTY: %q\n%s", len(line), tc.width, line, got)
				}
			}
		})
	}
}
