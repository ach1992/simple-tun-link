package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// All human health views consume existing read-only, versioned CLI reports.
// They neither implement their own probes nor change machine CLI/JSON output.
func menuHealthLine(out io.Writer, label, kind, value string) {
	status := menuPaint(out, menuStatusRole(kind), "["+kind+"]")
	if tty, ok := menuTerminal(out); ok {
		// Account for the minimum 16-column label even when its text is
		// shorter (Ping, MTU, etc.), plus spaces and the [STATUS] brackets.
		visibleWidth := 2 + max(16, len(label)) + 1 + len(kind) + 2 + 2 + len(value)
		if ws, err := unix.IoctlGetWinsize(int(tty.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col > 0 &&
			visibleWidth > int(ws.Col) && !menuCopyable(value) {
			fmt.Fprintf(out, "  %-16s %s\n", label, status)
			width := max(16, int(ws.Col)-6)
			fmt.Fprintln(out, "      "+strings.ReplaceAll(wrapTerminalGuidance(value, width), "\n", "\n      "))
			return
		}
	}
	fmt.Fprintf(out, "  %-16s %s  %s\n", label, status, value)
}

func menuHealthMeasurements(out io.Writer, mtu diagnostics.MTUResult, quality diagnostics.QualityResult,
	rx, tx *uint64, counterUnit string, handshake *int64) {
	if quality.PacketsSent > 0 {
		kind := "WARNING"
		if quality.Status == diagnostics.QualityMeasured && quality.PacketsReceived == quality.PacketsSent {
			kind = "OK"
		}
		value := fmt.Sprintf("%d/%d replies", quality.PacketsReceived, quality.PacketsSent)
		if quality.PacketLossPct != nil {
			value += fmt.Sprintf(" (%.0f%% packet loss)", *quality.PacketLossPct)
		}
		if quality.Status == diagnostics.QualityPartial {
			value += "; test interrupted"
		}
		menuHealthLine(out, "Ping", kind, value)
	} else {
		menuHealthLine(out, "Ping", "UNKNOWN", "Not measured (no verified ICMP attempts)")
	}
	if quality.PacketsReceived > 0 && quality.AvgRTTMs != nil && quality.MinRTTMs != nil && quality.MaxRTTMs != nil {
		menuField(out, "Latency", fmt.Sprintf("avg %.1f ms | min %.1f | max %.1f",
			*quality.AvgRTTMs, *quality.MinRTTMs, *quality.MaxRTTMs))
		if quality.JitterMs != nil {
			menuField(out, "Ping variation", fmt.Sprintf("%.1f ms between consecutive replies", *quality.JitterMs))
		}
	}
	if quality.PacketsSent == 0 || quality.Status != diagnostics.QualityMeasured {
		menuField(out, "Probe reason", menuProbeReason(quality.Reason))
	}
	if mtu.SelectedMTU > 0 {
		switch mtu.Choice {
		case diagnostics.MTUVerified:
			menuHealthLine(out, "Suggested MTU", "OK", fmt.Sprintf("%d bytes (peer probe-confirmed suggestion)", mtu.SelectedMTU))
		case diagnostics.MTUManual:
			menuHealthLine(out, "Suggested MTU", "INFO", fmt.Sprintf("%d bytes (manual request; not probe-confirmed)", mtu.SelectedMTU))
		default:
			menuHealthLine(out, "Suggested MTU", "WARNING", fmt.Sprintf("%d bytes (conservative estimate; not peer-confirmed)", mtu.SelectedMTU))
		}
	}
	if rx != nil && tx != nil && counterUnit != "" {
		menuField(out, "Interface RX/TX", fmt.Sprintf("%d / %d %s (cumulative)", *rx, *tx, counterUnit))
	} else {
		menuField(out, "Interface RX/TX", "not verified")
	}
	if handshake != nil {
		if *handshake <= 0 {
			menuHealthLine(out, "WireGuard", "UNKNOWN", "No handshake observed")
		} else {
			menuField(out, "Last handshake", time.Unix(*handshake, 0).UTC().Format("2006-01-02 15:04 UTC")+" (historical)")
		}
	}
}

func menuProbeReason(reason diagnostics.QualityReason) string {
	switch reason {
	case diagnostics.QualityReasonProbeError:
		return "Probe error; ping result is unknown"
	case diagnostics.QualityReasonUnsupported, diagnostics.QualityReasonNoProbe:
		return "ICMP probe facility unavailable"
	case diagnostics.QualityReasonTooLarge:
		return "Small packet rejected as too large"
	case diagnostics.QualityReasonNone:
		return "No additional error identified"
	default:
		return "Incomplete diagnostic observation"
	}
}

func menuHealthNext(out io.Writer, quality diagnostics.QualityResult) {
	switch {
	case quality.Status == diagnostics.QualityMeasured && quality.PacketsSent > 0 && quality.PacketsReceived == quality.PacketsSent:
		menuNotice(out, "OK", "Peer answered all pings in this short check; long-term stability is not proven.")
	case quality.PacketsSent > 0 && quality.PacketsReceived == quality.PacketsSent:
		menuNotice(out, "WARNING", "All attempted pings replied, but the five-sample check ended early.")
	case quality.PacketsSent > 0 && quality.PacketsReceived > 0:
		menuNotice(out, "WARNING", "Some pings had no reply. Check packet loss and repeat later if needed.")
	case quality.PacketsSent > 0:
		menuNotice(out, "WARNING", "No peer ping replies. Check peer setup, route and ICMP/firewall rules.")
	default:
		menuNotice(out, "WARNING", "Ping was not measured. Check local probe tools and peer setup.")
	}
}

func menuPublicDiagnosticFailure(out io.Writer, raw []byte) {
	var failure linkReadErrorResponse
	if json.Unmarshal(raw, &failure) == nil && failure.Error != nil {
		menuNotice(out, "WARNING", "Could not verify connection; this does not prove the tunnel is disconnected.")
		if failure.Error.Detail != "" {
			menuField(out, "Problem", failure.Error.Detail)
		}
		if failure.Error.ReasonCode != "" {
			menuField(out, "Reason", failure.Error.ReasonCode)
		}
		menuSection(out, "Next check")
		menuProse(out, failure.Error.NextStep)
		return
	}
	menuNotice(out, "WARNING", "Connection check unavailable. Inspect local status and prerequisites; no changes made.")
}

// The one-Link quality JSON intentionally contains no backend traffic counters.
// A separate canonical read-only Status observation provides optional cumulative
// counters and handshake. It does NOT rerun ICMP probes or alter QualityResult.
func menuReadVerifiedStatus(id domain.LinkID, options *runtimeOptions) (linkStatusResponse, []byte, int) {
	var raw bytes.Buffer
	code := linkReadCommand([]string{"status", string(id), "--json"}, &raw, io.Discard, options)
	if code != 0 {
		return linkStatusResponse{}, raw.Bytes(), code
	}
	var result linkStatusResponse
	if err := json.Unmarshal(raw.Bytes(), &result); err != nil ||
		result.SchemaVersion != jsonSchemaVersion || result.Link.ID != id || !result.InterfaceVerified {
		return linkStatusResponse{}, nil, 1
	}
	return result, nil, 0
}

// A nil counter is unmeasured, including IPsec SA data where no exact-owner
// kernel counter reader exists. A zero counter is a valid verified value.
func menuStatusTraffic(status linkStatusResponse) (rx, tx *uint64, unit string, handshake *int64) {
	switch {
	case status.GREState != nil:
		a, b := status.GREState.RXPackets, status.GREState.TXPackets
		return &a, &b, "packets", nil
	case status.IPIPState != nil:
		a, b := status.IPIPState.RXPackets, status.IPIPState.TXPackets
		return &a, &b, "packets", nil
	case status.WSSState != nil:
		a, b, last := status.WSSState.RXBytes, status.WSSState.TXBytes, status.WSSState.LastHandshakeUnix
		return &a, &b, "bytes", &last
	case status.WireGuardState != nil:
		a, b, last := status.WireGuardState.RXBytes, status.WireGuardState.TXBytes, status.WireGuardState.LatestHandshakeUnix
		return &a, &b, "bytes", &last
	case status.IPsecState != nil:
		return status.IPsecState.RXPackets, status.IPsecState.TXPackets, status.IPsecState.CounterUnit, nil
	}
	return nil, nil, "", nil
}

func menuCheckOneConnection(id domain.LinkID, out, errOut io.Writer, options *runtimeOptions) int {
	var raw bytes.Buffer
	code := linkDiagnoseCommand([]string{"diagnose", string(id), "--json"}, &raw, io.Discard, options)
	menuSection(out, "Connectivity / five-ping check")
	if code != 0 {
		menuPublicDiagnosticFailure(out, raw.Bytes())
		return code
	}
	var result diagnostics.Report
	if err := json.Unmarshal(raw.Bytes(), &result); err != nil || result.LinkID != id || result.SchemaVersion != jsonSchemaVersion {
		menuNotice(out, "WARNING", "Diagnostic response could not be verified; no connectivity result is claimed.")
		return 1
	}
	menuHealthLine(out, "Local interface", "OK", "Identity verified (not a peer connection test)")
	status, _, statusCode := menuReadVerifiedStatus(id, options)
	var rx, tx *uint64
	var handshake *int64
	var unit string
	if statusCode == 0 {
		rx, tx, unit, handshake = menuStatusTraffic(status)
	}
	menuHealthMeasurements(out, result.MTU, result.Quality, rx, tx, unit, handshake)
	if result.MTU.Mode == "not_measured" {
		menuHealthLine(out, "Path MTU", "INFO", "Not measured for WSS; this check used five private ICMP probes")
	}
	if statusCode != 0 {
		menuNotice(out, "WARNING", "Cumulative counters could not be checked separately; ping results are independent.")
	}
	if statusCode == 0 && status.IPsecState != nil {
		menuField(out, "IPsec SA", fmt.Sprintf("observed=%t (not proof of peer traffic)", status.IPsecState.SecurityAssociationPresent))
	}
	menuHealthNext(out, result.Quality)
	return 0
}

// A compact human view of the existing versioned, read-only all-Link
// report. It never probes independently and never treats saved State,
// local interface existence or missing ICMP as proof of connectivity.
func menuAllCheckResult(check healthLinkCheck) (string, string) {
	switch {
	case check.Status == "observed" && check.ReasonCode == "link_peer_replied" &&
		check.Observed != nil &&
		check.Observed.Quality.Status == diagnostics.QualityMeasured &&
		check.Observed.Quality.Reachable &&
		check.Observed.Quality.PacketsReceived > 0:
		if check.Observed.Quality.PacketsReceived < check.Observed.Quality.PacketsSent {
			return "Packet loss", "WARNING" // some replies, but also measured loss
		}
		return "Replied", "OK"
	case check.Status == "blocked":
		return "Blocked", "WARNING"
	case check.ReasonCode == "link_probe_no_reply" && check.Observed != nil &&
		check.Observed.Quality.Status == diagnostics.QualityMeasured:
		return "No reply", "WARNING" // ICMP may be filtered; not proven down
	case check.ReasonCode == "diagnostic_interrupted":
		return "Interrupted", "UNKNOWN"
	default:
		return "Unknown", "UNKNOWN"
	}
}

func menuAllCheckPing(check healthLinkCheck) string {
	if check.Observed == nil || check.Observed.Quality.PacketsSent == 0 {
		return "-"
	}
	quality := check.Observed.Quality
	return fmt.Sprintf("%d/%d", quality.PacketsReceived, quality.PacketsSent)
}

func menuAllCheckTable(out io.Writer, result healthCenterResponse) {
	// Avoid terminal-induced wraps when the window is narrow or a future
	// address family is wider than IPv4. Never truncate exact peer addresses.
	cols := menuColumns(out)
	narrow := cols > 0 && cols < 68
	for _, check := range result.Checks {
		kind := string(check.Link.Backend) + "/" + string(check.Link.Encapsulation)
		if len(kind) > 16 || len(check.Link.PeerAddress) > 20 {
			narrow = true
		}
	}
	if !narrow {
		fmt.Fprintln(out, "  #   Tunnel           Peer Link IP         Ping     Result")
		fmt.Fprintln(out, "  "+strings.Repeat("-", 63))
	}
	for i, check := range result.Checks {
		kind := safeMenuText(string(check.Link.Backend) + "/" + string(check.Link.Encapsulation))
		peer := safeMenuText(check.Link.PeerAddress)
		ping := menuAllCheckPing(check)
		label, role := menuAllCheckResult(check)
		resultLabel := menuPaint(out, menuStatusRole(role), label)
		if narrow {
			// Keep the peer token intact. Longer addresses need their own
			// row rather than relying on the terminal's accidental wrap.
			linkLine := fmt.Sprintf("  %d  %s  -> %s", i+1, kind, peer)
			if cols > 0 && len(linkLine) > cols {
				fmt.Fprintf(out, "  %d  %s\n", i+1, kind)
				prefix := "  -> "
				if len(prefix)+len(peer) > cols {
					prefix = ""
				}
				fmt.Fprintf(out, "%s%s\n", prefix, peer)
			} else {
				fmt.Fprintln(out, linkLine)
			}
			metrics := fmt.Sprintf("     Ping: %-7s Result: %s", ping, label)
			if cols > 0 && len(metrics) > cols {
				fmt.Fprintf(out, "     Ping: %s\n", ping)
				fmt.Fprintf(out, "     Result: %s\n", resultLabel)
			} else {
				fmt.Fprintf(out, "     Ping: %-7s Result: %s\n", ping, resultLabel)
			}
		} else {
			fmt.Fprintf(out, "  %-3d %-16s %-20s %-8s %s\n", i+1, kind, peer, ping, resultLabel)
		}
	}
	var summary string
	if narrow {
		fmt.Fprintf(out, "\nLinks in snapshot: %d\n", result.Total)
		summary = fmt.Sprintf("Peer replied: %d | blocked: %d | unknown: %d",
			result.Observed, result.Blocked, result.Unknown)
	} else {
		fmt.Fprintln(out)
		summary = fmt.Sprintf("Links in snapshot: %d | peer replied: %d | blocked: %d | unknown: %d",
			result.Total, result.Observed, result.Blocked, result.Unknown)
	}
	if result.Outcome != "complete" {
		summary += " | run: " + safeMenuText(result.Outcome)
	}
	if narrow || (cols > 0 && len(summary) > cols) {
		menuProse(out, summary)
	} else {
		fmt.Fprintln(out, summary)
	}
	menuProse(out, "Results are from this brief check only. No ICMP reply does not prove that a tunnel is disconnected.")

	// Keep failures actionable without expanding every healthy row into
	// lengthy latency/MTU/counter blocks. Per-Link Test connectivity
	// remains the detailed observational view.
	hasProblems := false
	for _, check := range result.Checks {
		if label, _ := menuAllCheckResult(check); label != "Replied" {
			hasProblems = true
			break
		}
	}
	if hasProblems {
		menuSection(out, "Checks needing attention")
		for i, check := range result.Checks {
			if label, _ := menuAllCheckResult(check); label == "Replied" {
				continue
			}
			label, _ := menuAllCheckResult(check)
			reason := safeMenuText(check.ReasonCode)
			reasonLine := fmt.Sprintf("  %d  %s (%s)", i+1, label, reason)
			if cols > 0 && len(reasonLine) > cols {
				fmt.Fprintf(out, "  %d  %s\n", i+1, label)
				if len("     Reason: ")+len(reason) > cols {
					fmt.Fprintf(out, "     Reason:\n     %s\n", reason)
				} else {
					fmt.Fprintf(out, "     Reason: %s\n", reason)
				}
			} else {
				fmt.Fprintln(out, reasonLine)
			}
			if check.NextStep != "" {
				if menuCopyable(check.NextStep) {
					menuCopyLine(out, "Next", check.NextStep)
				} else {
					menuProse(out, "Next: "+check.NextStep)
				}
			}
		}
		menuProse(out, "For MTU, latency, counters and detailed diagnosis, select one tunnel in Test connectivity.")
	}
}

func menuCheckAllConnections(out, errOut io.Writer, options *runtimeOptions) int {
	var raw bytes.Buffer
	code := linkDiagnoseCommand([]string{"diagnose", "--all", "--json"}, &raw, io.Discard, options)
	var result healthCenterResponse
	menuSection(out, "Connectivity / all saved tunnels")
	if err := json.Unmarshal(raw.Bytes(), &result); err != nil ||
		result.SchemaVersion != jsonSchemaVersion || result.Operation != "link_diagnose_all" ||
		result.Total != len(result.Checks) ||
		result.Total != result.Observed+result.Blocked+result.Unknown {
		menuPublicDiagnosticFailure(out, raw.Bytes())
		return codeOrFailure(code)
	}
	if result.Total == 0 {
		menuNotice(out, "INFO", "No saved tunnels to check.")
		return code
	}
	menuAllCheckTable(out, result)
	if result.Blocked+result.Unknown > 0 {
		menuNotice(out, "WARNING", "Some links remain unknown, blocked or without peer replies.")
	}
	return code
}

func codeOrFailure(code int) int {
	if code == 0 {
		return 1
	}
	return code
}

func menuShowLocalStatus(id domain.LinkID, out, errOut io.Writer, options *runtimeOptions) int {
	result, raw, code := menuReadVerifiedStatus(id, options)
	menuSection(out, "Local status / not a peer ping")
	if code != 0 {
		menuPublicDiagnosticFailure(out, raw)
		return code
	}
	menuHealthLine(out, "Interface", "OK", "Local interface verified")
	if result.WSSState != nil {
		if result.WSSState.WSSHelperActive {
			menuHealthLine(out, "WSS helper", "OK", "Managed helper active")
		} else {
			menuHealthLine(out, "WSS helper", "WARNING", "Helper not observed as active")
		}
		if result.WSSState.WGIngressGuardActive {
			menuHealthLine(out, "WG ingress", "OK", "Scoped UDP protection active")
		} else {
			menuHealthLine(out, "WG ingress", "WARNING", "Scoped UDP guard not observed")
		}
	}
	menuHealthLine(out, "Peer traffic", "UNKNOWN", "connectivity not measured; use Check connection for 5 pings")
	rx, tx, unit, handshake := menuStatusTraffic(result)
	if rx != nil && tx != nil && unit != "" {
		menuField(out, "Interface RX/TX", fmt.Sprintf("%d / %d %s (cumulative)", *rx, *tx, unit))
	} else {
		menuField(out, "Interface RX/TX", "not available from this backend")
	}
	if handshake != nil {
		if *handshake > 0 {
			menuField(out, "Last handshake", time.Unix(*handshake, 0).UTC().Format("2006-01-02 15:04 UTC")+" (historical)")
		} else {
			menuHealthLine(out, "WireGuard", "UNKNOWN", "No handshake observed")
		}
	}
	if result.IPsecState != nil {
		menuField(out, "IPsec SA", fmt.Sprintf("observed=%t (not proof of peer traffic)", result.IPsecState.SecurityAssociationPresent))
	}
	return 0
}
