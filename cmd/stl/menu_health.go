package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// All human health views consume existing read-only, versioned CLI reports.
// They neither implement their own probes nor change machine CLI/JSON output.
func menuHealthLine(out io.Writer, label, kind, value string) {
	role := menuYellow
	switch kind {
	case "OK":
		role = menuGreen
	case "INFO":
		role = menuBlue
	}
	fmt.Fprintf(out, "  %-16s %s  %s\n", label,
		menuPaint(out, role, "["+kind+"]"), value)
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
		fmt.Fprintln(out, wrapTerminalGuidance(failure.Error.NextStep, 68))
		return
	}
	menuNotice(out, "WARNING", "Connection check unavailable. Inspect local status and prerequisites; no changes made.")
}

type menuDiagnosticReport struct {
	diagnostics.Report
	State struct {
		RXPackets           *uint64 `json:"rx_packets"`
		TXPackets           *uint64 `json:"tx_packets"`
		RXBytes             *uint64 `json:"rx_bytes"`
		TXBytes             *uint64 `json:"tx_bytes"`
		LatestHandshakeUnix *int64  `json:"latest_handshake_unix"`
	} `json:"state"`
}

func menuCheckOneConnection(id domain.LinkID, out, errOut io.Writer, options *runtimeOptions) int {
	var raw bytes.Buffer
	code := linkDiagnoseCommand([]string{"diagnose", string(id), "--json"}, &raw, io.Discard, options)
	menuSection(out, "Connectivity / five-ping check")
	if code != 0 {
		menuPublicDiagnosticFailure(out, raw.Bytes())
		return code
	}
	var result menuDiagnosticReport
	if err := json.Unmarshal(raw.Bytes(), &result); err != nil || result.LinkID != id || result.SchemaVersion != jsonSchemaVersion {
		menuNotice(out, "WARNING", "Diagnostic response could not be verified; no connectivity result is claimed.")
		return 1
	}
	menuHealthLine(out, "Local interface", "OK", "Identity verified (not a peer connection test)")
	rx, tx, unit := result.State.RXPackets, result.State.TXPackets, "packets"
	if result.State.RXBytes != nil && result.State.TXBytes != nil {
		rx, tx, unit = result.State.RXBytes, result.State.TXBytes, "bytes"
	}
	menuHealthMeasurements(out, result.MTU, result.Quality, rx, tx, unit, result.State.LatestHandshakeUnix)
	menuHealthNext(out, result.Quality)
	return 0
}

func menuCheckAllConnections(out, errOut io.Writer, options *runtimeOptions) int {
	var raw bytes.Buffer
	code := linkDiagnoseCommand([]string{"diagnose", "--all", "--json"}, &raw, io.Discard, options)
	var result healthCenterResponse
	menuSection(out, "Connectivity / all saved tunnels")
	if err := json.Unmarshal(raw.Bytes(), &result); err != nil || result.SchemaVersion != jsonSchemaVersion || result.Operation != "link_diagnose_all" {
		menuPublicDiagnosticFailure(out, raw.Bytes())
		return codeOrFailure(code)
	}
	if result.Total == 0 {
		menuNotice(out, "INFO", "No saved tunnels to check.")
		return code
	}
	for i, check := range result.Checks {
		menuSection(out, fmt.Sprintf("Tunnel %d / %s %s", i+1, check.Link.Backend, check.Link.Encapsulation))
		menuField(out, "Tunnel IPs", check.Link.LocalAddress+" -> "+check.Link.PeerAddress)
		if check.Observed == nil {
			menuHealthLine(out, "Ping", "UNKNOWN", "Not measured ("+check.Status+")")
			menuField(out, "Reason", check.ReasonCode)
			menuField(out, "Next", check.NextStep)
			continue
		}
		menuHealthLine(out, "Local interface", "OK", "Identity verified (peer tested separately)")
		handshake := check.Observed.LatestHandshakeUnix
		if handshake == nil && check.Link.Backend == domain.BackendWireGuard {
			missing := int64(0) // all-Link JSON omits a zero handshake; show it as unknown
			handshake = &missing
		}
		menuHealthMeasurements(out, check.Observed.MTU, check.Observed.Quality,
			check.Observed.RX, check.Observed.TX, check.Observed.CounterUnit, handshake)
		menuHealthNext(out, check.Observed.Quality)
	}
	fmt.Fprintf(out, "\nLinks in snapshot: %d | peer replied: %d | blocked: %d | unknown: %d\n",
		result.Total, result.Observed, result.Blocked, result.Unknown)
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
	var raw bytes.Buffer
	code := linkReadCommand([]string{"status", string(id), "--json"}, &raw, io.Discard, options)
	menuSection(out, "Local status / not a peer ping")
	if code != 0 {
		menuPublicDiagnosticFailure(out, raw.Bytes())
		return code
	}
	var result linkStatusResponse
	if err := json.Unmarshal(raw.Bytes(), &result); err != nil || result.Link.ID != id || result.SchemaVersion != jsonSchemaVersion || !result.InterfaceVerified {
		menuNotice(out, "WARNING", "Local status could not be interpreted; no connection claim made.")
		return 1
	}
	menuHealthLine(out, "Interface", "OK", "Local interface verified")
	menuHealthLine(out, "Peer traffic", "UNKNOWN", "connectivity not measured; use Check connection for 5 pings")
	var rx, tx uint64
	unit := "packets"
	have := false
	switch {
	case result.GREState != nil:
		rx, tx, have = result.GREState.RXPackets, result.GREState.TXPackets, true
	case result.IPIPState != nil:
		rx, tx, have = result.IPIPState.RXPackets, result.IPIPState.TXPackets, true
	case result.WireGuardState != nil:
		rx, tx, unit, have = result.WireGuardState.RXBytes, result.WireGuardState.TXBytes, "bytes", true
		v := result.WireGuardState.LatestHandshakeUnix
		if v > 0 {
			menuField(out, "Last handshake", time.Unix(v, 0).UTC().Format("2006-01-02 15:04 UTC")+" (historical)")
		} else {
			menuHealthLine(out, "WireGuard", "UNKNOWN", "No handshake observed")
		}
	case result.IPsecState != nil:
		if result.IPsecState.SecurityAssociationPresent {
			menuHealthLine(out, "IPsec SA", "INFO", "Observed; not proof of peer IP traffic")
		} else {
			menuHealthLine(out, "IPsec SA", "UNKNOWN", "Not observed")
		}
	}
	if have {
		menuField(out, "Interface RX/TX", fmt.Sprintf("%d / %d %s (cumulative)", rx, tx, unit))
	}
	return 0
}
