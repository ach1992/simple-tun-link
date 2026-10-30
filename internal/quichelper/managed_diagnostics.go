package quichelper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/hostidentity"
)

// HelperDiagnostics separates current owned process evidence from historical
// helper events. Neither a running process nor an authenticated carrier event
// proves WireGuard traffic or a working private Link route.
type HelperDiagnostics struct {
	GuardPresent     bool          `json:"guard_present"`
	HelperPresent    bool          `json:"helper_present"`
	HelperLoaded     bool          `json:"helper_loaded"`
	GuardObserved    bool          `json:"guard_observed"`
	HelperObserved   bool          `json:"helper_observed"`
	State            string        `json:"state"`
	Authentication   string        `json:"authentication"`
	Handshake        string        `json:"handshake"`
	Unit             string        `json:"unit,omitempty"`
	InvocationID     string        `json:"invocation_id,omitempty"`
	PID              int           `json:"pid,omitempty"`
	ProcessStartTime uint64        `json:"process_start_time,omitempty"`
	RestartCount     uint64        `json:"restart_count"`
	ExitResult       string        `json:"exit_result,omitempty"`
	ExitCode         uint64        `json:"exit_code,omitempty"`
	ExitStatus       uint64        `json:"exit_status,omitempty"`
	JournalState     string        `json:"journal_state"`
	MaterialState    string        `json:"material_state"`
	Events           []HelperEvent `json:"events,omitempty"`
}

type HelperEvent struct {
	TimestampUSec uint64 `json:"timestamp_usec"`
	Level         string `json:"level"`
	Event         string `json:"event"`
	ReasonCode    string `json:"reason_code,omitempty"`
	NextStep      string `json:"next_step,omitempty"`
}

// Diagnose is strictly read-only and obtains the committed owner from the
// canonical Store. It never loads uncommitted source-only receipts as owner,
// starts a service or treats journal text as management authority.
func (h *Host) Diagnose(ctx context.Context, link domain.Link) (HelperDiagnostics, error) {
	result := HelperDiagnostics{State: "unknown", Authentication: "not_observed", Handshake: "not_observed", JournalState: "not_observed"}
	if h == nil || h.store == nil || ctx == nil {
		return result, fmt.Errorf("managed QUIC diagnostic runtime unavailable")
	}
	snapshot, err := h.store.Load(ctx)
	if err != nil {
		return result, managedError(link, "diagnose", "state_unavailable", "protected Link State could not be read", err, false)
	}
	record, ok := snapshot.Find(link.ID)
	if !ok || record.Desired != link || record.QUICGeneration.Validate(link) != nil {
		return result, managedError(link, "diagnose", "unprovisioned", "QUIC Link has no committed managed generation; pending operations remain quarantined", nil, false)
	}
	ctx, err = core.WithQUICOrigin(ctx, record.QUICGeneration.OriginNonce)
	if err != nil {
		return result, err
	}
	ctx = core.WithQUICGeneration(ctx, record.QUICGeneration)
	ctx, release, err := h.Begin(ctx, link, &record.QUICGeneration)
	if err != nil {
		return result, err
	}
	defer release()
	scope, _ := ctx.Value(managedScopeKey{}).(*managedScope)
	result.MaterialState = "verified"
	if err := scope.material.VerifyForLaunch(ctx); err != nil {
		result.MaterialState = "not_currently_launchable"
	}
	result.GuardPresent, err = h.GuardPresent(ctx, link)
	if err != nil {
		return result, managedError(link, "diagnose", "guard_unverified", "QUIC ingress guard identity could not be verified", err, false)
	}
	result.GuardObserved = true
	obs, err := h.inspect(ctx, link)
	if err != nil {
		return result, err
	}
	result.HelperObserved, result.HelperLoaded, result.HelperPresent = true, obs.Loaded, obs.Active
	spec, _ := h.spec(ctx, link)
	result.Unit = spec.Name
	if !obs.Loaded {
		result.State = "absent"
		result.JournalState = "no_current_invocation"
		return result, nil
	}
	result.State = obs.Values["ActiveState"]
	result.InvocationID = obs.Values["InvocationID"]
	result.RestartCount, _ = canonicalUint(obs.Values["NRestarts"])
	result.ExitCode, _ = canonicalUint(obs.Values["ExecMainCode"])
	result.ExitStatus, _ = canonicalUint(obs.Values["ExecMainStatus"])
	result.ExitResult = safeUnitResult(obs.Values["Result"])
	if obs.Process != nil {
		result.PID, result.ProcessStartTime = obs.Process.Observation.PID, obs.Process.Observation.StartTime
	}
	if !canonicalHex(result.InvocationID, 32) || strings.Trim(result.InvocationID, "0") == "" {
		result.JournalState = "no_current_invocation"
		return result, nil
	}
	events, err := h.ops.events(ctx, spec.Name, result.InvocationID, obs.Host.BootID)
	if err != nil {
		result.JournalState = "unavailable"
		return result, managedError(link, "diagnose", "journal_unavailable", "owned QUIC process state was inspected, but bounded attributed helper events are unavailable", err, false)
	}
	result.JournalState, result.Events = "observed", events
	for _, event := range events {
		if event.Event == "transport_connected" || event.Event == "peer_connected" {
			result.Authentication, result.Handshake = "observed", "observed"
		}
	}
	return result, nil
}

func safeUnitResult(value string) string {
	switch value {
	case "success", "resources", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "protocol", "oom-kill":
		return value
	default:
		return "unknown"
	}
}

// helperJournalArgs preserves exact attribution while using journalctl's
// 32-character ID128 boot selector. The trusted kernel source supplies a dashed
// UUID; passing that spelling to --boot fails even on otherwise supported hosts.
// Never reinterpret an invalid identity as an offset or the current boot.
func helperJournalArgs(unit, invocation, boot string) ([]string, error) {
	bootHex := boot
	if hostidentity.ValidBootID(boot) {
		bootHex = strings.ReplaceAll(boot, "-", "")
	}
	if !safeArgument(unit) || !canonicalHex(invocation, 32) ||
		!canonicalHex(bootHex, 32) || strings.Trim(bootHex, "0") == "" {
		return nil, fmt.Errorf("invalid QUIC journal attribution")
	}
	return []string{"--system", "--no-pager", "--quiet", "--output=json", "--lines=64",
		"--boot=" + bootHex, "_SYSTEMD_UNIT=" + unit, "_SYSTEMD_INVOCATION_ID=" + invocation, "_TRANSPORT=stdout"}, nil
}

func readHelperEvents(ctx context.Context, unit, invocation, boot string) ([]HelperEvent, error) {
	args, err := helperJournalArgs(unit, invocation, boot)
	if err != nil {
		return nil, err
	}
	raw, err := managerCommand(ctx, "journalctl", args...)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return parseHelperEvents(raw, unit, invocation, boot)
}

func parseHelperEvents(raw []byte, unit, invocation, boot string) ([]HelperEvent, error) {
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("QUIC journal readback exceeds bound")
	}
	if len(raw) != 0 && raw[len(raw)-1] != '\n' {
		return nil, fmt.Errorf("QUIC journal readback is incomplete")
	}
	var events []HelperEvent
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		if len(events) >= 64 {
			return nil, fmt.Errorf("QUIC journal record bound exceeded")
		}
		row, err := uniqueEventObject(scanner.Bytes())
		if err != nil {
			return nil, err
		}
		if eventString(row, "_TRANSPORT") != "stdout" || eventString(row, "_SYSTEMD_UNIT") != unit || eventString(row, "_SYSTEMD_INVOCATION_ID") != invocation ||
			eventString(row, "_BOOT_ID") != strings.ReplaceAll(boot, "-", "") {
			return nil, fmt.Errorf("QUIC journal attribution differs")
		}
		timestamp, err := canonicalUint(eventString(row, "__REALTIME_TIMESTAMP"))
		if err != nil || timestamp == 0 {
			return nil, fmt.Errorf("QUIC journal timestamp is unverified")
		}
		message := eventString(row, "MESSAGE")
		payload, err := uniqueEventObject([]byte(message))
		if err != nil {
			events = append(events, HelperEvent{TimestampUSec: timestamp, Level: "unknown", Event: "unrecognized_output"})
			continue
		}
		event := classifyHelperEvent(payload)
		event.TimestampUSec = timestamp
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("QUIC journal stream is incomplete")
	}
	return events, nil
}

// Only known messages and authored classifications cross this boundary.
// Even an attributed journal's MESSAGE/error/id/addr/URI are untrusted text.
// Upstream source: HyNetwork/hysteria app/v2.13.0, commit
// ca8fbd874fd6ca82413948de6dc5924405e103e1 app/cmd/{root,client,server}.go;
// password authentication returns the constant "user", never its password.
func classifyHelperEvent(fields map[string]json.RawMessage) HelperEvent {
	e := HelperEvent{Level: eventString(fields, "level"), Event: "unrecognized_output"}
	switch e.Level {
	case "info", "warn", "error", "fatal":
	default:
		e.Level = "unknown"
	}
	switch eventString(fields, "msg") {
	case "client mode", "server mode":
		e.Event = "helper_starting"
	case "server up and running":
		e.Event = "listener_ready"
	case "UDP forwarding listening":
		e.Event = "forwarder_ready"
	case "connected to server":
		e.Event = "transport_connected"
	case "client connected":
		e.Event = "peer_connected"
	case "client disconnected":
		e.Event = "peer_disconnected"
	case "received signal, shutting down gracefully", "server stopped":
		e.Event = "helper_stopping"
	case "failed to read client config", "failed to parse client config", "failed to load client config",
		"failed to read server config", "failed to parse server config", "failed to load server config":
		e.Event, e.ReasonCode, e.NextStep = "configuration_failed", "quic_configuration_failed", "verify the original protected material; do not overwrite it"
	case "failed to initialize client", "failed to initialize server", "failed to serve":
		e.Event = "initialization_failed"
	case "UDP forwarding error", "UDP error":
		e.Event = "udp_forwarding_failed"
	}
	errText := eventString(fields, "error")
	if e.Event == "initialization_failed" || e.Event == "udp_forwarding_failed" || e.Event == "peer_disconnected" {
		switch {
		case strings.Contains(errText, "authentication error, HTTP status code: 404"):
			e.ReasonCode, e.NextStep = "quic_authorization_rejected", "compare the original paired endpoint credentials; do not replace an active Link's identity"
		case strings.Contains(errText, "certificate") && (strings.Contains(errText, "x509:") || strings.Contains(errText, "tls:")):
			e.ReasonCode, e.NextStep = "quic_tls_verification_failed", "verify the paired CA, TLS server name, certificate lifetime and system time"
		case strings.Contains(errText, "address already in use"):
			e.ReasonCode, e.NextStep = "quic_udp_port_occupied", "inspect the selected UDP socket owner before changing this Link"
		case errText == "rejected":
			e.ReasonCode, e.NextStep = "quic_forwarding_rejected", "verify the original fixed loopback WireGuard destination and carrier configuration"
		case strings.Contains(errText, "timeout") || strings.Contains(errText, "deadline exceeded"):
			e.ReasonCode, e.NextStep = "quic_transport_timeout", "check the selected physical UDP path and peer availability"
		case errText != "":
			e.ReasonCode, e.NextStep = "quic_helper_failure", "inspect the selected helper exit state, peer availability and fixed protected configuration"
		}
	}
	return e
}

func eventString(fields map[string]json.RawMessage, key string) string {
	var value string
	if json.Unmarshal(fields[key], &value) != nil {
		return ""
	}
	return value
}

func uniqueEventObject(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, fmt.Errorf("invalid bounded QUIC event")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("invalid QUIC event object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("incomplete QUIC event")
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid QUIC event key")
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("ambiguous QUIC event key")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid QUIC event value")
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("incomplete QUIC event object")
	}
	return fields, nil
}
