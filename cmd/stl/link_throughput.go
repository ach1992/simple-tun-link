package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/maintenance"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const (
	defaultThroughputSeconds = 3
	maxThroughputSeconds     = 10

	throughputVersionBudget     = 3 * time.Second
	throughputBenchmarkOverhead = 6 * time.Second
	// Allow for the installation/Link locks, two state snapshots and exact
	// route verification outside the already bounded diagnostic phase.
	throughputPreparationReserve = 5 * time.Second
	// Parsing and reporting must not race the parent immediately after a
	// benchmark that finishes within its own bounded subprocess allowance.
	throughputCompletionReserve = 2 * time.Second
)

// A slow but in-budget 35-second diagnostic must not consume the version
// check or the explicitly requested benchmark's execution allowance.
// This increases only the outer cancellation budget: no extra probes,
// retries, iperf3 traffic or on-wire duration are authorized.
func throughputOperationBudget(seconds int) time.Duration {
	return diagnoseOperationTimeout + throughputPreparationReserve +
		throughputVersionBudget + time.Duration(seconds)*time.Second +
		throughputBenchmarkOverhead + throughputCompletionReserve
}

// iperf3 3.10 exposed --bind-dev but could leave TCP *data* sockets
// unbound (esnet/iperf #1153, fixed in 3.11). A successful run on
// 3.10 does not prove that high-rate traffic stayed on the chosen Link.
// Only this known-safe 3.x release family is accepted.
var iperf3TCPBindVersion = regexp.MustCompile(`^iperf(?:3)?[ \t]+(?:version[ \t]+)?3\.([0-9]{1,3})(?:\.([0-9]{1,3}))?(?:[ \t(]|$)`)

func knownSafeIperf3TCPDeviceBinding(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 2048 || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return false
	}
	// Trust only the first line, not a later injected banner/help string.
	first := string(raw)
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if len(first) > 240 || strings.ContainsRune(first, '\r') {
		return false
	}
	match := iperf3TCPBindVersion.FindStringSubmatch(first)
	if len(match) != 3 {
		return false
	}
	minor, err := strconv.Atoi(match[1])
	return err == nil && minor >= 11
}

type linkThroughputResult struct {
	SchemaVersion int            `json:"schema_version"`
	Operation     string         `json:"operation"`
	LinkID        domain.LinkID  `json:"link_id"`
	Backend       domain.Backend `json:"backend"`
	Protocol      string         `json:"protocol"`
	Direction     string         `json:"direction"`
	Seconds       int            `json:"seconds"`
	SentBytes     uint64         `json:"sent_bytes"`
	ReceivedBytes uint64         `json:"received_bytes"`
	SentMbps      float64        `json:"sent_mbps"`
	ReceivedMbps  float64        `json:"received_mbps"`
}

// Exact CLI grammar requires a repeated Link-ID confirmation before any
// traffic. No automatic launch from health, create, restore or the menu.
func parseThroughputArgs(args []string) (domain.LinkID, int, bool, bool) {
	isJSON := len(args) > 0 && args[len(args)-1] == "--json"
	if len(args) < 4 || args[0] != "throughput" || args[2] != "--confirm" || args[1] != args[3] {
		return "", 0, isJSON, false
	}
	id := domain.LinkID(args[1])
	if id.Validate() != nil {
		return "", 0, isJSON, false
	}
	seconds, rest := defaultThroughputSeconds, args[4:]
	if len(rest) >= 2 && rest[0] == "--seconds" {
		n, err := strconv.Atoi(rest[1])
		if err != nil || n < 1 || n > maxThroughputSeconds {
			return "", 0, isJSON, false
		}
		seconds, rest = n, rest[2:]
	}
	if len(rest) != 0 && !(len(rest) == 1 && rest[0] == "--json") {
		return "", 0, isJSON, false
	}
	return id, seconds, isJSON, true
}

func throughputMeasuredInterface(m linkDiagnostic) string {
	switch r := m.report.(type) {
	case diagnostics.GREReport:
		return r.State.Interface
	case diagnostics.IPIPReport:
		return r.State.Interface
	case diagnostics.WireGuardReport:
		return r.State.Interface
	case diagnostics.IPsecReport:
		return r.State.Interface
	case diagnostics.Report:
		// The only generic Report on this path is from exact-owner WSS
		// diagnostics after scoped helper/guard/kernel WG + private
		// interface/route preflight. No unverified Native WG inference.
		name, err := wgbackend.InterfaceName(r.LinkID)
		if err == nil {
			return name
		}
		return ""
	default:
		return ""
	}
}

// Only accept canonical interface strings inside iperf3's Linux
// SO_BINDTODEVICE syntax. No interface or peer is accepted from argv.
func safeThroughputInterface(name string) bool {
	if name == "" || len(name) > 15 || name[0] == '-' || strings.ContainsAny(name, " \t\n\r\x00%/:=") {
		return false
	}
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func throughputFailure(out, errOut io.Writer, asJSON bool, code stlerr.Code, reason, summary, next string) int {
	e := stlerr.New(code, "link_throughput", "", "", summary)
	e.ReasonCode, e.NextStep = reason, next
	return readCommandPublicError(out, errOut, asJSON, e)
}

type iperfSummary struct {
	Bytes   *uint64  `json:"bytes"`
	Bitrate *float64 `json:"bits_per_second"`
	Seconds *float64 `json:"seconds"`
}

// Return a **bounded numerical projection**, never raw iperf3 JSON,
// supplied server metadata, public underlay, stderr or process errors.
func parseThroughputOutput(raw []byte, id domain.LinkID, backend domain.Backend, seconds int) (linkThroughputResult, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return linkThroughputResult{}, fmt.Errorf("unverified throughput output length")
	}
	var r struct {
		Error string `json:"error"`
		End   struct {
			Sent     *iperfSummary `json:"sum_sent"`
			Received *iperfSummary `json:"sum_received"`
		} `json:"end"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Error != "" || r.End.Sent == nil || r.End.Received == nil {
		return linkThroughputResult{}, fmt.Errorf("unverified iperf completion")
	}
	for _, item := range []*iperfSummary{r.End.Sent, r.End.Received} {
		if item.Bytes == nil || item.Bitrate == nil || item.Seconds == nil ||
			math.IsNaN(*item.Bitrate) || math.IsInf(*item.Bitrate, 0) ||
			*item.Bitrate < 0 || *item.Bitrate > 100e12 ||
			math.IsNaN(*item.Seconds) || math.IsInf(*item.Seconds, 0) ||
			*item.Seconds <= 0 || *item.Seconds > float64(seconds)+5 {
			return linkThroughputResult{}, fmt.Errorf("incomplete or invalid iperf metrics")
		}
	}
	return linkThroughputResult{
		SchemaVersion: jsonSchemaVersion, Operation: "link_throughput",
		LinkID: id, Backend: backend, Protocol: "tcp", Direction: "local_to_peer",
		Seconds: seconds, SentBytes: *r.End.Sent.Bytes, ReceivedBytes: *r.End.Received.Bytes,
		SentMbps: *r.End.Sent.Bitrate / 1e6, ReceivedMbps: *r.End.Received.Bitrate / 1e6,
	}, nil
}

// Optional throughput is deliberately traffic-generating but requires
// specific operator opt-in, prior Link identity/reachability verification,
// route-to-peer ownership, and a TCP client *bound to the Link device*.
// It neither configures a server nor permits arbitrary target/port choices.
func linkThroughputCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	return linkThroughputWithContext(context.Background(), args, out, errOut, opts)
}

// This context seam allows deterministic cancellation tests of the actual
// opt-in command. Production always uses its own bounded background context.
func linkThroughputWithContext(parent context.Context, args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	id, seconds, asJSON, ok := parseThroughputArgs(args)
	if !ok {
		return readCommandError(out, errOut, asJSON, stlerr.CodeInvalid, "link_throughput",
			"usage: stl link throughput <link-id> --confirm <link-id> [--seconds <1..10>] [--json]")
	}
	ctx, cancel := context.WithTimeout(parent, throughputOperationBudget(seconds))
	defer cancel()

	root := state.DefaultRoot
	if opts != nil {
		root = opts.stateRoot
	}
	if root == "" {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeState,
			"throughput_state_unavailable", "local desired state unavailable", "Repair local state access; no traffic was attempted.")
	}
	// Use the same order and exact claim as Engine: installation's shared
	// maintenance gate first (production default root), then the per-Link
	// lock. Holding it through the short iperf run prevents STL-driven
	// Remove/Ensure/restore from replacing this Link mid-transmission.
	if root == state.DefaultRoot {
		unlockMaintenance, err := maintenance.NewInstalledGate().Acquire(ctx)
		if err != nil {
			return throughputFailure(out, errOut, asJSON, stlerr.CodeState,
				"throughput_maintenance_blocked", "installed runtime maintenance gate unavailable",
				"Recheck installation/maintenance and retry only after it is stable.")
		}
		defer unlockMaintenance()
	}
	unlockLink, err := state.NewLockManager(root).Acquire(ctx,
		[]domain.ResourceClaim{{Kind: "stl-link", Key: string(id)}})
	if err != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeState,
			"throughput_link_busy", "canonical Link lock unavailable",
			"Wait for the selected Link lifecycle operation to finish; no traffic was attempted.")
	}
	defer unlockLink()
	store := state.NewFileStore(root)
	snapshot, err := store.Load(ctx)
	if err != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeState,
			"throughput_state_unavailable", "cannot inspect committed Link", "Repair local state access; no traffic was attempted.")
	}
	record, exists := snapshot.Find(id)
	if !exists {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInvalid,
			"throughput_link_not_found", "Link is not committed locally", "Choose a committed Link; no traffic was attempted.")
	}
	if opts == nil {
		opts, err = productionRuntimeOptions()
		if err != nil {
			return throughputFailure(out, errOut, asJSON, stlerr.CodeState,
				"throughput_backend_unavailable", "cannot initialize observational runtime", "Inspect backend prerequisites; no traffic was attempted.")
		}
	}
	if record.Desired.Backend == domain.BackendIPsec && !hasOperationalIPsec(*opts) {
		return ipsecUnregisteredError(out, errOut, asJSON, "link_throughput", id)
	}
	runner := opts.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	// A completed but unexpectedly slow inspection must not quietly consume
	// the separate iperf3 budget. Keep the same 35-second per-Link limit
	// enforced by standalone and all-Link read-only diagnostics.
	diagnoseCtx, endDiagnose := context.WithTimeout(ctx, diagnoseOperationTimeout)
	measurement, err := inspectLinkDiagnostic(diagnoseCtx, record.Desired, *opts, 0)
	diagnoseErr := diagnoseCtx.Err()
	endDiagnose()
	if err != nil || diagnoseErr != nil || ctx.Err() != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInspect,
			"throughput_identity_unverified", "owned Link identity or quality observation unavailable",
			"Run link diagnose and resolve ownership/reachability problems before opting into throughput.")
	}
	iface := throughputMeasuredInterface(measurement)
	if !safeThroughputInterface(iface) ||
		measurement.quality.Status != diagnostics.QualityMeasured ||
		!measurement.quality.Reachable {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInspect,
			"throughput_peer_unverified", "the exact peer Link Address did not pass preflight",
			"Check the selected Link's peer response with link diagnose; no throughput test ran.")
	}
	route, err := (linux.RouteResolver{Runner: runner}).Resolve(ctx, record.Desired.Addresses.Peer.Addr())
	if err != nil || route.Source != record.Desired.Addresses.Local.Addr() ||
		route.Device != iface || route.Gateway.IsValid() || ctx.Err() != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInspect,
			"throughput_route_unverified", "peer Link Address route or source is not exact",
			"Repair the owned Link route; no throughput test ran.")
	}
	// A change to the local committed Link invalidates earlier preflight.
	// The iperf3 device bind additionally fails closed after route drift.
	now, err := store.Load(ctx)
	if err != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeState,
			"throughput_state_changed", "local Link snapshot unavailable after preflight",
			"Retry only after the Link lifecycle stabilizes.")
	}
	current, exists := now.Find(id)
	if !exists || current.Desired != record.Desired {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeConflict,
			"throughput_state_changed", "local Link changed during preflight",
			"Retry only after the Link lifecycle stabilizes.")
	}

	tool := opts.throughputRunner
	if tool == nil {
		tool = linux.ExecRunner{Timeout: time.Duration(seconds)*time.Second + throughputBenchmarkOverhead}
	}
	// A local, bounded version inspection MUST complete before the first
	// iperf3 client socket is opened. Older 3.x versions could bind the
	// control socket but silently leave the TCP data socket unbound.
	versionCtx, versionCancel := context.WithTimeout(ctx, throughputVersionBudget)
	versionOutput, versionErr := tool.RunBounded(versionCtx,
		linux.CaptureLimits{Stdout: 2048, Stderr: 1024}, "iperf3", "--version")
	versionTimedOut := versionCtx.Err() != nil
	versionCancel()
	compatible := versionErr == nil && !versionTimedOut && knownSafeIperf3TCPDeviceBinding(versionOutput.Stdout)
	clear(versionOutput.Stdout)
	clear(versionOutput.Stderr)
	if ctx.Err() != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInspect,
			"throughput_interrupted", "operation expired during throughput tool verification",
			"Recheck the Link and explicitly retry when host resources are available; no benchmark was started.")
	}
	if !compatible {
		code, reason := stlerr.CodeUnsupported, "throughput_tool_incompatible"
		next := "Use iperf3 >= 3.11 with reliable TCP --bind-dev support; do not use older or unverified builds."
		if errors.Is(versionErr, exec.ErrNotFound) {
			reason = "throughput_tool_unavailable"
			next = "Install iperf3 >= 3.11 before explicitly retrying; no throughput traffic was sent."
		}
		return throughputFailure(out, errOut, asJSON, code, reason,
			"cannot verify local iperf3 TCP data-socket binding capability", next)
	}
	benchCtx, finish := context.WithTimeout(ctx, time.Duration(seconds)*time.Second+throughputBenchmarkOverhead)
	defer finish()
	// The explicit Linux --bind-dev form requests SO_BINDTODEVICE on
	// control AND data TCP sockets in the known-safe version family.
	// Never fall back to address-only binding after a tool failure.
	result, err := tool.RunBounded(benchCtx, linux.CaptureLimits{Stdout: 64 << 10, Stderr: 2048},
		"iperf3", "--client", record.Desired.Addresses.Peer.Addr().String(),
		"--bind", record.Desired.Addresses.Local.Addr().String(),
		"--bind-dev", iface,
		"--port", "5201", "--time", strconv.Itoa(seconds),
		"--connect-timeout", "2000", "--json")
	if ctx.Err() != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInspect,
			"throughput_interrupted", "operation expired before the benchmark could be verified",
			"Recheck Link state and explicitly retry when host resources are available; no complete measurement was recorded.")
	}
	if err != nil || benchCtx.Err() != nil {
		code, reason := stlerr.CodeInspect, "throughput_server_unavailable"
		if errors.Is(err, exec.ErrNotFound) {
			code, reason = stlerr.CodeUnsupported, "throughput_tool_unavailable"
		}
		return throughputFailure(out, errOut, asJSON, code, reason,
			"bounded iperf3 client measurement did not complete",
			"Install compatible iperf3 and have the authorized peer explicitly listen on its Link Address TCP/5201; STL never starts a server.")
	}
	projected, err := parseThroughputOutput(result.Stdout, id, record.Desired.Backend, seconds)
	if ctx.Err() != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInspect,
			"throughput_interrupted", "operation expired before throughput results were verified",
			"Recheck the Link and explicitly retry; the expired observation was not published.")
	}
	if err != nil {
		return throughputFailure(out, errOut, asJSON, stlerr.CodeInspect,
			"throughput_result_unverified", "no complete numeric throughput measurement",
			"Inspect the separately managed peer listener and explicitly retry.")
	}
	if asJSON {
		if json.NewEncoder(out).Encode(projected) != nil {
			fmt.Fprintln(errOut, "failed to encode throughput report")
			return 1
		}
		return 0
	}
	fmt.Fprintf(out, "Link %s: explicitly requested %ds single-stream TCP test (local to peer).\n", id, seconds)
	fmt.Fprintf(out, "Sent %.3f Mbit/s (%d bytes); peer received %.3f Mbit/s (%d bytes).\n",
		projected.SentMbps, projected.SentBytes, projected.ReceivedMbps, projected.ReceivedBytes)
	fmt.Fprintln(out, "A short opt-in sample is not a sustained-capacity or availability guarantee.")
	return 0
}
