package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// A v1, read-only, multi-Link health inventory. Each check is independent:
// an unavailable backend, dead peer, or inactive IPsec does not prevent
// observing other Links. No saved display name, pairing material, private
// key, raw command output or free-form backend error is emitted.
type healthCenterResponse struct {
	SchemaVersion int               `json:"schema_version"`
	Operation     string            `json:"operation"`
	Outcome       string            `json:"outcome"`
	Total         int               `json:"total"`
	Observed      int               `json:"observed"`
	Blocked       int               `json:"blocked"`
	Unknown       int               `json:"unknown"`
	Checks        []healthLinkCheck `json:"checks"`
}

type healthLinkCheck struct {
	Link       linkSummary            `json:"link"`
	Status     string                 `json:"status"`
	ReasonCode string                 `json:"reason_code"`
	Summary    string                 `json:"summary"`
	NextStep   string                 `json:"next_step"`
	Observed   *healthLinkObservation `json:"observation,omitempty"`
}

type healthLinkObservation struct {
	MTU                 diagnostics.MTUResult     `json:"mtu"`
	Quality             diagnostics.QualityResult `json:"quality"`
	RX                  uint64                    `json:"rx"`
	TX                  uint64                    `json:"tx"`
	CounterUnit         string                    `json:"counter_unit"`
	LatestHandshakeUnix *int64                    `json:"latest_handshake_unix,omitempty"`
}

func parseHealthCenterArgs(args []string) (jsonOutput bool, timeout time.Duration, ok bool) {
	if len(args) < 2 || args[0] != "diagnose" || args[1] != "--all" {
		return false, 0, false
	}
	seenJSON, seenTimeout := false, false
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--json":
			if seenJSON {
				return false, 0, false
			}
			seenJSON = true
		case "--timeout":
			if seenTimeout || i+1 >= len(args) {
				return false, 0, false
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil || d <= 0 {
				return false, 0, false
			}
			timeout, seenTimeout = d, true
			i++
		default:
			return false, 0, false
		}
	}
	return seenJSON, timeout, true
}

func linkDiagnoseAllCommand(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
	jsonOutput := slices.Contains(args, "--json")
	_, timeout, valid := parseHealthCenterArgs(args)
	if !valid {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_diagnose_all",
			"usage: stl link diagnose --all [--timeout <duration>] [--json]")
	}
	root := state.DefaultRoot
	if options != nil {
		root = options.stateRoot
	}
	if root == "" {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_diagnose_all",
			"local desired-state root is unavailable")
	}

	// One authoritative, time-local state snapshot: Links created/removed
	// concurrently are not implicitly adopted or merged into this inventory.
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_diagnose_all",
			"cannot read persisted Link inventory")
	}
	links := make([]domain.Link, 0, len(snapshot.Links))
	for _, entry := range snapshot.Links {
		links = append(links, entry.Desired)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	response := healthCenterResponse{
		SchemaVersion: jsonSchemaVersion, Operation: "link_diagnose_all",
		Outcome: "complete", Total: len(links), Checks: make([]healthLinkCheck, 0, len(links)),
	}

	// Initialization errors are not silently treated as healthy/vacant.
	// A global lack of tools does not discard the per-Link inventory.
	runtimeAvailable := true
	if options == nil && len(links) > 0 {
		options, err = productionRuntimeOptions()
		runtimeAvailable = err == nil
	}
	if options == nil {
		options = &runtimeOptions{stateRoot: root}
	}

	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx := baseCtx
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(baseCtx, timeout)
		defer cancel()
	}
	for _, link := range links {
		var check healthLinkCheck
		switch {
		case ctx.Err() != nil:
			response.Outcome = "interrupted"
			check = healthUnavailable(link, "diagnostic_interrupted",
				"Batch diagnosis stopped before this Link could be observed.",
				"Review current Link state and rerun the read-only check with a suitable --timeout.")
		case link.Backend == domain.BackendIPsec:
			check = healthBlocked(link, "ipsec_runtime_not_registered",
				"IPsec runtime is not installed or registered for operational Link checks.",
				"Use a supported active backend; complete exclusive strongSwan qualification before IPsec activation.")
		case !runtimeAvailable:
			check = healthUnavailable(link, "diagnostic_runtime_unavailable",
				"Diagnostic runtime could not be initialized; no live observation was attempted.",
				"Check host backend dependencies and local runtime availability without changing Link state.")
		default:
			// Independent bounded per-Link work; no global request timeout is
			// imposed by default. Operators may configure an overall budget.
			probeCtx, cancel := context.WithTimeout(ctx, diagnoseOperationTimeout)
			measurement, problem := inspectLinkDiagnostic(probeCtx, link, *options, 0)
			cancel()
			if problem != nil {
				check = healthDiagnosticFailure(link, problem)
				if ctx.Err() != nil {
					response.Outcome = "interrupted"
				}
			} else {
				check = healthFromMeasurement(link, measurement)
			}
		}
		switch check.Status {
		case "observed":
			response.Observed++
		case "blocked":
			response.Blocked++
		default:
			response.Unknown++
		}
		response.Checks = append(response.Checks, check)
	}
	if ctx.Err() != nil {
		response.Outcome = "interrupted"
	}

	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(response); err != nil {
			fmt.Fprintln(stderr, "cannot encode health-center report; output may be incomplete")
			return 1
		}
	} else {
		if len(links) == 0 {
			fmt.Fprintln(stdout, "No configured Links in the current saved snapshot; no live link was tested.")
		}
		for _, check := range response.Checks {
			fmt.Fprintf(stdout, "%s %s/%s: %s/%s\n  %s\n  Next: %s\n",
				check.Link.ID, check.Link.Backend, check.Link.Encapsulation,
				check.Status, check.ReasonCode, check.Summary, check.NextStep)
			if check.Observed != nil {
				fmt.Fprintf(stdout, "  MTU=%d, probes=%d, replies=%d, RX=%d TX=%d %s\n",
					check.Observed.MTU.SelectedMTU, check.Observed.Quality.PacketsSent,
					check.Observed.Quality.PacketsReceived, check.Observed.RX,
					check.Observed.TX, check.Observed.CounterUnit)
			}
		}
		fmt.Fprintf(stdout, "Links in snapshot: %d | peer replied: %d | blocked: %d | unknown: %d | run: %s\n",
			response.Total, response.Observed, response.Blocked, response.Unknown, response.Outcome)
	}
	// A completed inventory is not necessarily a healthy set. Never exit 0
	// for a failed/inconclusive Link or a canceled inventory.
	if response.Unknown > 0 || response.Outcome != "complete" {
		return 1
	}
	if response.Blocked > 0 {
		return 4
	}
	return 0
}

func healthUnavailable(link domain.Link, reason, summary, next string) healthLinkCheck {
	return healthLinkCheck{Link: summarizeLink(link), Status: "unknown",
		ReasonCode: reason, Summary: summary, NextStep: next}
}

func healthBlocked(link domain.Link, reason, summary, next string) healthLinkCheck {
	return healthLinkCheck{Link: summarizeLink(link), Status: "blocked",
		ReasonCode: reason, Summary: summary, NextStep: next}
}

func healthDiagnosticFailure(link domain.Link, err error) healthLinkCheck {
	if code := stlerr.CodeOf(err); code == stlerr.CodeUnsupported {
		return healthBlocked(link, "diagnostic_capability_unavailable",
			"Backend capability or diagnostic adapter is unavailable.",
			"Check host kernel/tools and the requested backend; do not treat missing diagnostics as a healthy Link.")
	}
	if stlerr.CodeOf(err) == stlerr.CodeConflict {
		return healthBlocked(link, "diagnostic_ownership_conflict",
			"Backend rejected a conflicting observed resource or Link identity.",
			"Inspect live resource ownership; do not take over or delete unrecognized interfaces.")
	}
	if stlerr.CodeOf(err) == stlerr.CodeInvalid {
		return healthBlocked(link, "diagnostic_link_invalid",
			"Saved Link configuration is invalid for current diagnostics.",
			"Review saved Link configuration read-only; do not blindly reapply.")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return healthUnavailable(link, "diagnostic_interrupted",
			"Link observation was interrupted or timed out.",
			"Inspect Link status; rerun read-only diagnosis when host availability permits.")
	}
	return healthUnavailable(link, "diagnostic_observation_unverified",
		"Backend identity, network probe or current Link observation could not be verified.",
		"Inspect Link status and kernel prerequisites; do not infer absence, repairability or successful traffic.")
}

func healthFromMeasurement(link domain.Link, measurement linkDiagnostic) healthLinkCheck {
	observed := &healthLinkObservation{
		MTU: measurement.mtu, Quality: measurement.quality,
		RX: measurement.rx, TX: measurement.tx, CounterUnit: measurement.counterUnit,
	}
	if measurement.handshakeUTC > 0 {
		observed.LatestHandshakeUnix = &measurement.handshakeUTC
	}
	switch {
	case measurement.quality.Status == diagnostics.QualityMeasured && measurement.quality.Reachable:
		return healthLinkCheck{
			Link: summarizeLink(link), Status: "observed", ReasonCode: "link_peer_replied",
			Summary:  "The verified Link received a peer echo reply during bounded probes; future traffic is not guaranteed.",
			NextStep: "No automatic action; use per-Link diagnosis for counters and detailed PMTU/quality evidence.",
			Observed: observed,
		}
	case measurement.quality.Status == diagnostics.QualityMeasured:
		check := healthUnavailable(link, "link_probe_no_reply",
			"The Link's verified interface produced no peer echo replies during this brief probe.",
			"Check peer reachability, route and ICMP policy; lack of replies alone is not proof that all traffic is down.")
		check.Observed = observed
		return check
	default:
		check := healthUnavailable(link, "link_probe_incomplete",
			"Link identity was checked but active reachability measurement was incomplete.",
			"Review per-Link MTU/quality reason codes and host probe prerequisites before changing configuration.")
		check.Observed = observed
		return check
	}
}
