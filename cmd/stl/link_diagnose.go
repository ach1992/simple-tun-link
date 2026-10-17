package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Default probes require at most 28 seconds (18 MTU x 1s, 5 quality x
// 2s). Retain the original 35-second per-Link deadline, leaving 7 seconds
// for verified backend inspection/preflight and scheduling overhead. Both
// single-Link and all-Link diagnostics use this same per-Link bound.
const diagnoseOperationTimeout = diagnostics.DefaultDiagnosticProbeBudget + 7*time.Second

// linkDiagnoseCommand is explicitly active but read-only: it sends bounded
// ICMP echo packets to the selected peer Link Address; it never repairs,
// applies MTU, adds routes, or modifies any kernel or saved Link state.
func linkDiagnoseCommand(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
	if len(args) >= 2 && args[1] == "--all" {
		return linkDiagnoseAllCommand(args, stdout, stderr, options)
	}
	jsonOutput := slices.Contains(args, "--json")
	manualMTU, ok := parseDiagnoseOptions(args)
	if !ok {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_diagnose",
			"usage: stl link diagnose <link-id> [--mtu <bytes>] [--json]")
	}
	id := domain.LinkID(args[1])
	if err := id.Validate(); err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_diagnose", "invalid Link ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), diagnoseOperationTimeout)
	defer cancel()

	root := state.DefaultRoot
	if options != nil {
		root = options.stateRoot
	}
	if root == "" {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_diagnose", "local state root is unavailable")
	}
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_diagnose", "cannot read local desired-state snapshot")
	}
	record, exists := snapshot.Find(id)
	if !exists {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInvalid, "link_diagnose", "Link ID is not present in local desired state")
	}

	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_diagnose", "cannot initialize diagnostic backend")
		}
	}
	if record.Desired.Backend == domain.BackendIPsec && !hasOperationalIPsec(*options) {
		return ipsecUnregisteredError(stdout, stderr, jsonOutput, "link_diagnose", id)
	}
	measurement, err := inspectLinkDiagnostic(ctx, record.Desired, *options, manualMTU)
	if err != nil {
		code := stlerr.CodeOf(err)
		if record.Desired.Backend == domain.BackendIPsec && stlerr.Public(err).ReasonCode == "ipsec_sa_not_established" {
			public := stlerr.New(stlerr.CodeInspect, "link_diagnose", string(id), "ipsec",
				"IPsec is configured but no matching security association exists; no ICMP probes were sent")
			public.ReasonCode = "ipsec_sa_not_established"
			public.NextStep = stlerr.Public(err).NextStep
			return readCommandPublicError(stdout, stderr, jsonOutput, public)
		}
		if stlerr.Public(err).ReasonCode == "kernel_module_not_loaded" {
			public := stlerr.New(code, "link_diagnose", "", "",
				"required kernel module is available on disk but not loaded; diagnostic inventory was not verified")
			public.ReasonCode = "kernel_module_not_loaded"
			public.NextStep = "Check kernel module policy and load only with authorization; rerun observational diagnosis."
			return readCommandPublicError(stdout, stderr, jsonOutput, public)
		}
		switch code {
		case stlerr.CodeInvalid:
			return readCommandError(stdout, stderr, jsonOutput, code, "link_diagnose", "invalid diagnostic configuration or MTU request")
		case stlerr.CodeUnsupported:
			return readCommandError(stdout, stderr, jsonOutput, code, "link_diagnose", "Link diagnosis unsupported on this host")
		default:
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_diagnose", "Link diagnostic observation failed")
		}
	}
	report := measurement.report
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			fmt.Fprintln(stderr, "cannot encode diagnostic report")
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, report.Summary())
	return 0
}

// The optional mtu value is deliberately inner IPv4 packet bytes (not
// iputils ping -s payload bytes). The common diagnostics algorithm performs
// final validation against the kernel-observed outer MTU and backend overhead.
func parseDiagnoseOptions(args []string) (int, bool) {
	if len(args) < 2 || args[0] != "diagnose" {
		return 0, false
	}
	manual, seenMTU, seenJSON := 0, false, false
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--json":
			if seenJSON {
				return 0, false
			}
			seenJSON = true
		case "--mtu":
			if seenMTU || i+1 >= len(args) {
				return 0, false
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < diagnostics.MinIPv4MTU || n > diagnostics.MaxIPv4MTU {
				return 0, false
			}
			manual, seenMTU = n, true
			i++
		default:
			return 0, false
		}
	}
	return manual, true
}
