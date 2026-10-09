package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

const diagnoseOperationTimeout = 35 * time.Second

// linkDiagnoseCommand is explicitly active but read-only: it sends bounded
// ICMP echo packets to the selected peer Link Address; it never repairs,
// applies MTU, adds routes, or modifies any kernel or saved Link state.
func linkDiagnoseCommand(args []string, stdout, stderr io.Writer, options *runtimeOptions) int {
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
	if record.Desired.Backend != domain.BackendGRE && record.Desired.Backend != domain.BackendIPIP {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_diagnose", "active diagnostics for this backend are unavailable")
	}
	if options == nil {
		options, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeState, "link_diagnose", "cannot initialize diagnostic backend")
		}
	}
	var selected backend.Backend
	for _, impl := range options.backends {
		if impl != nil && impl.Kind() == record.Desired.Backend {
			selected = impl
			break
		}
	}
	if selected == nil {
		return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_diagnose", "diagnostic backend is unavailable")
	}
	runner := options.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	var report interface{ Summary() string }
	backendName := "GRE"
	switch record.Desired.Backend {
	case domain.BackendGRE:
		inspector, ok := selected.(diagnostics.GREInspector)
		if !ok {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_diagnose", "GRE diagnostic backend is unavailable")
		}
		var measured diagnostics.GREReport
		measured, err = diagnostics.ObserveGRE(ctx, record.Desired, inspector, runner, manualMTU)
		report = measured
	case domain.BackendIPIP:
		backendName = "IPIP"
		inspector, ok := selected.(diagnostics.IPIPInspector)
		if !ok {
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeUnsupported, "link_diagnose", "IPIP diagnostic backend is unavailable")
		}
		var measured diagnostics.IPIPReport
		measured, err = diagnostics.ObserveIPIP(ctx, record.Desired, inspector, runner, manualMTU)
		report = measured
	}
	if err != nil {
		code := stlerr.CodeOf(err)
		switch code {
		case stlerr.CodeInvalid:
			return readCommandError(stdout, stderr, jsonOutput, code, "link_diagnose", "invalid "+backendName+" diagnostic configuration or MTU request")
		case stlerr.CodeUnsupported:
			return readCommandError(stdout, stderr, jsonOutput, code, "link_diagnose", backendName+" diagnosis unsupported on this host")
		default:
			return readCommandError(stdout, stderr, jsonOutput, stlerr.CodeInspect, "link_diagnose", backendName+" Link diagnostic observation failed")
		}
	}
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
