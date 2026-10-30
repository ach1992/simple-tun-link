package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/quichelper"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// The helper owns bounded journal attribution and classification. Only its
// public fields cross this layer; command stderr and journal MESSAGE never do.
// A partial event read preserves proven process facts and explicitly reports
// unavailable events. Failure to observe the actual owner remains an error.
func observeQUICHelperDetails(ctx context.Context, link domain.Link, record state.LinkRecord,
	observed app.QUICInspection, options runtimeOptions) (*quichelper.HelperDiagnostics, string, error) {
	observe := options.quicHelperObserver
	if observe == nil {
		host, err := quichelper.NewHost(options.stateRoot, state.NewFileStore(options.stateRoot))
		if err != nil {
			return nil, "", quicHealthError(link, "quic_observer_unavailable", "owned helper diagnostic adapter unavailable")
		}
		observe = host.Diagnose
	}
	details, err := observe(ctx, link)
	partial := ""
	if err != nil {
		if !details.GuardObserved || !details.HelperObserved || details.JournalState != "unavailable" {
			return nil, "", quicHealthError(link, "quic_helper_unverified", "current owned helper process or protected material could not be observed")
		}
		partial = "quic_journal_unavailable"
	}
	if !details.GuardObserved || !details.HelperObserved || details.GuardPresent != observed.GuardActive ||
		details.HelperPresent != observed.HelperActive || details.HelperLoaded != observed.HelperLoaded {
		return nil, "", quicHealthError(link, "quic_observation_changed", "helper or guard changed between the separate bounded observations")
	}
	// Neither a stale CLI selection nor a concurrent committed generation may
	// lend its name to another helper's events. Both adapters independently
	// verify original host objects, and this final check binds the public view.
	after, loadErr := state.NewFileStore(options.stateRoot).Load(ctx)
	current, present := after.Find(link.ID)
	_, pending := after.FindQUICCrashOperation(link.ID)
	if loadErr != nil || !present || current.Desired != link || current.QUICGeneration != record.QUICGeneration || pending {
		return nil, "", quicHealthError(link, "quic_observation_changed", "committed QUIC generation changed during diagnostic observation")
	}
	return &details, partial, nil
}

func writeQUICHelperDetails(out io.Writer, details *quichelper.HelperDiagnostics, partial string) {
	if details == nil {
		return
	}
	fmt.Fprintf(out, "Helper process: state=%s, restarts=%d, material=%s, events=%s.\n", details.State, details.RestartCount, details.MaterialState, details.JournalState)
	if details.ExitResult != "" {
		fmt.Fprintf(out, "Helper exit: result=%s code=%d status=%d.\n", details.ExitResult, details.ExitCode, details.ExitStatus)
	}
	fmt.Fprintf(out, "Current-invocation historical carrier events: authentication=%s handshake=%s; these events do not prove private application traffic.\n", details.Authentication, details.Handshake)
	if partial != "" {
		fmt.Fprintln(out, "Helper event stream unavailable; verified local process and guard facts remain separately reported.")
	}
	start := len(details.Events) - 8
	if start < 0 {
		start = 0
	}
	for _, event := range details.Events[start:] {
		at := time.UnixMicro(int64(event.TimestampUSec)).UTC().Format(time.RFC3339)
		fmt.Fprintf(out, "  %s %s %s", at, event.Level, event.Event)
		if event.ReasonCode != "" {
			fmt.Fprintf(out, " [%s]", event.ReasonCode)
		}
		fmt.Fprintln(out)
		if event.NextStep != "" {
			fmt.Fprintln(out, "    Next:", event.NextStep)
		}
	}
}

// Preserve only authored QUIC reason codes. The generic status projection
// deliberately discards arbitrary backend errors; that must not erase the
// specific, secret-free evidence boundary introduced by this adapter.
func readQUICInspectionError(ctx context.Context, out, errOut io.Writer, jsonOutput bool, observed error) int {
	if ctx.Err() != nil {
		return readStatusInspectionError(ctx, out, errOut, jsonOutput, observed)
	}
	public := stlerr.Public(observed)
	if public.Operation != "quic_health" || public.Backend != string(domain.BackendWireGuardQUIC) {
		return readStatusInspectionError(ctx, out, errOut, jsonOutput, observed)
	}
	var detail string
	switch public.ReasonCode {
	case "quic_identity_unverified":
		detail = "saved QUIC identity is unverified"
	case "quic_crash_quarantined":
		detail = "QUIC generation has an unresolved operation; no healthy status is asserted"
	case "quic_observer_unavailable":
		detail = "canonical QUIC observer unavailable"
	case "quic_original_unverified":
		detail = "original QUIC helper, guard or kernel generation is unverified"
	case "quic_helper_unverified":
		detail = "current owned helper process or protected material could not be observed"
	case "quic_observation_changed":
		detail = "QUIC generation or host observations changed during inspection"
	case "quic_local_not_ready":
		detail = "QUIC helper, ingress guard or private WireGuard interface is not ready"
	case "quic_quality_unverified":
		detail = "private QUIC peer quality observation unavailable"
	default:
		return readStatusInspectionError(ctx, out, errOut, jsonOutput, observed)
	}
	id := public.ObjectID
	if domain.LinkID(id).Validate() != nil {
		id = ""
	}
	fixed := stlerr.New(stlerr.CodeInspect, "quic_health", id, string(domain.BackendWireGuardQUIC), detail)
	fixed.ReasonCode = public.ReasonCode
	fixed.NextStep = "Preserve original credentials and unresolved journals; inspect the selected Link's protected State and current helper/guard/kernel evidence."
	return readCommandPublicError(out, errOut, jsonOutput, fixed)
}
