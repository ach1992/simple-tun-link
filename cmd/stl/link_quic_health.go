package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ach1992/simple-tun-link/internal/app"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/quichelper"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// These are separately observed local facts. A running process never proves
// QUIC authentication or private application traffic.
type QUICLinkDiagnostics struct {
	SchemaVersion              int                           `json:"schema_version"`
	LinkID                     domain.LinkID                 `json:"link_id"`
	Carrier                    string                        `json:"carrier"`
	Role                       string                        `json:"role"`
	Interface                  string                        `json:"interface,omitempty"`
	IfIndex                    int                           `json:"ifindex,omitempty"`
	QUICHelperActive           bool                          `json:"quic_helper_active"`
	QUICHelperLoaded           bool                          `json:"quic_helper_loaded"`
	WGIngressGuardActive       bool                          `json:"wg_ingress_guard_active"`
	KernelWireGuardPresent     bool                          `json:"kernel_wireguard_present"`
	WireGuardHandshakeObserved bool                          `json:"wireguard_handshake_observed"`
	LastHandshakeUnix          int64                         `json:"last_handshake_unix,omitempty"`
	RXBytes                    uint64                        `json:"rx_bytes"`
	TXBytes                    uint64                        `json:"tx_bytes"`
	AuthenticationObservation  string                        `json:"authentication_observation"`
	TrafficObservation         string                        `json:"traffic_observation"`
	Helper                     *quichelper.HelperDiagnostics `json:"helper,omitempty"`
	HelperObservationReason    string                        `json:"helper_observation_reason,omitempty"`
}

func quicHealthError(link domain.Link, reason, detail string) error {
	e := stlerr.New(stlerr.CodeInspect, "quic_health", string(link.ID), string(link.Backend), detail)
	e.ReasonCode = reason
	e.NextStep = "Inspect this Link's protected State and the reported local helper/guard/kernel evidence; preserve original credentials and unresolved journals."
	return e
}

// The canonical Engine binds the committed generation and re-inspects all
// owned resources under its existing locks. CLI code does not adopt names,
// receipts or arbitrary matching processes as ownership evidence.
func trustedQUICObservation(ctx context.Context, link domain.Link, options runtimeOptions) (QUICLinkDiagnostics, linux.Runner, error) {
	d := QUICLinkDiagnostics{SchemaVersion: 1, LinkID: link.ID, Carrier: "quic-udp", Role: link.QUIC.Role,
		AuthenticationObservation: "not_observable_from_process_state",
		TrafficObservation:        "not_tested_by_read_only_diagnostics"}
	if link.Backend != domain.BackendWireGuardQUIC {
		return d, nil, quicHealthError(link, "quic_identity_unverified", "not a QUIC Link")
	}
	snapshot, err := state.NewFileStore(options.stateRoot).Load(ctx)
	if err != nil {
		return d, nil, quicHealthError(link, "quic_identity_unverified", "saved QUIC identity is unavailable")
	}
	record, found := snapshot.Find(link.ID)
	if !found || record.Desired != link {
		return d, nil, quicHealthError(link, "quic_identity_unverified", "saved QUIC identity changed")
	}
	if _, pending := snapshot.FindQUICCrashOperation(link.ID); pending {
		return d, nil, quicHealthError(link, "quic_crash_quarantined", "QUIC generation has an unresolved operation; no healthy status or probe is asserted")
	}
	var observed app.QUICInspection
	if options.quicObserver != nil {
		observed, err = options.quicObserver(ctx, link.ID)
	} else {
		engine, buildErr := buildRuntimeEngine(options)
		if buildErr != nil {
			return d, nil, quicHealthError(link, "quic_observer_unavailable", "canonical QUIC observer unavailable")
		}
		observed, err = engine.InspectQUIC(ctx, link.ID)
	}
	if err != nil {
		return d, nil, quicHealthError(link, "quic_original_unverified", "original QUIC helper, guard or kernel generation is unverified")
	}
	name, nameErr := wgbackend.InterfaceName(link.ID)
	if nameErr != nil || (observed.KernelPresent && (observed.Interface != name || observed.IfIndex <= 0)) ||
		observed.LatestHandshakeUnix < 0 || observed.LatestHandshakeUnix > time.Now().Add(5*time.Minute).Unix() {
		return d, nil, quicHealthError(link, "quic_original_unverified", "QUIC public observation is inconsistent")
	}
	d.Interface, d.IfIndex = observed.Interface, observed.IfIndex
	d.QUICHelperActive, d.QUICHelperLoaded = observed.HelperActive, observed.HelperLoaded
	d.WGIngressGuardActive, d.KernelWireGuardPresent = observed.GuardActive, observed.KernelPresent
	d.LastHandshakeUnix, d.RXBytes, d.TXBytes = observed.LatestHandshakeUnix, observed.RXBytes, observed.TXBytes
	d.WireGuardHandshakeObserved = observed.LatestHandshakeUnix > 0
	if d.WireGuardHandshakeObserved {
		d.AuthenticationObservation = "kernel WireGuard peer authenticated; QUIC mTLS is not individually attested by this command"
	}
	if d.RXBytes > 0 && d.TXBytes > 0 {
		d.TrafficObservation = "kernel WireGuard RX/TX bytes observed; application traffic was not measured by this command"
	}
	helper, partial, helperErr := observeQUICHelperDetails(ctx, link, record, observed, options)
	if helperErr != nil {
		return d, nil, helperErr
	}
	d.Helper, d.HelperObservationReason = helper, partial
	if helper.Authentication == "observed" {
		d.AuthenticationObservation = "QUIC carrier authentication observed in attributed current-invocation events; private application traffic remains a separate measurement"
	}
	runner := options.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	return d, runner, nil
}

func inspectQUICQuality(ctx context.Context, link domain.Link, options runtimeOptions) (linkDiagnostic, error) {
	observed, runner, err := trustedQUICObservation(ctx, link, options)
	if err != nil {
		return linkDiagnostic{}, err
	}
	if !observed.QUICHelperActive || !observed.WGIngressGuardActive || !observed.KernelWireGuardPresent {
		return linkDiagnostic{}, quicHealthError(link, "quic_local_not_ready", "QUIC helper, ingress guard or private WireGuard interface is not ready")
	}
	report, err := diagnostics.ObservePrivateLinkQuality(ctx, link, observed.Interface, runner)
	if err != nil {
		return linkDiagnostic{}, quicHealthError(link, "quic_quality_unverified", "private QUIC peer quality observation is unavailable")
	}
	return linkDiagnostic{report: report, mtu: report.MTU, quality: report.Quality,
		rx: observed.RXBytes, tx: observed.TXBytes, counterUnit: "bytes", handshakeUTC: observed.LastHandshakeUnix}, nil
}

// The dedicated diagnostic is read-only. Generic `link diagnose` performs
// the separately requested, bounded private-IP probes.
func linkQUICDiagnoseCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	isJSON := len(args) == 3 && args[2] == "--json"
	if !(len(args) == 2 || isJSON) || domain.LinkID(args[1]).Validate() != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "diagnose_quic", "usage: stl link diagnose-quic <link-id> [--json]")
	}
	var err error
	if opts == nil {
		opts, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState, "diagnose_quic", "runtime unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(ctx)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, "diagnose_quic", "saved Link State unavailable")
	}
	record, exists := snapshot.Find(domain.LinkID(args[1]))
	if !exists || record.Desired.Backend != domain.BackendWireGuardQUIC {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "diagnose_quic", "saved QUIC Link unavailable")
	}
	observed, _, err := trustedQUICObservation(ctx, record.Desired, *opts)
	if err != nil {
		return readQUICInspectionError(ctx, out, errOut, isJSON, err)
	}
	if isJSON {
		if json.NewEncoder(out).Encode(observed) != nil {
			return 1
		}
	} else {
		fmt.Fprintf(out, "QUIC Link %s: helper=%t guard=%t kernel=%t WG-handshake=%t, RX=%d TX=%d bytes; private connectivity not measured.\n",
			observed.LinkID, observed.QUICHelperActive, observed.WGIngressGuardActive, observed.KernelWireGuardPresent,
			observed.WireGuardHandshakeObserved, observed.RXBytes, observed.TXBytes)
		writeQUICHelperDetails(out, observed.Helper, observed.HelperObservationReason)
	}
	return 0
}
