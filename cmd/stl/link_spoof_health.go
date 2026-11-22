package main

import (
	"context"

	spoofbackend "github.com/ach1992/simple-tun-link/internal/backend/spoof"
	carrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/spoofhost"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Spoof diagnose is an explicitly invoked active private-IP measurement,
// never source scanning or Link modification. Reject unproven helper
// ownership/liveness before sending diagnostic traffic.
func inspectSpoofQuality(ctx context.Context, link domain.Link, opts runtimeOptions) (linkDiagnostic, error) {
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(ctx)
	if err != nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "spoof_health", string(link.ID), "spoof", "cannot inspect committed Link State")
	}
	original, found := snapshot.Find(link.ID)
	if !found || original.Desired != link {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeConflict, "spoof_health", string(link.ID), "spoof", "original Spoof Link not committed")
	}
	var inspector interface {
		DiagnosticState(context.Context, domain.Link) (spoofbackend.HostObservation, error)
	}
	for _, impl := range opts.backends {
		if impl != nil && impl.Kind() == domain.BackendSpoof {
			inspector, _ = impl.(interface {
				DiagnosticState(context.Context, domain.Link) (spoofbackend.HostObservation, error)
			})
			break
		}
	}
	if inspector == nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeUnsupported, "spoof_health", string(link.ID), "spoof", "managed Spoof host inspector unavailable")
	}
	host, err := inspector.DiagnosticState(ctx, link)
	if err != nil || !host.RuntimeReady {
		failure := stlerr.New(stlerr.CodeInspect, "spoof_health", string(link.ID), "spoof",
			"Spoof local helper, TUN, private route or credential identity is not verified; no private ICMP probes were sent")
		failure.ReasonCode = "spoof_local_helper_unverified"
		failure.NextStep = "Run stl link spoof-status " + string(link.ID) + " --json; inspect the original helper, systemd unit, TUN and private route without adopting foreign resources."
		return linkDiagnostic{}, failure
	}
	runtime := spoofhost.TrustedRuntimeStatus(opts.stateRoot, link.ID, host)
	if runtime.State != "CONNECTED" || !runtime.BilateralConfirmed || !runtime.Authenticated {
		failure := stlerr.New(stlerr.CodeInspect, "spoof_health", string(link.ID), "spoof",
			"Spoof local Link is provisioned, but an authenticated bilateral path has not been confirmed; no private ICMP probes were sent")
		failure.ReasonCode = "spoof_bilateral_unconfirmed"
		failure.NextStep = "Run stl link spoof-status " + string(link.ID) + " --json on both peers; check authenticated, bilateral_confirmed, Source candidates and exact real destinations. Retry private diagnosis only after bilateral confirmation."
		return linkDiagnostic{}, failure
	}
	device, err := carrier.TunnelName(link.ID)
	if err != nil {
		return linkDiagnostic{}, err
	}
	runner := opts.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	report, err := diagnostics.ObservePrivateLinkQuality(ctx, link, device, runner)
	if err != nil {
		failure := stlerr.New(stlerr.CodeInspect, "spoof_health", string(link.ID), "spoof",
			"Spoof authenticated carrier was observed, but the private IPv4 ICMP quality probe was not verified")
		failure.ReasonCode = "spoof_private_icmp_unverified"
		failure.NextStep = "Inspect peer private routes, ICMP policy and current Spoof status; the probe failure is not proof that the carrier has disconnected."
		return linkDiagnostic{}, failure
	}
	return linkDiagnostic{report: report, mtu: report.MTU, quality: report.Quality}, nil
}
