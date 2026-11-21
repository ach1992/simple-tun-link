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
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "spoof_health", string(link.ID), "spoof", "Spoof original systemd helper, TUN, private route or material not verified")
	}
	runtime := spoofhost.TrustedRuntimeStatus(opts.stateRoot, link.ID, host)
	if runtime.State != "CONNECTED" || !runtime.BilateralConfirmed || !runtime.Authenticated {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "spoof_health", string(link.ID), "spoof", "Spoof private probing unavailable until authenticated bilateral path is confirmed; check spoof-status")
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
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "spoof_health", string(link.ID), "spoof", "Spoof private ICMP quality probe failed; inspect peer status and Source viability")
	}
	return linkDiagnostic{report: report, mtu: report.MTU, quality: report.Quality}, nil
}
