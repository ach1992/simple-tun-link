package main

import (
	"context"

	masquebackend "github.com/ach1992/simple-tun-link/internal/backend/masque"
	"github.com/ach1992/simple-tun-link/internal/carrier/masque"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// An active ICMP probe requires exact, committed original ownership AND a
// read-only verified local TUN/service. This does not assume an open remote
// CONNECT-IP stream, which the actual five pings must measure separately.
func inspectMASQUEQuality(ctx context.Context, link domain.Link, opts runtimeOptions) (linkDiagnostic, error) {
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(ctx)
	if err != nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "masque_health", string(link.ID), "masque", "cannot read saved original Link identity")
	}
	record, committed := snapshot.Find(link.ID)
	if !committed || record.Desired != link {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeConflict, "masque_health", string(link.ID), "masque", "original MASQUE identity is not committed")
	}
	if _, pending := snapshot.FindMASQUEOperation(link.ID); pending {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeConflict, "masque_health", string(link.ID), "masque", "MASQUE host effect has an unresolved journal")
	}
	var inspector interface {
		DiagnosticState(context.Context, domain.Link) (masquebackend.HostObservation, error)
	}
	for _, impl := range opts.backends {
		if impl != nil && impl.Kind() == domain.BackendMASQUE {
			inspector, _ = impl.(interface {
				DiagnosticState(context.Context, domain.Link) (masquebackend.HostObservation, error)
			})
			break
		}
	}
	if inspector == nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeUnsupported, "masque_health", string(link.ID), "masque", "managed host inspector unavailable")
	}
	observed, err := inspector.DiagnosticState(ctx, link)
	if err != nil || !observed.RuntimeReady {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "masque_health", string(link.ID), "masque", "owned local MASQUE service, TUN, route and credentials are not all verified")
	}
	iface, err := masque.AgentInterfaceName(link.ID)
	if err != nil {
		return linkDiagnostic{}, err
	}
	runner := opts.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	report, err := diagnostics.ObservePrivateLinkQuality(ctx, link, iface, runner)
	if err != nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "masque_health", string(link.ID), "masque", "private MASQUE ICMP observation unavailable")
	}
	return linkDiagnostic{report: report, mtu: report.MTU, quality: report.Quality}, nil
}
