//go:build linux

package diagnostics

import (
	"context"
	"fmt"

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// IPsecInspector exposes only admitted, verified public XFRM and SA state.
// No credential, SA encryption key or arbitrary daemon output is requested.
type IPsecInspector interface {
	DiagnosticState(context.Context, domain.Link) (ipsecbackend.DiagnosticState, error)
}

type IPsecReport struct {
	Report
	Backend domain.Backend               `json:"backend"`
	State   ipsecbackend.DiagnosticState `json:"state"`
}

func ObserveIPsec(ctx context.Context, link domain.Link, inspector IPsecInspector,
	runner linux.Runner, manualMTU int) (IPsecReport, error) {
	if ctx == nil || inspector == nil || runner == nil {
		return IPsecReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_ipsec", string(link.ID), "ipsec", "IPsec diagnostic observer requires context, backend and read-only probe")
	}
	if err := ctx.Err(); err != nil {
		return IPsecReport{}, err
	}
	if link.Backend != domain.BackendIPsec {
		return IPsecReport{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_ipsec", string(link.ID), "ipsec", "diagnose_ipsec only accepts IPsec Links")
	}
	overhead, err := ipsecbackend.DiagnosticOverhead(link)
	if err != nil {
		return IPsecReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_ipsec", string(link.ID), "ipsec", "invalid IPsec diagnostic profile")
	}
	state, err := inspector.DiagnosticState(ctx, link)
	if err != nil {
		return IPsecReport{}, stlerr.New(stlerr.CodeInspect, "diagnose_ipsec", string(link.ID), "ipsec", "cannot verify private strongSwan connection and XFRM interface")
	}
	p, err := ipsecbackend.NewProfile(link)
	if err != nil || state.Interface != p.InterfaceName || state.XFRMID != p.InterfaceID ||
		state.IfIndex <= 0 || !state.ConnectionConfigured {
		return IPsecReport{}, stlerr.New(stlerr.CodeInspect, "diagnose_ipsec", string(link.ID), "ipsec", "IPsec kernel/daemon identity does not match desired Link")
	}
	if !state.SecurityAssociationPresent {
		return IPsecReport{}, stlerr.New(stlerr.CodeInspect, "diagnose_ipsec", string(link.ID), "ipsec",
			"no matching IPsec security association is installed; Link Address probes must not proceed")
	}
	report, err := ObserveLinux(ctx, link, LinuxProbeOptions{
		Runner: runner, Interface: state.Interface, ExpectedIfIndex: state.IfIndex,
		BackendOverhead: overhead, ManualMTU: manualMTU,
	})
	if err != nil {
		if ctx.Err() != nil {
			return IPsecReport{}, ctx.Err()
		}
		return IPsecReport{}, stlerr.New(stlerr.CodeInspect, "diagnose_ipsec", string(link.ID), "ipsec",
			"bounded IPsec Link Address probe could not establish measurements")
	}
	return IPsecReport{Report: report, Backend: domain.BackendIPsec, State: state}, nil
}

func (r IPsecReport) Summary() string {
	return fmt.Sprintf("%s; admitted IPsec/XFRM %s, SA observed; overhead budget is conservative, not an exact negotiated transform",
		r.Report.Summary(), r.State.Interface)
}
