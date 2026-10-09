//go:build linux

package diagnostics

import (
	"context"
	"fmt"

	ipipbackend "github.com/ach1992/simple-tun-link/internal/backend/ipip"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// IPIPInspector is the read-only diagnostic seam provided by the IPIP backend.
// Its production implementation verifies Link ownership/ifindex before
// exposing counters. This seam also keeps test probes nonprivileged.
type IPIPInspector interface {
	Capability(context.Context, domain.Link) (linux.CapabilityStatus, error)
	DiagnosticState(context.Context, domain.Link) (ipipbackend.DiagnosticState, error)
}

// IPIPReport extends the backend-neutral v1 report with read-only counters.
// Embedding Report preserves top-level schema_version, link_id, mtu, quality.
type IPIPReport struct {
	Report
	Backend domain.Backend              `json:"backend"`
	State   ipipbackend.DiagnosticState `json:"state"`
}

// ObserveIPIP refuses to measure without a currently validated, owned IPIP
// interface. It never calls Ensure/Apply/Remove or changes the suggested MTU.
func ObserveIPIP(ctx context.Context, link domain.Link, inspector IPIPInspector, runner linux.Runner, manualMTU int) (IPIPReport, error) {
	if ctx == nil {
		return IPIPReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_ipip", "", "", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return IPIPReport{}, err
	}
	if link.Backend != domain.BackendIPIP {
		return IPIPReport{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_ipip", string(link.ID), string(link.Backend), "IPIP diagnostics only accepts IPIP Links")
	}
	if inspector == nil || runner == nil {
		return IPIPReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_ipip", string(link.ID), string(link.Backend), "IPIP diagnostics dependencies are required")
	}
	// Overhead includes the selected IPIP/UDP/GUE transport bytes.
	overhead, err := ipipbackend.Overhead(link)
	if err != nil {
		return IPIPReport{}, stlerr.Wrap(stlerr.CodeInvalid, "diagnose_ipip", string(link.ID), string(link.Backend), "invalid IPIP Link configuration", err)
	}
	capability, err := inspector.Capability(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return IPIPReport{}, ctx.Err()
		}
		return IPIPReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_ipip", string(link.ID), string(link.Backend), "cannot inspect IPIP capability", err)
	}
	if !capability.Available {
		return IPIPReport{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_ipip", string(link.ID), string(link.Backend), "IPIP capability is not available")
	}
	state, err := inspector.DiagnosticState(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return IPIPReport{}, ctx.Err()
		}
		return IPIPReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_ipip", string(link.ID), string(link.Backend), "cannot verify IPIP operational state and counters", err)
	}
	expectedName, err := ipipbackend.InterfaceName(link.ID)
	if err != nil {
		return IPIPReport{}, err
	}
	if state.Interface != expectedName || state.IfIndex <= 0 || state.Encapsulation != link.Encapsulation {
		return IPIPReport{}, stlerr.New(stlerr.CodeInspect, "diagnose_ipip", string(link.ID), string(link.Backend), "IPIP diagnostic identity changed")
	}
	measurements, err := ObserveLinux(ctx, link, LinuxProbeOptions{
		Runner: runner, Interface: state.Interface, ExpectedIfIndex: state.IfIndex,
		BackendOverhead: overhead, ManualMTU: manualMTU,
	})
	if err != nil {
		if ctx.Err() != nil {
			return IPIPReport{}, ctx.Err()
		}
		return IPIPReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_ipip", string(link.ID), string(link.Backend), "IPIP Link measurement unavailable", err)
	}
	return IPIPReport{Report: measurements, Backend: domain.BackendIPIP, State: state}, nil
}

// Summary reflects exactly the measured report, not an optimistic estimate of
// Link quality or automatically applied MTU.
func (r IPIPReport) Summary() string {
	return fmt.Sprintf("%s; IPIP interface %s RX %d packets / TX %d packets",
		r.Report.Summary(), r.State.Interface, r.State.RXPackets, r.State.TXPackets)
}
