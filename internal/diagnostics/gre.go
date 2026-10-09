//go:build linux

package diagnostics

import (
	"context"
	"fmt"

	grebackend "github.com/ach1992/simple-tun-link/internal/backend/gre"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// GREInspector is the read-only diagnostic seam provided by the GRE backend.
// Its production implementation verifies Link ownership/ifindex before
// exposing counters. This seam also keeps test probes nonprivileged.
type GREInspector interface {
	Capability(context.Context, domain.Link) (linux.CapabilityStatus, error)
	DiagnosticState(context.Context, domain.Link) (grebackend.DiagnosticState, error)
}

// GREReport extends the backend-neutral v1 report with read-only counters.
// Embedding Report preserves top-level schema_version, link_id, mtu, quality.
type GREReport struct {
	Report
	Backend domain.Backend             `json:"backend"`
	State   grebackend.DiagnosticState `json:"state"`
}

// ObserveGRE refuses to measure without a currently validated, owned GRE
// interface. It never calls Ensure/Apply/Remove or changes the suggested MTU.
func ObserveGRE(ctx context.Context, link domain.Link, inspector GREInspector, runner linux.Runner, manualMTU int) (GREReport, error) {
	if ctx == nil {
		return GREReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_gre", "", "", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return GREReport{}, err
	}
	if link.Backend != domain.BackendGRE {
		return GREReport{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_gre", string(link.ID), string(link.Backend), "GRE diagnostics only accepts GRE Links")
	}
	if inspector == nil || runner == nil {
		return GREReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_gre", string(link.ID), string(link.Backend), "GRE diagnostics dependencies are required")
	}
	// Overhead includes all selected GRE/UDP/key/checksum/sequence bytes.
	overhead, err := grebackend.Overhead(link)
	if err != nil {
		return GREReport{}, stlerr.Wrap(stlerr.CodeInvalid, "diagnose_gre", string(link.ID), string(link.Backend), "invalid GRE Link configuration", err)
	}
	capability, err := inspector.Capability(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return GREReport{}, ctx.Err()
		}
		return GREReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_gre", string(link.ID), string(link.Backend), "cannot inspect GRE capability", err)
	}
	if !capability.Available {
		return GREReport{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_gre", string(link.ID), string(link.Backend), "GRE capability is not available")
	}
	state, err := inspector.DiagnosticState(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return GREReport{}, ctx.Err()
		}
		return GREReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_gre", string(link.ID), string(link.Backend), "cannot verify GRE operational state and counters", err)
	}
	expectedName, err := grebackend.InterfaceName(link.ID)
	if err != nil {
		return GREReport{}, err
	}
	if state.Interface != expectedName || state.IfIndex <= 0 || state.Encapsulation != link.Encapsulation {
		return GREReport{}, stlerr.New(stlerr.CodeInspect, "diagnose_gre", string(link.ID), string(link.Backend), "GRE diagnostic identity changed")
	}
	measurements, err := ObserveLinux(ctx, link, LinuxProbeOptions{
		Runner: runner, Interface: state.Interface, ExpectedIfIndex: state.IfIndex,
		BackendOverhead: overhead, ManualMTU: manualMTU,
	})
	if err != nil {
		if ctx.Err() != nil {
			return GREReport{}, ctx.Err()
		}
		return GREReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_gre", string(link.ID), string(link.Backend), "GRE Link measurement unavailable", err)
	}
	return GREReport{Report: measurements, Backend: domain.BackendGRE, State: state}, nil
}

// Summary reflects exactly the measured report, not an optimistic estimate of
// Link quality or automatically applied MTU.
func (r GREReport) Summary() string {
	return fmt.Sprintf("%s; GRE interface %s RX %d packets / TX %d packets",
		r.Report.Summary(), r.State.Interface, r.State.RXPackets, r.State.TXPackets)
}
