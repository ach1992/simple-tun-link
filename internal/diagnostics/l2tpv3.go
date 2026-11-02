//go:build linux

package diagnostics

import (
	"context"
	"fmt"

	l2tpbackend "github.com/ach1992/simple-tun-link/internal/backend/l2tpv3"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// L2TPv3Inspector is the read-only diagnostic seam provided by the L2TPv3 backend.
// Its production implementation verifies Link ownership/ifindex before
// exposing counters. This seam also keeps test probes nonprivileged.
type L2TPv3Inspector interface {
	Capability(context.Context, domain.Link) (linux.CapabilityStatus, error)
	DiagnosticState(context.Context, domain.Link) (l2tpbackend.DiagnosticState, error)
}

// L2TPv3Report extends the backend-neutral v1 report with read-only counters.
// Embedding Report preserves top-level schema_version, link_id, mtu, quality.
type L2TPv3Report struct {
	Report
	Backend domain.Backend              `json:"backend"`
	State   l2tpbackend.DiagnosticState `json:"state"`
}

// ObserveL2TPv3 refuses to measure without a currently validated, owned L2TPv3
// interface. It never calls Ensure/Apply/Remove or changes the suggested MTU.
func ObserveL2TPv3(ctx context.Context, link domain.Link, inspector L2TPv3Inspector, runner linux.Runner, manualMTU int) (L2TPv3Report, error) {
	if ctx == nil {
		return L2TPv3Report{}, stlerr.New(stlerr.CodeInvalid, "diagnose_l2tpv3", "", "", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return L2TPv3Report{}, err
	}
	if link.Backend != domain.BackendL2TPv3 {
		return L2TPv3Report{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_l2tpv3", string(link.ID), string(link.Backend), "L2TPv3 diagnostics only accepts L2TPv3 Links")
	}
	if inspector == nil || runner == nil {
		return L2TPv3Report{}, stlerr.New(stlerr.CodeInvalid, "diagnose_l2tpv3", string(link.ID), string(link.Backend), "L2TPv3 diagnostics dependencies are required")
	}
	// Overhead includes the selected L2TPv3/UDP/GUE transport bytes.
	overhead, err := l2tpbackend.Overhead(link)
	if err != nil {
		return L2TPv3Report{}, stlerr.Wrap(stlerr.CodeInvalid, "diagnose_l2tpv3", string(link.ID), string(link.Backend), "invalid L2TPv3 Link configuration", err)
	}
	capability, err := inspector.Capability(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return L2TPv3Report{}, ctx.Err()
		}
		return L2TPv3Report{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_l2tpv3", string(link.ID), string(link.Backend), "cannot inspect L2TPv3 capability", err)
	}
	if !capability.Available {
		unsupported := stlerr.New(stlerr.CodeUnsupported, "diagnose_l2tpv3", string(link.ID), string(link.Backend), "L2TPv3 capability is not available")
		if capability.ReasonCode == "kernel_module_not_loaded" {
			unsupported.ReasonCode = capability.ReasonCode
			unsupported.NextStep = "Check module availability for this kernel; load only with operator authorization and retry observation."
		}
		return L2TPv3Report{}, unsupported
	}
	state, err := inspector.DiagnosticState(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return L2TPv3Report{}, ctx.Err()
		}
		wrapped := stlerr.Wrap(stlerr.CodeInspect, "diagnose_l2tpv3", string(link.ID), string(link.Backend),
			"cannot verify L2TPv3 operational state and counters", err)
		if known := stlerr.Public(err); known.ReasonCode == "kernel_module_not_loaded" {
			wrapped.ReasonCode, wrapped.NextStep = known.ReasonCode, known.NextStep
		}
		return L2TPv3Report{}, wrapped
	}
	expectedName, err := l2tpbackend.InterfaceName(link.ID)
	if err != nil {
		return L2TPv3Report{}, err
	}
	if state.Interface != expectedName || state.IfIndex <= 0 || state.Encapsulation != link.Encapsulation {
		return L2TPv3Report{}, stlerr.New(stlerr.CodeInspect, "diagnose_l2tpv3", string(link.ID), string(link.Backend), "L2TPv3 diagnostic identity changed")
	}
	measurements, err := ObserveLinux(ctx, link, LinuxProbeOptions{
		Runner: runner, Interface: state.Interface, ExpectedIfIndex: state.IfIndex,
		BackendOverhead: overhead, ManualMTU: manualMTU,
	})
	if err != nil {
		if ctx.Err() != nil {
			return L2TPv3Report{}, ctx.Err()
		}
		return L2TPv3Report{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_l2tpv3", string(link.ID), string(link.Backend), "L2TPv3 Link measurement unavailable", err)
	}
	return L2TPv3Report{Report: measurements, Backend: domain.BackendL2TPv3, State: state}, nil
}

// Summary reflects exactly the measured report, not an optimistic estimate of
// Link quality or automatically applied MTU.
func (r L2TPv3Report) Summary() string {
	return fmt.Sprintf("%s; L2TPv3 interface %s RX %d packets / TX %d packets",
		r.Report.Summary(), r.State.Interface, r.State.RXPackets, r.State.TXPackets)
}
