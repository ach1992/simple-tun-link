package main

import (
	"context"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// linkDiagnostic is the one shared, read-only measurement projection used by
// both per-Link diagnose and the all-Link operator health center. It contains
// no raw command stdout, credentials, display name or foreign interface dump.
type linkDiagnostic struct {
	report       interface{ Summary() string }
	mtu          diagnostics.MTUResult
	quality      diagnostics.QualityResult
	rx, tx       uint64
	counterUnit  string
	handshakeUTC int64
}

// inspectLinkDiagnostic has no mutation-capable backend method in its
// interface. Backends must prove Link identity before the bounded probe
// algorithm can emit traffic toward the requested peer Link Address.
func inspectLinkDiagnostic(ctx context.Context, link domain.Link, options runtimeOptions, manualMTU int) (linkDiagnostic, error) {
	if err := ctx.Err(); err != nil {
		return linkDiagnostic{}, err
	}
	if link.Backend == domain.BackendIPsec {
		err := stlerr.New(stlerr.CodeUnsupported, "link_diagnose", string(link.ID), string(link.Backend),
			"IPsec runtime is not registered; no active Link diagnosis is available")
		err.ReasonCode = "ipsec_runtime_not_registered"
		err.NextStep = "Use GRE/IPIP/WireGuard for active Links; qualify exclusive strongSwan ownership before any IPsec activation."
		return linkDiagnostic{}, err
	}
	var selected backend.Backend
	for _, impl := range options.backends {
		if impl != nil && impl.Kind() == link.Backend {
			selected = impl
			break
		}
	}
	if selected == nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeUnsupported, "link_diagnose", string(link.ID), string(link.Backend),
			"diagnostic backend is unavailable")
	}
	runner := options.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	switch link.Backend {
	case domain.BackendGRE:
		inspector, ok := selected.(diagnostics.GREInspector)
		if !ok {
			return linkDiagnostic{}, stlerr.New(stlerr.CodeUnsupported, "link_diagnose", string(link.ID), string(link.Backend),
				"GRE diagnostic backend is unavailable")
		}
		m, err := diagnostics.ObserveGRE(ctx, link, inspector, runner, manualMTU)
		if err != nil {
			return linkDiagnostic{}, err
		}
		return linkDiagnostic{report: m, mtu: m.MTU, quality: m.Quality,
			rx: m.State.RXPackets, tx: m.State.TXPackets, counterUnit: "packets"}, nil
	case domain.BackendIPIP:
		inspector, ok := selected.(diagnostics.IPIPInspector)
		if !ok {
			return linkDiagnostic{}, stlerr.New(stlerr.CodeUnsupported, "link_diagnose", string(link.ID), string(link.Backend),
				"IPIP diagnostic backend is unavailable")
		}
		m, err := diagnostics.ObserveIPIP(ctx, link, inspector, runner, manualMTU)
		if err != nil {
			return linkDiagnostic{}, err
		}
		return linkDiagnostic{report: m, mtu: m.MTU, quality: m.Quality,
			rx: m.State.RXPackets, tx: m.State.TXPackets, counterUnit: "packets"}, nil
	case domain.BackendWireGuard:
		inspector, ok := selected.(diagnostics.WireGuardInspector)
		if !ok {
			return linkDiagnostic{}, stlerr.New(stlerr.CodeUnsupported, "link_diagnose", string(link.ID), string(link.Backend),
				"WireGuard diagnostic backend is unavailable")
		}
		m, err := diagnostics.ObserveWireGuard(ctx, link, inspector, runner, manualMTU)
		if err != nil {
			return linkDiagnostic{}, err
		}
		return linkDiagnostic{report: m, mtu: m.MTU, quality: m.Quality,
			rx: m.State.RXBytes, tx: m.State.TXBytes, counterUnit: "bytes",
			handshakeUTC: m.State.LatestHandshakeUnix}, nil
	default:
		return linkDiagnostic{}, stlerr.New(stlerr.CodeUnsupported, "link_diagnose", string(link.ID), string(link.Backend),
			"active diagnosis is not implemented for this backend")
	}
}
