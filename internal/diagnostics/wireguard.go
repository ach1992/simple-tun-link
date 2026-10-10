//go:build linux

package diagnostics

import (
	"context"
	"fmt"
	"time"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// WireGuardInspector is read-only: the backend verifies the owned interface,
// its public key identity, peer and listen configuration before returning
// public handshake/counter observations. It has no access to private keys.
type WireGuardInspector interface {
	Capability(context.Context, domain.Link) (linux.CapabilityStatus, error)
	DiagnosticState(context.Context, domain.Link) (wgbackend.DiagnosticState, error)
}

// WireGuardReport keeps the common v1 diagnostic envelope while adding
// identity-checked, secret-free WireGuard observations.
type WireGuardReport struct {
	Report
	Backend domain.Backend            `json:"backend"`
	State   wgbackend.DiagnosticState `json:"state"`
}

// ObserveWireGuard never configures, repairs or changes the Link MTU. It
// refuses to probe before verifying that the selected interface belongs to
// the requested Link and has the expected public WireGuard configuration.
func ObserveWireGuard(ctx context.Context, link domain.Link, inspector WireGuardInspector, runner linux.Runner, manualMTU int) (WireGuardReport, error) {
	if ctx == nil {
		return WireGuardReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_wireguard", "", "", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return WireGuardReport{}, err
	}
	if link.Backend != domain.BackendWireGuard {
		return WireGuardReport{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_wireguard", string(link.ID), string(link.Backend), "WireGuard diagnostics only accepts WireGuard Links")
	}
	if inspector == nil || runner == nil {
		return WireGuardReport{}, stlerr.New(stlerr.CodeInvalid, "diagnose_wireguard", string(link.ID), string(link.Backend), "WireGuard diagnostic dependencies are required")
	}
	overhead, err := wgbackend.Overhead(link)
	if err != nil {
		return WireGuardReport{}, stlerr.Wrap(stlerr.CodeInvalid, "diagnose_wireguard", string(link.ID), string(link.Backend), "invalid WireGuard Link configuration", err)
	}
	capability, err := inspector.Capability(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return WireGuardReport{}, ctx.Err()
		}
		return WireGuardReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_wireguard", string(link.ID), string(link.Backend), "cannot inspect WireGuard capability", err)
	}
	if !capability.Available {
		return WireGuardReport{}, stlerr.New(stlerr.CodeUnsupported, "diagnose_wireguard", string(link.ID), string(link.Backend), "WireGuard capability is not available")
	}
	state, err := inspector.DiagnosticState(ctx, link)
	if err != nil {
		if ctx.Err() != nil {
			return WireGuardReport{}, ctx.Err()
		}
		return WireGuardReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_wireguard", string(link.ID), string(link.Backend), "cannot verify WireGuard operational state and counters", err)
	}
	expectedName, err := wgbackend.InterfaceName(link.ID)
	if err != nil {
		return WireGuardReport{}, err
	}
	if state.Interface != expectedName || state.IfIndex <= 0 ||
		state.LocalPublicKey != link.WireGuard.LocalPublicKey ||
		state.PeerPublicKey != link.WireGuard.PeerPublicKey ||
		state.ListenPort != link.WireGuard.ListenPort ||
		state.LatestHandshakeUnix < 0 {
		return WireGuardReport{}, stlerr.New(stlerr.CodeInspect, "diagnose_wireguard", string(link.ID), string(link.Backend), "WireGuard diagnostic identity changed")
	}
	measurements, err := ObserveLinux(ctx, link, LinuxProbeOptions{
		Runner: runner, Interface: state.Interface, ExpectedIfIndex: state.IfIndex,
		BackendOverhead: overhead, ManualMTU: manualMTU,
	})
	if err != nil {
		if ctx.Err() != nil {
			return WireGuardReport{}, ctx.Err()
		}
		return WireGuardReport{}, stlerr.Wrap(stlerr.CodeInspect, "diagnose_wireguard", string(link.ID), string(link.Backend), "WireGuard Link measurement unavailable", err)
	}
	return WireGuardReport{Report: measurements, Backend: domain.BackendWireGuard, State: state}, nil
}

func (r WireGuardReport) Summary() string {
	handshake := "no handshake observed at pre-probe inspection"
	if r.State.LatestHandshakeUnix > 0 {
		handshake = "last observed handshake " + time.Unix(r.State.LatestHandshakeUnix, 0).UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("%s; WireGuard interface %s RX %d bytes / TX %d bytes; %s",
		r.Report.Summary(), r.State.Interface, r.State.RXBytes, r.State.TXBytes, handshake)
}
