package main

import (
	"context"
	"strconv"
	"strings"

	core "github.com/ach1992/simple-tun-link/internal/backend"
	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// The same exact-origin WSS observer powers local Status and the common
// native-style five-ping command. Unlike a saved Link record, it verifies
// the host's scoped guard, helper, kernel identity, and per-peer counters.
// A superseded or crash-quarantined original MUST NOT be probed.
func trustedWSSObservation(ctx context.Context, link domain.Link, options runtimeOptions) (WSSLinkDiagnostics, linux.Runner, error) {
	if link.Backend != domain.BackendWireGuardWSS {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeInvalid, "wss_health", string(link.ID), "", "not a WSS Link")
	}
	snapshot, err := state.NewFileStore(options.stateRoot).Load(ctx)
	if err != nil {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeInspect, "wss_health", string(link.ID), "", "cannot verify saved WSS identity")
	}
	record, present := snapshot.Find(link.ID)
	if !present || record.Desired != link {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeConflict, "wss_health", string(link.ID), "", "saved WSS identity changed")
	}
	if record.WSSSupersededBy != "" {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeConflict, "wss_health", string(link.ID), "", "original WSS Link is superseded")
	}
	if _, pending := snapshot.FindWSSCrashOperation(link.ID); pending {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeConflict, "wss_health", string(link.ID), "", "WSS original has an unresolved crash journal")
	}
	ctx, err = core.WithWSSOrigin(ctx, record.WSSOrigin)
	if err != nil {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeInspect, "wss_health", string(link.ID), "", "original WSS ownership provenance unverified")
	}
	runner := options.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	bounded, ok := runner.(linux.BoundedRunner)
	if !ok {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeUnsupported, "wss_health", string(link.ID), "", "bounded WSS host observer unavailable")
	}
	observer := observeWSSLink
	if options.wssObserver != nil {
		observer = options.wssObserver
	}
	observed, err := observer(ctx, options.stateRoot, bounded, link)
	if err != nil {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeInspect, "wss_health", string(link.ID), "", "original WSS helper/guard/WireGuard identity unverified")
	}
	if !observed.KernelWireGuardPresent {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeInspect, "wss_health", string(link.ID), "", "kernel WSS WireGuard interface not verified")
	}
	iface, err := wgbackend.InterfaceName(link.ID)
	if err != nil {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeInvalid, "wss_health", string(link.ID), "", "invalid WSS interface identity")
	}
	// The separately admitted WSS observer attests the owned carrier and
	// exact configured PEER. Confirm our own kernel WG public identity and
	// per-Link UDP listen port too before declaring the interface local.
	// Neither value is a secret. No private-key read is attempted.
	public, publicErr := runner.Run(ctx, "wg", "show", iface, "public-key")
	port, portErr := runner.Run(ctx, "wg", "show", iface, "listen-port")
	parsedPort, parseErr := strconv.ParseUint(strings.TrimSpace(string(port.Stdout)), 10, 16)
	if publicErr != nil || portErr != nil || parseErr != nil ||
		strings.TrimSpace(string(public.Stdout)) != link.WireGuard.LocalPublicKey ||
		uint16(parsedPort) != link.WireGuard.ListenPort {
		return WSSLinkDiagnostics{}, nil, stlerr.New(stlerr.CodeInspect, "wss_health", string(link.ID), "", "kernel WireGuard local public identity or owned UDP port changed")
	}
	return observed, runner, nil
}

func inspectWSSQuality(ctx context.Context, link domain.Link, options runtimeOptions) (linkDiagnostic, error) {
	observed, runner, err := trustedWSSObservation(ctx, link, options)
	if err != nil {
		return linkDiagnostic{}, err
	}
	if !observed.WSSHelperActive || !observed.WGIngressGuardActive || !observed.KernelWireGuardPresent {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "wss_health", string(link.ID), "", "WSS helper, guard or private WireGuard interface is not ready")
	}
	iface, err := wgbackend.InterfaceName(link.ID)
	if err != nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInvalid, "wss_health", string(link.ID), "", "invalid WireGuard interface name")
	}
	// The selected interface owns the expected local address and private
	// route. No TCP/TLS/underlay path-MTU claim is made by these five echoes.
	report, err := diagnostics.ObservePrivateLinkQuality(ctx, link, iface, runner)
	if err != nil {
		return linkDiagnostic{}, stlerr.New(stlerr.CodeInspect, "wss_health", string(link.ID), "", "WSS private peer quality observation unverified")
	}
	return linkDiagnostic{report: report, mtu: report.MTU, quality: report.Quality,
		rx: observed.RXBytes, tx: observed.TXBytes, counterUnit: "bytes",
		handshakeUTC: observed.LastHandshakeUnix}, nil
}
