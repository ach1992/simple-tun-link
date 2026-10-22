package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type WSSLinkDiagnostics struct {
	SchemaVersion              int           `json:"schema_version"`
	LinkID                     domain.LinkID `json:"link_id"`
	Carrier                    string        `json:"carrier"`
	Role                       string        `json:"role"`
	WSSHelperActive            bool          `json:"wss_helper_active"`
	WGIngressGuardActive       bool          `json:"wg_ingress_guard_active"`
	KernelWireGuardPresent     bool          `json:"kernel_wireguard_present"`
	WireGuardHandshakeObserved bool          `json:"wireguard_handshake_observed"`
	LastHandshakeUnix          int64         `json:"last_handshake_unix,omitempty"`
	RXBytes                    uint64        `json:"rx_bytes"`
	TXBytes                    uint64        `json:"tx_bytes"`
	AuthenticationObservation  string        `json:"authentication_observation"`
	TrafficObservation         string        `json:"traffic_observation"`
}

func readR1PeerValue(ctx context.Context, runner linux.Runner, iface, field, expectedPeer string) ([]string, error) {
	out, err := runner.Run(ctx, "wg", "show", iface, field)
	if err != nil {
		return nil, fmt.Errorf("WireGuard %s inspection unavailable: %w", field, err)
	}
	parts := strings.Fields(strings.TrimSpace(string(out.Stdout)))
	if len(parts) != 2 || parts[0] != expectedPeer {
		return nil, fmt.Errorf("WireGuard peer identity or %s readback changed", field)
	}
	return parts, nil
}

func observeWSSLink(ctx context.Context, root string, runner linux.BoundedRunner, link domain.Link) (WSSLinkDiagnostics, error) {
	d := WSSLinkDiagnostics{SchemaVersion: 1, LinkID: link.ID, Carrier: "wss-tls",
		Role: link.WSS.Role, AuthenticationObservation: "not_observable_from_process_state",
		TrafficObservation: "not_tested_by_read_only_diagnostics"}
	if link.Backend != domain.BackendWireGuardWSS {
		return d, fmt.Errorf("not a WSS Link")
	}
	host := wss.Host{StateRoot: root, Runner: runner}
	var err error
	d.WGIngressGuardActive, err = host.GuardPresent(ctx, link)
	if err != nil {
		return d, fmt.Errorf("scoped WSS firewall guard inspection unavailable: %w", err)
	}
	d.WSSHelperActive, err = host.HelperPresent(ctx, link)
	if err != nil {
		return d, fmt.Errorf("WSS helper inspection unavailable: %w", err)
	}
	name, err := wgbackend.InterfaceName(link.ID)
	if err != nil {
		return d, err
	}
	current, err := runner.Run(ctx, "ip", "-json", "link", "show", "dev", name)
	if err != nil {
		return d, fmt.Errorf("cannot inspect kernel Link identity: %w", err)
	}
	// The canonical Engine's public desired-state identity is rechecked by
	// backend Ensure; this read-only command never adopts host resources.
	if len(current.Stdout) == 0 || current.Stdout[0] != '[' {
		return d, fmt.Errorf("WireGuard interface inventory incomplete")
	}
	d.KernelWireGuardPresent = true
	parts, err := readR1PeerValue(ctx, runner, name, "latest-handshakes", link.WireGuard.PeerPublicKey)
	if err != nil {
		return d, err
	}
	handshake, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || handshake < 0 || handshake > time.Now().Add(5*time.Minute).Unix() {
		return d, fmt.Errorf("invalid kernel WireGuard handshake timestamp")
	}
	d.WireGuardHandshakeObserved = handshake > 0
	d.LastHandshakeUnix = handshake
	out, err := runner.Run(ctx, "wg", "show", name, "transfer")
	if err != nil {
		return d, fmt.Errorf("WireGuard transfer inspection unavailable: %w", err)
	}
	fields := strings.Fields(string(out.Stdout))
	if len(fields) != 3 || fields[0] != link.WireGuard.PeerPublicKey {
		return d, fmt.Errorf("WireGuard transfer peer changed")
	}
	d.RXBytes, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return d, fmt.Errorf("invalid WireGuard RX counters")
	}
	d.TXBytes, err = strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return d, fmt.Errorf("invalid WireGuard TX counters")
	}
	if d.WireGuardHandshakeObserved {
		d.AuthenticationObservation = "kernel WireGuard peer authenticated; WSS mTLS not individually attested"
	}
	if d.RXBytes > 0 && d.TXBytes > 0 {
		d.TrafficObservation = "kernel WireGuard RX/TX bytes observed; application traffic not tested by this command"
	}
	return d, nil
}

func linkWSSDiagnoseCommand(args []string, out, errOut io.Writer, opts *runtimeOptions) int {
	if !(len(args) == 2 || len(args) == 3 && args[2] == "--json") {
		return readCommandError(out, errOut, false, stlerr.CodeInvalid, "diagnose_wss",
			"usage: stl link diagnose-wss <link-id> [--json]")
	}
	isJSON := len(args) == 3
	id := domain.LinkID(args[1])
	if id.Validate() != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "diagnose_wss", "invalid WSS Link ID")
	}
	if opts == nil {
		var err error
		opts, err = productionRuntimeOptions()
		if err != nil {
			return readCommandError(out, errOut, isJSON, stlerr.CodeState, "diagnose_wss", "runtime unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snapshot, err := state.NewFileStore(opts.stateRoot).Load(ctx)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeState, "diagnose_wss", "saved Link State unavailable")
	}
	record, ok := snapshot.Find(id)
	if !ok || record.Desired.Backend != domain.BackendWireGuardWSS {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInvalid, "diagnose_wss", "requested identity is not a saved WSS Link")
	}
	runner := opts.probeRunner
	if runner == nil {
		runner = linux.ExecRunner{}
	}
	bounded, ok := runner.(linux.BoundedRunner)
	if !ok {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInspect, "diagnose_wss", "bounded host inspection unavailable")
	}
	details, err := observeWSSLink(ctx, opts.stateRoot, bounded, record.Desired)
	if err != nil {
		return readCommandError(out, errOut, isJSON, stlerr.CodeInspect, "diagnose_wss", "cannot establish trustworthy WSS host observations")
	}
	if isJSON {
		if err := json.NewEncoder(out).Encode(details); err != nil {
			return 1
		}
	} else {
		fmt.Fprintf(out, "WSS Link %s (%s)\n", id, details.Role)
		fmt.Fprintf(out, "Helper active: %t, scoped WG ingress guard active: %t, kernel WG present: %t\n",
			details.WSSHelperActive, details.WGIngressGuardActive, details.KernelWireGuardPresent)
		fmt.Fprintf(out, "Kernel WG handshake observed: %t, last Unix timestamp: %d\n",
			details.WireGuardHandshakeObserved, details.LastHandshakeUnix)
		fmt.Fprintf(out, "WireGuard counters: RX %d bytes, TX %d bytes\n", details.RXBytes, details.TXBytes)
		fmt.Fprintf(out, "Authentication evidence: %s; traffic evidence: %s\n",
			details.AuthenticationObservation, details.TrafficObservation)
		fmt.Fprintln(out, "Helper active does not prove WSS authentication or actual application delivery; run explicit connectivity tests.")
	}
	return 0
}
