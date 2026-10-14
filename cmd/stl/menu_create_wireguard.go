package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func askPort(p createPrompts, question string, optional bool) (uint16, error) {
	value, err := p.ask(question)
	if err != nil {
		return 0, err
	}
	if value == "" && optional {
		return 0, nil
	}
	raw, err := strconv.ParseUint(value, 10, 16)
	if err != nil || raw == 0 {
		return 0, fmt.Errorf("invalid WireGuard UDP port")
	}
	return uint16(raw), nil
}
func askKeepalive(p createPrompts, question string) (uint16, error) {
	value, err := p.ask(question)
	if err != nil {
		return 0, err
	}
	if value == "" {
		return 0, nil
	}
	raw, err := strconv.ParseUint(value, 10, 16)
	if err != nil || raw > 65535 {
		return 0, fmt.Errorf("invalid WireGuard keepalive")
	}
	return uint16(raw), nil
}

// The guided WireGuard sender assembles the same versioned public request
// used by the CLI; it never owns credential generation or backend mutation.
// New credentials appear only after a fresh exact-Link-ID confirmation, and
// are delivered to a deliberately chosen owner-private 0600 handoff file.
func menuCreateWireGuard(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	fmt.Fprintln(out, "\nCreate WireGuard (authenticated/encrypted UDP) — SENSITIVE Quick Link.")
	fmt.Fprintln(out, "Recipient key will be generated for a one-time 0600 handoff file; verify the intended peer out-of-band.")
	peer, err := askPeerUnderlay(p)
	if err != nil {
		return p.failed(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := createRunner(options)
	route, err := (linux.RouteResolver{Runner: runner}).Resolve(ctx, peer)
	if err != nil || !route.Source.Is4() || !route.Source.IsGlobalUnicast() || route.Source.IsLoopback() || route.Source == peer {
		fmt.Fprintln(errOut, "No reliable IPv4 underlay/source route was found; nothing applied.")
		return 4
	}
	fmt.Fprintf(out, "THIS server's connection IPv4 (automatic from route): %s; no need to type it.\n", route.Source)
	root := createStateRoot(options)
	if root == "" {
		fmt.Fprintln(errOut, "Local state root unavailable; nothing applied.")
		return 1
	}
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot inspect existing local Link reservations; nothing applied.")
		return 1
	}
	addresses, err := askLinkAddresses(p, runner, snapshot, peer, false)
	if err != nil {
		return p.failed(err)
	}
	fmt.Fprintln(out, "WireGuard communicates over UDP. Open the ports below on the corresponding server.")
	localPort, err := askPortDefault(p, "UDP port on THIS server [51820]: ", 51820)
	if err != nil {
		return p.failed(err)
	}
	peerPort, err := askPortDefault(p, "UDP port on OTHER server [51820]: ", 51820)
	if err != nil {
		return p.failed(err)
	}
	localKeep, peerKeep := uint16(25), uint16(25)
	advanced, err := p.yesNo("Change advanced keepalive or local MTU settings? [y/N]: ")
	if err != nil {
		return p.failed(err)
	}
	if advanced {
		localKeep, err = askKeepalive(p, "Keepalive seconds on THIS server [Enter=off]: ")
		if err != nil {
			return p.failed(err)
		}
		peerKeep, err = askKeepalive(p, "Keepalive seconds on OTHER server [Enter=off]: ")
		if err != nil {
			return p.failed(err)
		}
	}
	idMaker := domain.NewLinkID
	if options != nil && options.createLinkID != nil {
		idMaker = options.createLinkID
	}
	id, err := idMaker()
	if err != nil || id.Validate() != nil {
		fmt.Fprintln(errOut, "Cannot generate stable Link ID; nothing applied.")
		return 1
	}
	if _, already := snapshot.Find(id); already {
		fmt.Fprintln(errOut, "Generated Link ID already exists; nothing applied.")
		return 2
	}
	path, err := askPrivateHandoffPath(p, options, id)
	if err != nil {
		return p.failed(err)
	}
	request := wireGuardSenderRequestV1{SchemaVersion: 1, LinkID: id,
		Underlay:   desiredUnderlayV1{Local: route.Source, Peer: peer},
		Addresses:  desiredLinkAddressesV1{Local: addresses.Local, Peer: addresses.Peer},
		ListenPort: localPort, PeerPort: peerPort, LocalKeepalive: localKeep, PeerKeepalive: peerKeep}
	// v2 sets an endpoint-local MTU policy. Neither a measured PMTU nor
	// the local policy is copied to the receiver Setup Link.
	mtu := domain.MTUPolicy{Mode: domain.MTUAuto}
	if advanced {
		if err := chooseManagedMTU(p, &mtu); err != nil {
			return p.failed(err)
		}
	}
	request.SchemaVersion = managedMTUSchemaVersion
	payload, err := json.Marshal(wireGuardSenderRequestV2{
		wireGuardSenderRequestV1: request,
		MTU:                      mtu,
	})
	if err != nil {
		fmt.Fprintln(errOut, "Cannot encode WireGuard creator request; nothing applied.")
		return 1
	}
	fmt.Fprintln(out, "\nReview WireGuard tunnel — no changes yet:")
	fmt.Fprintf(out, "  WireGuard/UDP | THIS %s -> OTHER %s via %s\n", route.Source, peer, safeMenuText(route.Device))
	fmt.Fprintf(out, "  Tunnel IPs THIS %s | OTHER %s | UDP listen ports THIS/OTHER %d/%d | keepalive %d/%d\n",
		request.Addresses.Local, request.Addresses.Peer, localPort, peerPort, localKeep, peerKeep)
	fmt.Fprintf(out, "  Save protected peer-setup file: %s\n", path)
	fmt.Fprintln(out, "After confirmation: generate two unique WireGuard keys; publish protected receiver offer; ensure local interface via the canonical Engine.")
	fmt.Fprintln(out, "The receiver setup URL is a credential, not sender authentication; deliver out-of-band over a trusted channel.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish fresh terminal confirmation; nothing applied.")
		return 2
	}
	answer, err := p.ask("Create the encrypted tunnel and private handoff file? Type YES to confirm (Enter=no): ")
	if err != nil {
		return p.failed(err)
	}
	if !strings.EqualFold(answer, "yes") {
		fmt.Fprintln(out, "WireGuard creation cancelled; no changes applied.")
		return 0
	}
	code := linkCreateWireGuardCommand([]string{"create-wireguard", "--stdin", "--output", path}, bytes.NewReader(payload), out, errOut, options)
	if code != 0 {
		fmt.Fprintln(errOut, "If a SENSITIVE file was published, retain it privately for explicit resume/reconciliation.")
		return code
	}
	fmt.Fprintf(out, "Saved protected Setup Link: %s\n", path)
	fmt.Fprintln(out, "Transfer this file privately to the OTHER server, then use menu -> Import -> Protected link.")
	fmt.Fprintln(out, "If you want to reuse the handoff later, keep this exact file; STL does not regenerate a lost receiver key.")
	fmt.Fprintln(out, "Verify real WireGuard handshake and Link Address traffic after both sides are activated.")
	return 0
}
