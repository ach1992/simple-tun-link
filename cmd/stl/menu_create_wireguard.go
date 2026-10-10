package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strconv"
	"time"
	"unicode"

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
	peerText, err := p.ask("Peer underlay IPv4 address: ")
	if err != nil {
		return p.failed(err)
	}
	peer, err := netip.ParseAddr(peerText)
	if err != nil || !peer.Is4() || !peer.IsGlobalUnicast() || peer.IsLoopback() || peer.IsLinkLocalUnicast() {
		return p.failed(fmt.Errorf("invalid peer IPv4"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := createRunner(options)
	route, err := (linux.RouteResolver{Runner: runner}).Resolve(ctx, peer)
	if err != nil || !route.Source.Is4() || !route.Source.IsGlobalUnicast() || route.Source.IsLoopback() || route.Source == peer {
		fmt.Fprintln(errOut, "No reliable IPv4 underlay/source route was found; nothing applied.")
		return 4
	}
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
	proposals, err := domain.Private31Candidates()
	if err != nil {
		fmt.Fprintln(errOut, "Cannot prepare Link Address candidates; nothing applied.")
		return 1
	}
	live, err := inspectedAddressClaims(ctx, runner, proposals)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot inspect host Link Address collisions; nothing applied.")
		return 1
	}
	reserved := collectReservedLinkAddresses(snapshot, peer)
	suggested, hasSuggestion, err := domain.FreePrivate31(proposals, append(live, reserved...))
	if err != nil {
		fmt.Fprintln(errOut, "Cannot validate host reservations; nothing applied.")
		return 1
	}
	if hasSuggestion {
		fmt.Fprintf(out, "Suggested Link /31: %s (local host checked; peer host remains unverified)\n", suggested)
	}
	chosen, err := p.ask("RFC1918 Link /31 subnet (Enter=suggested): ")
	if err != nil {
		return p.failed(err)
	}
	prefix := suggested
	if chosen != "" {
		prefix, err = netip.ParsePrefix(chosen)
		if err != nil || domain.ValidatePrivate31(prefix) != nil {
			return p.failed(fmt.Errorf("invalid RFC1918 /31"))
		}
		occupied, e := inspectedAddressClaims(ctx, runner, []netip.Prefix{prefix})
		if e != nil {
			fmt.Fprintln(errOut, "Cannot inspect chosen subnet; nothing applied.")
			return 1
		}
		_, ok, e := domain.FreePrivate31([]netip.Prefix{prefix}, append(occupied, reserved...))
		if e != nil || !ok {
			fmt.Fprintln(errOut, "Chosen subnet conflicts with host/saved resources; nothing applied.")
			return 2
		}
	} else if !hasSuggestion {
		fmt.Fprintln(errOut, "No safe automatic /31 available; supply manual subnet.")
		return 2
	}
	second, err := p.yesNo("Use second /31 address locally? [y/N]: ")
	if err != nil {
		return p.failed(err)
	}
	localAddr, peerAddr := prefix.Addr(), prefix.Addr().Next()
	if second {
		localAddr, peerAddr = peerAddr, localAddr
	}
	localPort, err := askPort(p, "Local WireGuard listen UDP port (required): ", false)
	if err != nil {
		return p.failed(err)
	}
	peerPort, err := askPort(p, "Receiver WireGuard listen UDP port (required): ", false)
	if err != nil {
		return p.failed(err)
	}
	localKeep, err := askKeepalive(p, "Local keepalive seconds (Enter=off, 25 commonly used behind NAT): ")
	if err != nil {
		return p.failed(err)
	}
	peerKeep, err := askKeepalive(p, "Receiver keepalive seconds (Enter=off, 25 commonly used behind NAT): ")
	if err != nil {
		return p.failed(err)
	}
	path, err := p.ask("Absolute SENSITIVE handoff file path (parent owner-private 0700; file must not exist): ")
	if err != nil {
		return p.failed(err)
	}
	// Preview every byte of the path the operator is authorizing; never
	// truncate a consequential destination in safeMenuText below.
	if len(path) == 0 || len(path) > menuInputLimit || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return p.failed(fmt.Errorf("unsafe or unpreviewable SENSITIVE handoff path"))
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return p.failed(fmt.Errorf("unsafe control character in SENSITIVE handoff path"))
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
	request := wireGuardSenderRequestV1{SchemaVersion: 1, LinkID: id,
		Underlay:   desiredUnderlayV1{Local: route.Source, Peer: peer},
		Addresses:  desiredLinkAddressesV1{Local: netip.PrefixFrom(localAddr, 31), Peer: netip.PrefixFrom(peerAddr, 31)},
		ListenPort: localPort, PeerPort: peerPort, LocalKeepalive: localKeep, PeerKeepalive: peerKeep}
	payload, err := json.Marshal(request)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot encode WireGuard creator request; nothing applied.")
		return 1
	}
	fmt.Fprintln(out, "\nPREVIEW ONLY — no credentials, file or tunnel created yet")
	fmt.Fprintf(out, "Link ID %s | WireGuard/UDP; underlay %s -> %s via %s\n", id, route.Source, peer, safeMenuText(route.Device))
	fmt.Fprintf(out, "Link Addresses local %s peer %s | receive UDP ports %d/%d | keepalive %d/%d\n",
		request.Addresses.Local, request.Addresses.Peer, localPort, peerPort, localKeep, peerKeep)
	fmt.Fprintf(out, "Explicit SENSITIVE handoff destination: %s (must be trusted/private and nonexistent)\n", path)
	fmt.Fprintln(out, "After confirmation: generate two unique WireGuard keys; publish protected receiver offer; ensure local interface via the canonical Engine.")
	fmt.Fprintln(out, "The receiver setup URL is a credential, not sender authentication; deliver out-of-band over a trusted channel.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish fresh terminal confirmation; nothing applied.")
		return 2
	}
	answer, err := p.ask(fmt.Sprintf("To APPLY and generate sensitive handoff, type exact Link ID %s (Enter cancels): ", id))
	if err != nil {
		return p.failed(err)
	}
	if answer != string(id) {
		fmt.Fprintln(out, "WireGuard creation cancelled; no changes applied.")
		return 0
	}
	code := linkCreateWireGuardCommand([]string{"create-wireguard", "--stdin", "--output", path}, bytes.NewReader(payload), out, errOut, options)
	if code != 0 {
		fmt.Fprintln(errOut, "If a SENSITIVE file was published, retain it privately for explicit resume/reconciliation.")
		return code
	}
	fmt.Fprintln(out, "On the peer: stl link preview --stdin < PRIVATE_FILE; confirm, then stl link import --stdin --confirm DIGEST < PRIVATE_FILE")
	fmt.Fprintln(out, "Verify real WireGuard handshake and Link Address traffic after both sides are activated.")
	return 0
}
