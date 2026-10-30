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

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Collect public topology through the menu. Key generation, private peer
// handoff and host mutations remain in the canonical Engine and QUIC CLI.
func menuCreateQUIC(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	return menuCreateQUICWithExecutable(input, reader, out, errOut, opts, quic.DefaultExecutable)
}

// The internal executable parameter lets isolated PTY tests inspect a pinned test
// executable with the production identity guard, without installing a helper
// or changing the global /usr/local/libexec/stl path.
func menuCreateQUICWithExecutable(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	opts *runtimeOptions, companion string) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	menuSection(out, "Create / WireGuard over QUIC (mTLS)")
	menuNotice(out, "INFO", "Kernel WireGuard ingress is guarded; the remote peer connects over authenticated QUIC/UDP with TLS and per-Link credentials.")
	if _, err := quic.InspectPinnedHysteria(companion); err != nil {
		menuNotice(out, "WARNING", "Approved Hysteria v2.13.0 companion is missing or untrusted.")
		menuProse(out, "Place the exact official hysteria-linux-ARCH binary beside the official one-file STL installer and rerun that installer with --with-quic.")
		return 4
	}
	peer, err := askPeerUnderlay(p)
	if err != nil {
		return p.failed(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := createRunner(opts)
	route, err := (linux.RouteResolver{Runner: runner}).Resolve(ctx, peer)
	if err != nil || !route.Source.Is4() || !route.Source.IsGlobalUnicast() || route.Source == peer {
		menuNotice(out, "WARNING", "No verified local IPv4 route to the remote peer.")
		return 4
	}
	root := createStateRoot(opts)
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot inspect Link reservations.")
		return 1
	}
	addresses, err := askLinkAddresses(p, runner, snapshot, peer, false)
	if err != nil {
		return p.failed(err)
	}
	menuSection(out, "QUIC roles / which side accepts public TLS?")
	menuOption(out, "1", "Listen QUIC", "THIS server accepts the selected UDP port")
	menuOption(out, "2", "Dial QUIC", "OTHER server accepts the UDP port")
	choice, err := p.ask("Choose [1]: ")
	if err != nil {
		return p.failed(err)
	}
	role := "listen"
	if choice == "2" {
		role = "dial"
	} else if choice != "" && choice != "1" {
		menuNotice(out, "WARNING", "Choose 1 or 2.")
		return 2
	}
	obfuscation, err := askQUICObfuscation(p)
	if err != nil {
		return p.failed(err)
	}
	udp, err := askPortDefault(p, "Public QUIC/TLS UDP port [443]: ", 443)
	if err != nil {
		return p.failed(err)
	}
	localWG, err := askPortDefault(p, "Kernel WG UDP port on THIS server [51821]: ", 51821)
	if err != nil {
		return p.failed(err)
	}
	peerWG, err := askPortDefault(p, "Kernel WG UDP port on OTHER server [51822]: ", 51822)
	if err != nil {
		return p.failed(err)
	}
	forward := uint16(0)
	remoteForward := uint16(0)
	if role == "listen" {
		remoteForward, err = askPortDefault(p, "OTHER server's private loopback forwarding UDP port [53001]: ", 53001)
	} else {
		forward, err = askPortDefault(p, "THIS server's private loopback forwarding UDP port [53001]: ", 53001)
	}
	if err != nil {
		return p.failed(err)
	}
	tlsName, err := p.ask("TLS certificate SAN (Enter = listener IP; or exact DNS name): ")
	if err != nil {
		return p.failed(err)
	}
	if len(tlsName) > 253 || strings.ContainsAny(tlsName, " \t\r\n/\\") {
		menuNotice(out, "WARNING", "Specify one verifiable IP or DNS name without paths.")
		return 2
	}
	idMaker := domain.NewLinkID
	if opts != nil && opts.createLinkID != nil {
		idMaker = opts.createLinkID
	}
	id, err := idMaker()
	if err != nil || id.Validate() != nil {
		menuNotice(out, "WARNING", "Cannot allocate Link identity.")
		return 1
	}
	if _, exists := snapshot.Find(id); exists {
		menuNotice(out, "WARNING", "Generated Link ID conflicts.")
		return 2
	}
	_, err = askPrivateHandoffPath(p, opts, id)
	if err != nil {
		return p.failed(err)
	}
	request := quicCreateRequest{SchemaVersion: 2, Obfuscation: publicQUICObfuscation(obfuscation), LinkID: id, Underlay: desiredUnderlayV1{Local: route.Source, Peer: peer},
		Addresses:  desiredLinkAddressesV1{Local: addresses.Local, Peer: addresses.Peer},
		ListenPort: localWG, PeerPort: peerWG, Role: role, UDPPort: udp,
		LocalKeepalive: 25, PeerKeepalive: 25,
		LocalForwardUDPPort: forward, RemoteForwardUDPPort: remoteForward, TLSServerName: tlsName}
	preview, err := json.Marshal(request)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot encode public QUIC configuration.")
		return 1
	}
	menuScreen(out, "Review / confirm WireGuard over QUIC")
	menuField(out, "Backend", "WireGuard / QUIC + TLS")
	menuField(out, "This server", route.Source.String()+" ("+role+")")
	menuField(out, "Other server", peer.String())
	menuField(out, "TLS UDP port", strconv.Itoa(int(udp)))
	menuField(out, "QUIC obfuscation", publicQUICObfuscation(obfuscation))
	menuField(out, "Kernel WG UDP", fmt.Sprintf("this %d / peer %d", localWG, peerWG))
	menuField(out, "Private IPs", addresses.Local.String()+" <-> "+addresses.Peer.String())
	menuField(out, "Private MTU", "Auto: conservative 1280-byte start; peer PMTU remains unmeasured")
	menuField(out, "QUIC forwarding UDP", fmt.Sprintf("this %d / peer %d", forward, remoteForward))
	menuNotice(out, "WARNING", "Creates scoped nft ingress guard, WG interface, QUIC helper, mTLS secrets and a private peer handoff.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		return 2
	}
	answer, err := p.askAction("YES", "Create QUIC Link and private receiver handoff? Type YES (Enter=cancel): ")
	if err != nil {
		return p.failed(err)
	}
	if !strings.EqualFold(answer, "yes") {
		menuNotice(out, "INFO", "Creation cancelled.")
		return 0
	}
	path, err := prepareProtectedMenuHandoff(opts, id)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot safely prepare private receiver handoff.")
		return 1
	}
	menuScreen(out, "Applying / QUIC+WireGuard")
	code := linkQUICCommand([]string{"create-quic", "--stdin", "--output", path},
		bytes.NewReader(preview), out, errOut, opts)
	if code != 0 {
		menuNotice(out, "WARNING", "Preserve the original peer handoff and reconcile State and owned host resources; do not generate replacement keys.")
		return code
	}
	menuScreen(out, "QUIC Link / local activation complete")
	menuNotice(out, "OK", "Local QUIC helper and kernel WG were ensured; verify actual peer handshake and private traffic separately.")
	menuShowNewProtectedHandoff(input, out, opts, id)
	menuProse(out, "On the peer: transfer the sensitive offer privately, run stl link preview-quic --stdin and then stl link import-quic --stdin --confirm SHA256; verify private traffic.")
	return 0
}

// The menu collects the same typed choice as creator schema v2; credentials
// remain generated and staged by the canonical QUIC lifecycle.
func askQUICObfuscation(p createPrompts) (string, error) {
	menuSection(p.out, "QUIC packet representation")
	menuOption(p.out, "1", "Plain", "standard QUIC packets (default)")
	menuOption(p.out, "2", "Salamander", "shared per-Link obfuscation; TLS authentication remains required")
	answer, err := p.ask("QUIC obfuscation [1]: ")
	if err != nil {
		return "", err
	}
	switch answer {
	case "", "1":
		return "", nil
	case "2":
		return "salamander", nil
	default:
		return "", fmt.Errorf("choose QUIC obfuscation 1 or 2")
	}
}
