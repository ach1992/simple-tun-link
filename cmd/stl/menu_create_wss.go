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

	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Collect public topology through the menu. Key generation, private peer
// handoff and host mutations remain in the canonical Engine and WSS CLI.
func menuCreateWSS(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	menuSection(out, "Create / WireGuard over WSS (mTLS)")
	menuNotice(out, "INFO", "WireGuard UDP is scoped to loopback; the remote peer connects over authenticated WSS/TLS TCP.")
	companion := wss.Host{StateRoot: createStateRoot(opts)}
	if _, err := wss.InspectPinnedExecutableForOperator(companion); err != nil {
		menuNotice(out, "WARNING", "Approved wstunnel v11.0.0 companion is missing or untrusted.")
		menuProse(out, "Place the exact official wstunnel_11.0.0_linux_ARCH.tar.gz beside the official one-file STL installer and rerun that SAME installer.")
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
	menuSection(out, "WSS roles / which side accepts public TLS?")
	menuOption(out, "1", "Listen WSS", "THIS server accepts the selected TCP port")
	menuOption(out, "2", "Dial WSS", "OTHER server accepts the TCP port")
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
	tcp, err := askPortDefault(p, "Public WSS/TLS TCP port [443]: ", 443)
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
	request := wssCreateRequest{SchemaVersion: 1, LinkID: id, Underlay: desiredUnderlayV1{Local: route.Source, Peer: peer},
		Addresses:  desiredLinkAddressesV1{Local: addresses.Local, Peer: addresses.Peer},
		ListenPort: localWG, PeerPort: peerWG, Role: role, TCPPort: tcp,
		LocalKeepalive: 25, PeerKeepalive: 25,
		LocalForwardUDPPort: forward, RemoteForwardUDPPort: remoteForward, TLSServerName: tlsName}
	preview, err := json.Marshal(request)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot encode public WSS configuration.")
		return 1
	}
	menuScreen(out, "Review / confirm WireGuard over WSS")
	menuField(out, "Backend", "WireGuard / WSS + TLS")
	menuField(out, "This server", route.Source.String()+" ("+role+")")
	menuField(out, "Other server", peer.String())
	menuField(out, "TLS TCP port", strconv.Itoa(int(tcp)))
	menuField(out, "Kernel WG UDP", fmt.Sprintf("this %d / peer %d", localWG, peerWG))
	menuField(out, "Private IPs", addresses.Local.String()+" <-> "+addresses.Peer.String())
	menuField(out, "WSS forwarding UDP", fmt.Sprintf("this %d / peer %d", forward, remoteForward))
	menuNotice(out, "WARNING", "Creates scoped nft ingress guard, WG interface, WSS sidecar, mTLS secrets and a private peer handoff.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		return 2
	}
	answer, err := p.askAction("YES", "Create WSS Link and private receiver handoff? Type YES (Enter=cancel): ")
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
	menuScreen(out, "Applying / WSS+WireGuard")
	code := linkWSSCommand([]string{"create-wss", "--stdin", "--output", path},
		bytes.NewReader(preview), out, errOut, opts)
	if code != 0 {
		menuNotice(out, "WARNING", "Preserve the original peer handoff and reconcile State and owned host resources; do not generate replacement keys.")
		return code
	}
	menuScreen(out, "WSS Link / local activation complete")
	menuNotice(out, "OK", "Local WSS helper and kernel WG were ensured; verify actual peer handshake and private traffic separately.")
	menuShowNewProtectedHandoff(input, out, opts, id)
	menuProse(out, "On the peer: transfer the sensitive offer privately, run stl link preview-wss --stdin and then stl link import-wss --stdin --confirm SHA256; verify private traffic.")
	return 0
}
