package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Collect public topology through the menu. Key generation, private peer
// handoff and host mutations remain in the canonical Engine and WSS CLI.
func menuCreateWSS(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	return menuCreateWSSWithHost(input, reader, out, errOut, opts, wss.Host{StateRoot: createStateRoot(opts)})
}

// The internal host parameter lets isolated PTY tests inspect a pinned test
// executable with the production identity guard, without installing a helper
// or changing the global /usr/local/libexec/stl path.
func menuCreateWSSWithHost(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	opts *runtimeOptions, companion wss.Host) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	menuScreen(out, "Create / WireGuard over WSS (mTLS)")
	menuNotice(out, "INFO", "WireGuard UDP is scoped to loopback; the remote peer connects over authenticated WSS/TLS TCP.")
	inspect := func() error {
		_, err := wss.InspectPinnedExecutableForOperator(companion)
		return err
	}
	if companion.Binary != "" && companion.Binary != wss.DefaultExecutable {
		// A test-controlled executable must not trigger root installation
		// of the production companion when its fixture is absent.
		if inspect() != nil {
			menuNotice(out, "WARNING", "Approved wstunnel v11.0.0 companion is missing or untrusted.")
			menuField(out, "Next", "Use the installed root menu to acquire a verified WSS companion.")
			return 4
		}
	} else {
		spec, supported := menuPinnedCompanion(menuCompanionWSS, runtime.GOARCH)
		if !supported {
			menuNotice(out, "WARNING", "This CPU has no supported official WSS companion.")
			return 4
		}
		if !menuEnsureCompanion(input, reader, out, spec, productionMenuCompanionOps(inspect, spec)) {
			return 4
		}
		menuScreen(out, "Create / WireGuard over WSS (mTLS)")
		menuField(out, "Companion", "Pinned helper verified; ready for Link setup")
	}
	peer, err := askPeerUnderlay(p)
	if err != nil {
		return p.failed(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := createRunner(opts)
	route, err := askLocalUnderlay(p, runner, peer)
	if err != nil {
		if err == errCreateCancelled || err == io.EOF {
			return p.failed(err)
		}
		menuNotice(out, "WARNING", "No verified local IPv4/interface was selected; no Link was created. Inspect ip -json address show, then retry with an assigned local address.")
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
	role, roleSource, err := askCarrierRole(p, "WSS", route.Source, peer)
	if err != nil {
		return p.failed(err)
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
	showCarrierDirectionReview(out, route.Source, peer, role, roleSource, "TCP", tcp)
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
