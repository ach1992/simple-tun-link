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

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Collect public topology through the menu. Key generation, private peer
// handoff and host mutations remain in the canonical Engine and QUIC CLI.
func menuCreateQUIC(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	return menuCreateQUICWithExecutable(input, reader, out, errOut, opts, quic.DefaultExecutable)
}

// The internal executable parameter retains production's exact pinned helper
// inspection. Guided tests inject a preflight-only seam below without changing
// Engine admission or the canonical production executable.
func menuCreateQUICWithExecutable(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	opts *runtimeOptions, companion string) int {
	return menuCreateQUICWithInspection(input, reader, out, errOut, opts, companion, func() error {
		_, err := quic.InspectPinnedHysteria(companion)
		return err
	})
}

// Guided tests replace only the preflight, cancel before Create and cannot
// authorize helper admission. Production and Engine keep their pinned checks.
func menuCreateQUICWithInspection(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	opts *runtimeOptions, companion string, inspect func() error) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	menuScreen(out, "Create / WireGuard over QUIC")
	menuNotice(out, "INFO", "Kernel WireGuard ingress is guarded. Choose either original mTLS, Salamander, or real HTTP/3 over UDP with private Link password authorization.")
	if companion != quic.DefaultExecutable {
		// Isolated fixture paths never authorize production helper install.
		if inspect() != nil {
			menuNotice(out, "WARNING", "Approved Hysteria v2.13.0 companion is missing or untrusted.")
			menuField(out, "Next", "Use the installed root menu to acquire a verified QUIC companion.")
			return 4
		}
	} else {
		spec, supported := menuPinnedCompanion(menuCompanionQUIC, runtime.GOARCH)
		if !supported {
			menuNotice(out, "WARNING", "This CPU has no supported official QUIC companion.")
			return 4
		}
		if !menuEnsureCompanion(input, reader, out, spec, productionMenuCompanionOps(inspect, spec)) {
			return 4
		}
		menuScreen(out, "Create / WireGuard over QUIC")
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
	role, roleSource, err := askCarrierRole(p, "QUIC", route.Source, peer)
	if err != nil {
		return p.failed(err)
	}
	obfuscation, publicHTTP3, err := askQUICMode(p)
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
	listener := peer
	if role == "listen" {
		listener = route.Source
	}
	tlsName, err := askTLSCertificateSAN(p, composition.QUIC, listener)
	if err != nil {
		return p.failed(err)
	}
	localKeep, peerKeep, err := askCarrierKeepalives(p)
	if err != nil {
		return p.failed(err)
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
	request := quicCreateRequest{SchemaVersion: 2, Obfuscation: publicQUICObfuscation(obfuscation), PublicHTTP3: publicHTTP3, LinkID: id, Underlay: desiredUnderlayV1{Local: route.Source, Peer: peer},
		Addresses:  desiredLinkAddressesV1{Local: addresses.Local, Peer: addresses.Peer},
		ListenPort: localWG, PeerPort: peerWG, Role: role, UDPPort: udp,
		LocalKeepalive: localKeep, PeerKeepalive: peerKeep,
		LocalForwardUDPPort: forward, RemoteForwardUDPPort: remoteForward, TLSServerName: tlsName}
	preview, err := json.Marshal(request)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot encode public QUIC configuration.")
		return 1
	}
	menuScreen(out, "Review / confirm WireGuard over QUIC")
	menuField(out, "Backend", "WireGuard / QUIC + TLS")
	showCarrierDirectionReview(out, route.Source, peer, role, roleSource, "UDP", udp)
	menuField(out, "TLS UDP port", strconv.Itoa(int(udp)))
	menuField(out, "QUIC obfuscation", publicQUICObfuscation(obfuscation))
	menuField(out, "Public HTTP/3", strconv.FormatBool(publicHTTP3))
	menuField(out, "Kernel WG UDP", fmt.Sprintf("this %d / peer %d", localWG, peerWG))
	menuField(out, "WG keepalive seconds", fmt.Sprintf("this %d / peer %d (0=off)", localKeep, peerKeep))
	menuField(out, "Private IPs", addresses.Local.String()+" <-> "+addresses.Peer.String())
	warnNonOnLinkPeerRoute(out, addresses)
	menuField(out, "Private MTU", "Auto: conservative 1280-byte start; peer PMTU remains unmeasured")
	menuField(out, "QUIC forwarding UDP", fmt.Sprintf("this %d / peer %d", forward, remoteForward))
	menuNotice(out, "WARNING", "Creates scoped nft guard, WireGuard, QUIC helper, private credentials and peer handoff. HTTP/3 mode admits public web requests but requires the Link password for private forwarding.")
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
	createRuntime, err := menuHandoffCreationOptions(opts, id, domain.BackendWireGuardQUIC)
	if err != nil {
		return menuGuidedCreateRuntimeFailure(out, domain.BackendWireGuardQUIC, err)
	}
	path, err := prepareProtectedMenuHandoff(opts, id)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot safely prepare private receiver handoff.")
		return 1
	}
	menuScreen(out, "Applying / QUIC+WireGuard")
	code := linkQUICCommand([]string{"create-quic", "--stdin", "--output", path},
		bytes.NewReader(preview), out, errOut, createRuntime)
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
func askQUICMode(p createPrompts) (string, bool, error) {
	menuSection(p.out, "QUIC packet representation")
	menuOption(p.out, "1", "Plain + mTLS", "original private QUIC handshake (default)")
	menuOption(p.out, "2", "Salamander + mTLS", "per-Link obfuscation; not standard HTTP/3")
	menuOption(p.out, "3", "Plain + public HTTP/3", "real same-UDP-endpoint HTTP/3; private forwarding requires Link password and WireGuard")
	for {
		answer, err := p.ask("QUIC mode [1]: ")
		if err != nil {
			return "", false, err
		}
		switch answer {
		case "", "1":
			return "", false, nil
		case "2":
			return "salamander", false, nil
		case "3":
			return "", true, nil
		default:
			fmt.Fprintln(p.out, "Choose QUIC mode 1, 2 or 3, or press q to go back.")
		}
	}
}
