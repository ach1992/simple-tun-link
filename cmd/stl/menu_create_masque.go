package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/masquehost"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// MASQUE accepts either IPv4 or IPv6 physical underlays. The ordinary guided
// GRE/WG address chooser is IPv4-only; never silently coerce IPv6 to IPv4.
func askMASQUEUnderlay(p createPrompts, local bool, peer netip.Addr) (netip.Addr, error) {
	prompt := "OTHER server's physical IPv4/IPv6 address (q=back): "
	if local {
		prompt = "THIS server's assigned physical IPv4/IPv6 address (q=back): "
	}
	for {
		value, err := p.ask(prompt)
		if err != nil {
			return netip.Addr{}, err
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
			menuNotice(p.out, "WARNING", "Enter a physical unicast IPv4 or IPv6 address, without a port, interface zone or prefix.")
			continue
		}
		if peer.IsValid() && (ip.BitLen() != peer.BitLen() || ip == peer) {
			menuNotice(p.out, "WARNING", "Both physical endpoints must be different addresses of the SAME IP family.")
			continue
		}
		if local && masquehost.VerifyLocalUnderlay(ip) != nil {
			menuNotice(p.out, "WARNING", "This physical address is not uniquely assigned to a local interface; inspect ip address show before proceeding.")
			continue
		}
		return ip, nil
	}
}

func askMASQUEPrivatePair(p createPrompts, snapshot state.Snapshot) (domain.LinkAddresses, error) {
	for {
		ownText, err := p.ask("Private IPv4 on THIS server (example 10.252.98.2; q=back): ")
		if err != nil {
			return domain.LinkAddresses{}, err
		}
		peerText, err := p.ask("Private IPv4 on OTHER server (example 10.252.98.1; q=back): ")
		if err != nil {
			return domain.LinkAddresses{}, err
		}
		own, ownErr := netip.ParseAddr(ownText)
		peer, peerErr := netip.ParseAddr(peerText)
		if ownErr != nil || peerErr != nil || !own.Is4() || !peer.Is4() || !own.IsPrivate() || !peer.IsPrivate() || own == peer {
			menuNotice(p.out, "WARNING", "Use two distinct private IPv4 addresses (RFC1918), without /32 suffix. All MASQUE private routes use /32.")
			continue
		}
		conflict := false
		for _, row := range snapshot.Links {
			for _, addr := range []netip.Addr{row.Desired.Addresses.Local.Addr(), row.Desired.Addresses.Peer.Addr()} {
				if addr == own || addr == peer {
					conflict = true
				}
			}
		}
		if conflict {
			menuNotice(p.out, "WARNING", "This private address is already used by a saved Link; choose two different addresses.")
			continue
		}
		return domain.LinkAddresses{Local: netip.PrefixFrom(own, 32), Peer: netip.PrefixFrom(peer, 32)}, nil
	}
}

// The menu collects public topology only. Identity issuance, protected
// handoff, owner checks, TUN, route and systemd are exclusively CLI/Engine.
func menuCreateMASQUE(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	menuScreen(out, "Create / MASQUE CONNECT-IP over authenticated HTTP/2")
	menuNotice(out, "INFO", "Native STL managed private IPv4 L3 over mTLS and HTTP/2 TCP; no external WireGuard or sidecar dependency.")
	menuProse(out, "The other server must be able to reach the chosen public TCP listener. A local Link is NOT proof of remote connectivity.")
	peer, err := askMASQUEUnderlay(p, false, netip.Addr{})
	if err != nil {
		return p.failed(err)
	}
	own, err := askMASQUEUnderlay(p, true, peer)
	if err != nil {
		return p.failed(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	snapshot, err := state.NewFileStore(createStateRoot(opts)).Load(ctx)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot inspect saved private address reservations.")
		return 1
	}
	addresses, err := askMASQUEPrivatePair(p, snapshot)
	if err != nil {
		return p.failed(err)
	}
	role, source, err := askCarrierRole(p, "MASQUE", own, peer)
	if err != nil {
		return p.failed(err)
	}
	tcp, err := askPortDefault(p, "Public MASQUE HTTPS TCP port [443]: ", 443)
	if err != nil {
		return p.failed(err)
	}
	listener := peer
	if role == "listen" {
		listener = own
	}
	tlsName, err := p.ask("TLS certificate name (Enter=listener IP; exact DNS name optional): ")
	if err != nil {
		return p.failed(err)
	}
	if tlsName == "" {
		tlsName = listener.String()
	}
	choose := domain.NewLinkID
	if opts != nil && opts.createLinkID != nil {
		choose = opts.createLinkID
	}
	id, err := choose()
	if err != nil || id.Validate() != nil {
		menuNotice(out, "WARNING", "Could not allocate a new Link ID.")
		return 1
	}
	req := masqueCreateRequestV1{SchemaVersion: 1, LinkID: id,
		Underlay:  desiredUnderlayV1{Local: own, Peer: peer},
		Addresses: desiredLinkAddressesV1{Local: addresses.Local, Peer: addresses.Peer},
		Role:      role, TCPPort: tcp, TLSServerName: tlsName}
	if _, _, err := req.makePair(id); err != nil {
		menuNotice(out, "WARNING", "MASQUE physical/private address or TLS name invalid; no credential or Link created.")
		return 2
	}
	if _, err := askPrivateHandoffPath(p, opts, id); err != nil {
		return p.failed(err)
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return 1
	}
	menuScreen(out, "Review / confirm MASQUE CONNECT-IP")
	menuField(out, "Backend", "MASQUE / RFC 9484 CONNECT-IP over HTTP/2 (mTLS)")
	showCarrierDirectionReview(out, own, peer, role, source, "TCP", tcp)
	menuField(out, "TLS server name", safeMenuText(tlsName))
	menuField(out, "Private IPv4 /32", addresses.Local.Addr().String()+" <-> "+addresses.Peer.Addr().String())
	menuField(out, "Initial TUN MTU", strconv.Itoa(1280)+" bytes (peer PMTU not measured)")
	menuNotice(out, "WARNING", "Creates a private mTLS credential generation, protected receiver handoff, owned transient systemd service and private TUN/route. No default route is changed.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		return 2
	}
	answer, err := p.askAction("YES", "Create managed MASQUE Link and private peer handoff? Type YES (Enter=cancel): ")
	if errors.Is(err, io.EOF) || errors.Is(err, errCreateCancelled) {
		return 0
	}
	if err != nil {
		return 2
	}
	if !strings.EqualFold(answer, "yes") {
		menuNotice(out, "INFO", "Creation cancelled before any host change.")
		return 0
	}
	createRuntime, err := menuHandoffCreationOptions(opts, id, domain.BackendMASQUE)
	if err != nil {
		return menuGuidedCreateRuntimeFailure(out, domain.BackendMASQUE, err)
	}
	path, err := prepareProtectedMenuHandoff(opts, id)
	if err != nil {
		menuNotice(out, "WARNING", "Cannot reserve the protected peer handoff file.")
		return 1
	}
	menuScreen(out, "Applying / MASQUE managed Link")
	code := linkMASQUECommand([]string{"create-masque", "--stdin", "--output", path}, bytes.NewReader(payload), out, errOut, createRuntime)
	if code != 0 {
		menuNotice(out, "WARNING", "Creation is not confirmed. Preserve the exact handoff, State and private files for inspection/reconciliation; do not regenerate an active identity.")
		return code
	}
	menuScreen(out, "MASQUE Link / local setup complete")
	menuNotice(out, "OK", "Owned local MASQUE helper and private TUN setup completed; authenticated peer stream and bidirectional private-IP traffic remain untested.")
	menuShowNewProtectedHandoff(input, out, opts, id)
	menuProse(out, "On the peer, privately transfer the original offer, preview it, then use stl link import-masque --stdin --confirm SHA256. Test both private IPs separately.")
	return 0
}
