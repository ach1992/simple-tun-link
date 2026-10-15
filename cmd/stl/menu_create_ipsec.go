package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// IPsec uses the existing admitted, protected sender CLI; the wizard is
// not an alternative strongSwan owner or a generic service installer.
func menuCreateIPsec(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, mode domain.Encapsulation) int {
	fmt.Fprintf(out, "\nIPsec %s — encrypted IKEv2 tunnel (advanced)\n", mode)
	fmt.Fprintln(out, "This requires a verified STL-exclusive strongSwan service.")
	if options == nil {
		var err error
		options, err = productionRuntimeOptions()
		if err != nil {
			fmt.Fprintln(out, "Cannot check IPsec prerequisites on this server. No changes applied.")
			fmt.Fprintln(out, "Run: stl doctor ipsec")
			return 4
		}
	}
	pre, done := context.WithTimeout(context.Background(), 15*time.Second)
	_, admitted := activeIPsecBackend(pre, options)
	done()
	if admitted != nil {
		fmt.Fprintln(out, "IPsec is not safely available on this server yet. No keys or tunnels created.")
		fmt.Fprintln(out, "Run: stl doctor ipsec --json  (shows which prerequisite is missing).")
		fmt.Fprintln(out, "You can use GRE/IPIP or WireGuard independently; existing strongSwan services will not be changed.")
		return 4
	}

	p := createPrompts{reader: reader, out: out, errOut: errOut}
	peer, err := askPeerUnderlay(p)
	if err != nil {
		return p.failed(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := createRunner(options)
	route, err := (linux.RouteResolver{Runner: runner}).Resolve(ctx, peer)
	if err != nil || !route.Source.Is4() || !route.Source.IsGlobalUnicast() || route.Source == peer {
		fmt.Fprintln(errOut, "No safe route/source IP to the other server was found. No changes applied.")
		return 4
	}
	fmt.Fprintf(out, "THIS server's connection IPv4 (automatic from route): %s; no need to type it.\n", route.Source)
	snapshot, err := state.NewFileStore(createStateRoot(options)).Load(ctx)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot inspect existing saved tunnels. No changes applied.")
		return 1
	}
	addresses, err := askLinkAddresses(p, runner, snapshot, peer, false)
	if err != nil {
		return p.failed(err)
	}
	idMaker := domain.NewLinkID
	if options != nil && options.createLinkID != nil {
		idMaker = options.createLinkID
	}
	id, err := idMaker()
	if err != nil || id.Validate() != nil {
		fmt.Fprintln(errOut, "Cannot choose safe tunnel ID. No changes applied.")
		return 1
	}
	if _, already := snapshot.Find(id); already {
		fmt.Fprintln(errOut, "This tunnel ID is already present. No changes applied.")
		return 2
	}
	handoff, err := askPrivateHandoffPath(p, options, id)
	if err != nil {
		return p.failed(err)
	}
	mtu := domain.MTUPolicy{Mode: domain.MTUAuto}
	advanced, err := p.yesNo("Change local MTU from the Auto estimate? [y/N]: ")
	if err != nil {
		return p.failed(err)
	}
	if advanced {
		if err := chooseManagedMTU(p, &mtu); err != nil {
			return p.failed(err)
		}
	}
	wire := ipsecSenderRequestV2{
		ipsecSenderRequestV1: ipsecSenderRequestV1{
			SchemaVersion: managedMTUSchemaVersion, LinkID: id,
			Underlay:      desiredUnderlayV1{Local: route.Source, Peer: peer},
			Addresses:     desiredLinkAddressesV1{Local: addresses.Local, Peer: addresses.Peer},
			Encapsulation: mode,
		},
		MTU: mtu,
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot prepare IPsec tunnel request; no changes applied.")
		return 1
	}
	fmt.Fprintln(out, "\nReview encrypted tunnel (not yet created):")
	fmt.Fprintf(out, "  IPsec %s | THIS server %s, tunnel IP %s\n", mode, route.Source, addresses.Local)
	fmt.Fprintf(out, "  OTHER server %s, tunnel IP %s\n", peer, addresses.Peer)
	fmt.Fprintln(out, "  Protected receiver Setup Link: retained for later sharing under STL-owned private storage")
	fmt.Fprintln(out, "This will generate a unique protected key, stage IPsec and activate only STL-owned resources.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish fresh terminal confirmation; no changes applied.")
		return 2
	}
	confirm, err := p.ask("Create IPsec tunnel? Type YES to confirm (Enter=no): ")
	if err != nil {
		return p.failed(err)
	}
	if !strings.EqualFold(confirm, "yes") {
		fmt.Fprintln(out, "Cancelled. No keys or tunnel were created.")
		return 0
	}
	handoff, err = prepareProtectedMenuHandoff(options, id)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot safely reserve the protected Setup Link file. No new key generated.")
		return 1
	}
	code := linkCreateIPsecCommand([]string{"create-ipsec", "--stdin", "--output", handoff},
		bytes.NewReader(payload), out, errOut, options)
	if code != 0 {
		fmt.Fprintln(errOut, "If a protected handoff was already staged, keep that file and reconcile before starting a new IPsec setup.")
		return code
	}
	fmt.Fprintln(out, "The protected receiver Setup Link remains available: My tunnels -> tunnel number -> Share Setup Link.")
	fmt.Fprintln(out, "OTHER server: Import -> Protected link, then explicitly Connect IPsec and diagnose traffic.")
	fmt.Fprintln(out, "Use Delete saved Setup Link only when you no longer need that receiver handoff.")
	return 0
}
