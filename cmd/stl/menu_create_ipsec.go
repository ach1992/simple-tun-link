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

// The preceding selected-package workflow may have changed APT/vendor
// service state. Never claim this entire Create attempt was effect-free.
func menuIPsecBlockedNotice(out io.Writer, attemptedProvision bool) {
	if attemptedProvision {
		menuNotice(out, "WARNING", "Private IPsec provisioning was attempted. Service/configuration may have changed; inspect receipts, systemd and daemon state before retry. No Link or keys created.")
		return
	}
	menuNotice(out, "WARNING", "No IPsec Link or keys were created by this step. Earlier package preparation, if approved, remains in effect and may have started or enabled a vendor strongSwan service; inspect package/systemd state before retrying. GRE/IPIP/WireGuard remain independent.")
}

// IPsec uses the existing admitted, protected sender CLI; the wizard is
// not an alternative strongSwan owner or a generic service installer.
func menuCreateIPsec(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, mode domain.Encapsulation) int {
	menuSection(out, fmt.Sprintf("Create IPsec / %s", mode))
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
		menuNotice(out, "WARNING", "IPsec cannot start: the STL-exclusive strongSwan runtime is not verified.")
		menuSection(out, "IPsec / prerequisites")
		menuField(out, "Packages", "strongswan-swanctl, charon-systemd, crypto plugins")
		menuField(out, "Service", "STL-private configuration, verified unit and origin receipts")
		menuField(out, "Next", "stl doctor ipsec --json (read-only)")
		menuProse(out, "Return to the guided IPsec PREPARE flow after reconciling the specific prerequisite or foreign ownership failure. Packages alone never establish service readiness.")
		menuIPsecBlockedNotice(out, false)
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
	menuField(out, "Local endpoint", route.Source.String()+" (automatic)")
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
	menuScreen(out, "Review / confirm IPsec")
	menuField(out, "Type", "IPsec / "+string(mode))
	menuField(out, "This server", route.Source.String())
	menuField(out, "Local tunnel IP", addresses.Local.String())
	menuField(out, "Other server", peer.String())
	menuField(out, "Remote tunnel IP", addresses.Peer.String())
	menuField(out, "Receiver setup", "Saved privately; displayed here after successful Create")
	menuNotice(out, "WARNING", "The receiver link contains a private PSK; share it only with your other server.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish fresh terminal confirmation; no changes applied.")
		return 2
	}
	confirm, err := p.askAction("YES", "Create IPsec tunnel? Type YES to confirm (Enter=no): ")
	if err != nil {
		return p.failed(err)
	}
	if !strings.EqualFold(confirm, "yes") {
		fmt.Fprintln(out, "Cancelled. No keys or tunnel were created.")
		return 0
	}
	menuScreen(out, "Applying / creating protected IPsec tunnel")
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
	menuScreen(out, "IPsec / local creation complete")
	menuNotice(out, "OK", "IPsec receiver Setup Link saved privately. Pairing is not finished yet.")
	menuShowNewProtectedHandoff(input, out, options, id)
	fmt.Fprintln(out, "After import, explicitly Connect IPsec and check traffic on both sides.")
	return 0
}
