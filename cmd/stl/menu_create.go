package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/state"
)

var errCreateCancelled = errors.New("guided create cancelled")

type createPrompts struct {
	reader *bufio.Reader
	out    io.Writer
	errOut io.Writer
}

func (p createPrompts) ask(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	answer, err := readMenuAnswer(p.reader)
	if err != nil {
		return "", err
	}
	if answer == "q" || strings.EqualFold(answer, "cancel") {
		return "", errCreateCancelled
	}
	return answer, nil
}

func (p createPrompts) yesNo(prompt string) (bool, error) {
	value, err := p.ask(prompt)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(value) {
	case "", "n", "no":
		return false, nil
	case "y", "yes":
		return true, nil
	default:
		return false, fmt.Errorf("expected yes or no")
	}
}

func (p createPrompts) failed(err error) int {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, errCreateCancelled):
		fmt.Fprintln(p.out, "Create cancelled. No changes applied.")
		return 0
	default:
		fmt.Fprintln(p.errOut, "Invalid, unavailable or oversized guided input. No changes applied.")
		return 2
	}
}

func createRunner(options *runtimeOptions) linux.Runner {
	if options != nil && options.probeRunner != nil {
		return options.probeRunner
	}
	return linux.ExecRunner{}
}

func createStateRoot(options *runtimeOptions) string {
	if options != nil {
		return options.stateRoot
	}
	return state.DefaultRoot
}

// collectReservedLinkAddresses includes legacy state that did not persist all
// owned claims, while leaving actual mutation/ownership authority to Engine.
func collectReservedLinkAddresses(snapshot state.Snapshot) []domain.ResourceClaim {
	var claims []domain.ResourceClaim
	for _, record := range snapshot.Links {
		claims = append(claims, record.OwnedResources...)
		for _, prefix := range []netip.Prefix{record.Desired.Addresses.Local, record.Desired.Addresses.Peer} {
			if prefix.IsValid() {
				claims = append(claims, domain.ResourceClaim{
					Kind: domain.ResourceLinkSubnet, Key: prefix.Masked().String(),
				})
			}
		}
	}
	return claims
}

func inspectedAddressClaims(ctx context.Context, runner linux.Runner, candidates []netip.Prefix) ([]domain.ResourceClaim, error) {
	claims := make([]domain.ResourceClaim, len(candidates))
	for i, prefix := range candidates {
		claims[i] = domain.ResourceClaim{Kind: domain.ResourceLinkSubnet, Key: prefix.String()}
	}
	observed, err := (linux.CollisionInspector{
		Snapshotter: linux.HostSnapshotter{Runner: runner},
	}).Inspect(ctx, claims)
	if err != nil {
		return nil, err
	}
	occupied := make([]domain.ResourceClaim, 0, len(observed))
	for _, item := range observed {
		occupied = append(occupied, item.Claim)
	}
	return occupied, nil
}

func randomGREKey() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw[:]), nil
}

func persistedGREReceiveConflict(snapshot state.Snapshot, link domain.Link) bool {
	wanted := domain.GREReceiveClaim(link.Underlay, link.GRE)
	for _, record := range snapshot.Links {
		if record.Desired.Backend != domain.BackendGRE {
			continue
		}
		if domain.GREReceiveClaim(record.Desired.Underlay, record.Desired.GRE) == wanted {
			return true
		}
	}
	return false
}

func configureGREAdvanced(p createPrompts, options *domain.GREOptions) error {
	key, err := p.ask("GRE key (Enter=keep generated key; 'off'=unkeyed; decimal=explicit key): ")
	if err != nil {
		return err
	}
	switch key {
	case "":
	case "off":
		options.KeyEnabled, options.Key = false, 0
	default:
		parsed, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid GRE key")
		}
		options.KeyEnabled, options.Key = true, uint32(parsed)
	}
	ttl, err := p.ask("GRE TTL (Enter=automatic; 1-255=fixed): ")
	if err != nil {
		return err
	}
	if ttl != "" {
		value, err := strconv.ParseUint(ttl, 10, 8)
		if err != nil || value == 0 {
			return fmt.Errorf("invalid GRE TTL")
		}
		options.TTL = uint8(value)
	}
	tos, err := p.ask("GRE TOS (Enter=default; decimal 0-255): ")
	if err != nil {
		return err
	}
	if tos != "" {
		value, err := strconv.ParseUint(tos, 10, 8)
		if err != nil {
			return fmt.Errorf("invalid GRE TOS")
		}
		options.TOS = uint8(value)
	}
	if options.TTL == 0 {
		options.DisablePMTUD, err = p.yesNo("Disable GRE PMTU discovery? [y/N]: ")
		if err != nil {
			return err
		}
	}
	options.Checksum, err = p.yesNo("Enable GRE checksum? [y/N]: ")
	if err != nil {
		return err
	}
	options.Sequence, err = p.yesNo("Enable GRE sequence numbers? [y/N]: ")
	return err
}

// The interactive wizard is only an operator-facing composer. Host inspection,
// collision semantics, versioned CLI decode, Engine ensure, pairing export and
// diagnostic/ownership logic are all reused; it never runs network mutations.
func menuCreate(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	fmt.Fprintln(out, "\nCreate GRE Native (default). Enter 'q' at any prompt to cancel.")
	fmt.Fprintln(out, "GRE is not encrypted or authenticated; verify your peer independently.")
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
	if err != nil || !route.Source.Is4() || !route.Source.IsGlobalUnicast() ||
		route.Source.IsLoopback() || route.Source == peer {
		fmt.Fprintln(errOut, "Cannot establish a usable local IPv4 source and route to that peer; nothing applied.")
		return 4
	}
	capabilities, err := (linux.CapabilityProbe{Runner: runner}).Probe(ctx)
	if err != nil || !capabilities[linux.CapabilityGRENative].Available {
		fmt.Fprintln(errOut, "GRE Native capability could not be confirmed on this host; nothing applied.")
		return 4
	}
	fmt.Fprintf(out, "Underlay: %s -> %s via %s (gateway: %s, route MTU: %d or unknown when 0)\n",
		route.Source, peer, safeMenuText(route.Device), route.Gateway, route.MTU)

	root := createStateRoot(options)
	if root == "" {
		fmt.Fprintln(errOut, "Local state root is unavailable; nothing applied.")
		return 1
	}
	snapshot, err := state.NewFileStore(root).Load(ctx)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot inspect existing STL Links; nothing applied.")
		return 1
	}
	proposals, err := domain.Private31Candidates()
	if err != nil {
		fmt.Fprintln(errOut, "Cannot prepare safe Link Address candidates; nothing applied.")
		return 1
	}
	live, err := inspectedAddressClaims(ctx, runner, proposals)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot inspect host address, route or interface reservations; nothing applied.")
		return 1
	}
	reserved := collectReservedLinkAddresses(snapshot)
	auto, autoOK, err := domain.FreePrivate31(proposals, append(live, reserved...))
	if err != nil {
		fmt.Fprintln(errOut, "Cannot validate Link Address reservations; nothing applied.")
		return 1
	}
	if autoOK {
		fmt.Fprintf(out, "Suggested Link subnet: %s (local host checked; peer host NOT checked)\n", auto)
	} else {
		fmt.Fprintln(out, "No free automatic /31 proposal found. Provide a manually verified RFC1918 /31.")
	}
	answer, err := p.ask("Link subnet (Enter=suggested; or supply an RFC1918 /31 network): ")
	if err != nil {
		return p.failed(err)
	}
	selected := auto
	if answer != "" {
		selected, err = netip.ParsePrefix(answer)
		if err != nil || domain.ValidatePrivate31(selected) != nil {
			return p.failed(fmt.Errorf("invalid /31"))
		}
		manualCtx, manualCancel := context.WithTimeout(context.Background(), 20*time.Second)
		live, err = inspectedAddressClaims(manualCtx, runner, []netip.Prefix{selected})
		manualCancel()
		if err != nil {
			fmt.Fprintln(errOut, "Cannot recheck manual Link subnet against host resources; nothing applied.")
			return 1
		}
		_, available, checkErr := domain.FreePrivate31([]netip.Prefix{selected}, append(live, reserved...))
		if checkErr != nil || !available {
			fmt.Fprintln(errOut, "Manual Link subnet overlaps local routes, addresses or saved STL Links. Nothing applied.")
			return 2
		}
	} else if !autoOK {
		fmt.Fprintln(errOut, "No safe automatic subnet is available; enter a manual /31. Nothing applied.")
		return 2
	}
	second, err := p.yesNo("Use second /31 address locally instead of first? [y/N]: ")
	if err != nil {
		return p.failed(err)
	}
	localAddr, peerAddr := selected.Addr(), selected.Addr().Next()
	if second {
		localAddr, peerAddr = peerAddr, localAddr
	}

	newID := domain.NewLinkID
	if options != nil && options.createLinkID != nil {
		newID = options.createLinkID
	}
	id, err := newID()
	if err != nil || id.Validate() != nil {
		fmt.Fprintln(errOut, "Cannot allocate Link ID; nothing applied.")
		return 1
	}
	if _, exists := snapshot.Find(id); exists {
		fmt.Fprintln(errOut, "Generated Link ID is already present in saved state; no changes applied.")
		return 2
	}
	key, err := randomGREKey()
	if err != nil {
		fmt.Fprintln(errOut, "Cannot generate GRE receive key; nothing applied.")
		return 1
	}
	link := domain.Link{
		ID:       id,
		Underlay: domain.Underlay{Local: route.Source, Peer: peer},
		Addresses: domain.LinkAddresses{
			Local: netip.PrefixFrom(localAddr, 31),
			Peer:  netip.PrefixFrom(peerAddr, 31),
		},
		Backend: domain.BackendGRE, Encapsulation: domain.EncapNative,
		GRE: domain.GREOptions{KeyEnabled: true, Key: key},
	}
	advanced, err := p.yesNo("Configure advanced GRE options? [y/N]: ")
	if err != nil {
		return p.failed(err)
	}
	if advanced {
		if err := configureGREAdvanced(p, &link.GRE); err != nil {
			return p.failed(err)
		}
	}
	// Retry only generated keys; never reinterpret a manually chosen key.
	if !advanced && persistedGREReceiveConflict(snapshot, link) {
		for n := 0; n < 8 && persistedGREReceiveConflict(snapshot, link); n++ {
			link.GRE.Key, err = randomGREKey()
			if err != nil {
				break
			}
		}
	}
	if err != nil || persistedGREReceiveConflict(snapshot, link) {
		fmt.Fprintln(errOut, "GRE receive identity conflicts with a saved Link or cannot be generated; nothing applied.")
		return 2
	}
	if err := link.Validate(); err != nil {
		return p.failed(err)
	}
	if _, err := pairing.NewQuickOffer(link, nil); err != nil {
		fmt.Fprintln(errOut, "Cannot construct a compatible peer setup offer; nothing applied.")
		return 2
	}

	fmt.Fprintln(out, "\nPREVIEW ONLY — nothing has been applied yet")
	fmt.Fprintf(out, "Link ID: %s | backend: GRE | encapsulation: Native\n", link.ID)
	fmt.Fprintf(out, "Underlay: %s -> %s | route: %s | gateway: %s\n",
		link.Underlay.Local, link.Underlay.Peer, safeMenuText(route.Device), route.Gateway)
	fmt.Fprintf(out, "Link Addresses: local %s | peer %s | /31 %s\n",
		link.Addresses.Local, link.Addresses.Peer, selected)
	fmt.Fprintf(out, "GRE: key_enabled=%t key=%d ttl=%d tos=%d disable_pmtud=%t checksum=%t sequence=%t\n",
		link.GRE.KeyEnabled, link.GRE.Key, link.GRE.TTL, link.GRE.TOS,
		link.GRE.DisablePMTUD, link.GRE.Checksum, link.GRE.Sequence)
	fmt.Fprintln(out, "If confirmed: Engine will validate/recheck ownership, create only an STL-owned GRE interface/address,")
	fmt.Fprintln(out, "manage a peer-scoped protocol-47 firewall rule and desired state, and configure owned restore persistence if supported.")
	fmt.Fprintln(out, "Only this host was inspected. Ensure the /31 is unused on the PEER and its route is reachable.")
	fmt.Fprintln(out, "The GRE key identifies a receive tunnel; it is NOT encryption or authentication.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish a fresh terminal confirmation; nothing applied.")
		return 2
	}
	confirm, err := p.ask(fmt.Sprintf("To APPLY, type exact Link ID %s (Enter cancels): ", link.ID))
	if err != nil {
		return p.failed(err)
	}
	if confirm != string(link.ID) {
		fmt.Fprintln(out, "Create cancelled. No changes applied.")
		return 0
	}
	// Marshal the deliberately pinned v1 public contract; never marshal
	// domain.Link directly into automation input or introduce a second apply.
	wire := desiredLinkRequestV1{
		SchemaVersion: desiredLinkSchemaVersion,
		Link: desiredLinkV1{
			ID: link.ID, Underlay: desiredUnderlayV1{
				Local: link.Underlay.Local, Peer: link.Underlay.Peer,
			}, Addresses: desiredLinkAddressesV1{
				Local: link.Addresses.Local, Peer: link.Addresses.Peer,
			},
			Backend: link.Backend, Encapsulation: link.Encapsulation,
			GRE: desiredGREOptionsV1{
				KeyEnabled: link.GRE.KeyEnabled, Key: link.GRE.Key, TTL: link.GRE.TTL,
				TOS: link.GRE.TOS, DisablePMTUD: link.GRE.DisablePMTUD,
				Checksum: link.GRE.Checksum, Sequence: link.GRE.Sequence,
			},
		},
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot encode Link intent; nothing applied.")
		return 1
	}
	fmt.Fprintln(out, "Applying via canonical versioned Link Ensure...")
	if code := linkLifecycleCommand([]string{"ensure", "--stdin"}, bytes.NewReader(payload), out, errOut, options); code != 0 {
		fmt.Fprintln(errOut, "Create failed or outcome is uncertain. Inspect host/Link state before retrying.")
		return code
	}
	fmt.Fprintln(out, "\nPeer Setup Link (explicit export; plaintext endpoint metadata):")
	if code := linkExportCommand([]string{"export", string(link.ID)}, out, errOut, options); code != 0 {
		fmt.Fprintln(errOut, "Local Link was ensured, but setup export failed; use stl link export with this Link ID.")
		return code
	}
	fmt.Fprintln(out, "On the peer, open stl > Import Setup Link, paste the export and confirm its Link ID.")
	fmt.Fprintln(out, "Local observed status (does not prove end-to-end connectivity):")
	if code := linkReadCommand([]string{"status", string(link.ID)}, out, errOut, options); code != 0 {
		fmt.Fprintln(errOut, "Local Link was ensured, but live status could not be verified. Reconcile before relying on it.")
		return code
	}
	diagnose, err := p.yesNo("Run active peer connectivity/MTU diagnostics now? (after peer import) [y/N]: ")
	if errors.Is(err, io.EOF) || errors.Is(err, errCreateCancelled) {
		fmt.Fprintln(out, "Diagnostics skipped; the local Link remains configured.")
		return 0
	}
	if err != nil {
		fmt.Fprintln(errOut, "Invalid diagnostics choice; the local Link remains configured.")
		return 2
	}
	if !diagnose {
		fmt.Fprintf(out, "After importing on the peer: stl link diagnose %s (or menu > Tests & Diagnostics).\n", link.ID)
		return 0
	}
	if code := linkDiagnoseCommand([]string{"diagnose", string(link.ID)}, out, errOut, options); code != 0 {
		fmt.Fprintln(errOut, "Diagnostics did not succeed. Local Link remains configured; investigate peer and route.")
		return code
	}
	return 0
}
