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
	for {
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
			fmt.Fprintln(p.out, "Type y for Yes or n for No, or q to go back.")
		}
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
// owned claims and the known peer underlay address (even though other peer
// host resources cannot be inspected). Mutation authority remains with Engine.
func collectReservedLinkAddresses(snapshot state.Snapshot, peer netip.Addr) []domain.ResourceClaim {
	claims := []domain.ResourceClaim{{Kind: domain.ResourceLinkAddress, Key: peer.String()}}
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
func menuCreatePlain(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions, backend domain.Backend, mode domain.Encapsulation, manualPair bool) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	fmt.Fprintf(out, "\nCreate %s / %s. Type q to go back at any question.\n", backend, mode)
	fmt.Fprintln(out, "This type is NOT encrypted; use WireGuard for confidential traffic.")
	peer, err := askPeerUnderlay(p)
	if err != nil {
		return p.failed(err)
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
	capability := plainBackendCapability(backend, mode)
	if err != nil || capability == "" || !capabilities[capability].Available {
		fmt.Fprintf(errOut, "%s/%s is not available on this server. Check kernel/iproute2 support (and FOU/GUE modules if selected). No tunnel created.\n", backend, mode)
		return 4
	}
	fmt.Fprintf(out, "THIS server's connection IP: %s (detected automatically from route to the OTHER server)\n", route.Source)
	fmt.Fprintf(out, "OTHER server's connection IP: %s\n", peer)
	fmt.Fprintf(out, "Network device: %s (gateway %s); no need to type THIS server's IP.\n", safeMenuText(route.Device), route.Gateway)

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
	addresses, err := askLinkAddresses(p, runner, snapshot, peer, manualPair)
	if err != nil {
		return p.failed(err)
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
	link := domain.Link{
		ID: id, Underlay: domain.Underlay{Local: route.Source, Peer: peer},
		Addresses: addresses, Backend: backend, Encapsulation: mode,
		MTU: domain.MTUPolicy{Mode: domain.MTUAuto},
	}
	if backend == domain.BackendGRE {
		if manualPair {
			// A no-link receiver must match the peer's GRE receive key, if
			// enabled. A numeric key is an identifier and is safe to copy;
			// it is not authentication/encryption. Enter means unkeyed.
			key, err := askManualGREKey(p)
			if err != nil {
				return p.failed(err)
			}
			link.GRE = key
		} else {
			key, err := randomGREKey()
			if err != nil {
				fmt.Fprintln(errOut, "Cannot generate a tunnel receive identifier; no changes applied.")
				return 1
			}
			link.GRE = domain.GREOptions{KeyEnabled: true, Key: key}
			if mode != domain.EncapNative {
				link.GRE.UDPPort = uint16(49152 + key%16384)
				fmt.Fprintf(out, "Automatic UDP tunnel port: %d (check your provider firewall)\n", link.GRE.UDPPort)
			}
		}
	}
	advanced, err := p.yesNo("Change advanced settings (including MTU)? [y/N]: ")
	if err != nil {
		return p.failed(err)
	}
	if advanced && backend == domain.BackendGRE && !manualPair {
		if err := configureGREAdvanced(p, &link.GRE); err != nil {
			fmt.Fprintln(out, "Invalid advanced GRE option; restarting tunnel setup is safe before confirmation.")
			return p.failed(err)
		}
	}
	if advanced {
		if err := chooseManagedMTU(p, &link.MTU); err != nil {
			return p.failed(err)
		}
	}
	// Retry generated receive identities, never silently change a custom key.
	if backend == domain.BackendGRE && !advanced && !manualPair && persistedGREReceiveConflict(snapshot, link) {
		for n := 0; n < 8 && persistedGREReceiveConflict(snapshot, link); n++ {
			link.GRE.Key, err = randomGREKey()
			if err != nil {
				break
			}
			if mode != domain.EncapNative {
				link.GRE.UDPPort = uint16(49152 + link.GRE.Key%16384)
			}
		}
	}
	if err != nil || backend == domain.BackendGRE && persistedGREReceiveConflict(snapshot, link) {
		fmt.Fprintln(errOut, "This tunnel's GRE identity conflicts with another saved tunnel. Choose a new attempt.")
		return 2
	}
	if manualPair {
		fmt.Fprintln(out, "Manual setup: configure the OTHER server with REVERSED source/peer IPs.")
		if backend == domain.BackendGRE && link.GRE.KeyEnabled {
			fmt.Fprintf(out, "Use exactly the SAME GRE receive key on the OTHER server: %d (not encryption).\n", link.GRE.Key)
		}
	}
	if err := link.Validate(); err != nil {
		return p.failed(err)
	}
	if _, err := pairing.NewQuickOffer(link, nil); err != nil {
		fmt.Fprintln(errOut, "Cannot construct a compatible peer setup offer; nothing applied.")
		return 2
	}

	fmt.Fprintln(out, "\nReview your tunnel before making any changes:")
	fmt.Fprintf(out, "  Type: %s / %s\n  THIS server: %s (tunnel IP %s)\n  OTHER server: %s (tunnel IP %s)\n",
		link.Backend, link.Encapsulation, route.Source, link.Addresses.Local,
		peer, link.Addresses.Peer)
	fmt.Fprintln(out, "  MTU: Auto estimates a safe local value now; actual peer/MTU tests run AFTER both sides are connected.")
	fmt.Fprintln(out, "  Transport: no encryption; do not send secrets over GRE/IPIP.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish a fresh terminal confirmation; nothing applied.")
		return 2
	}
	confirm, err := p.ask("Create this tunnel now? Type YES to confirm (Enter=no): ")
	if err != nil {
		return p.failed(err)
	}
	if !strings.EqualFold(confirm, "yes") {
		fmt.Fprintln(out, "Create cancelled. No changes applied.")
		return 0
	}
	// Marshal the explicitly versioned v2 automation contract with the
	// endpoint-local policy. The peer's Setup Link never copies this MTU.
	wire := desiredLinkRequestV2{
		SchemaVersion: managedMTUSchemaVersion,
		Link: desiredLinkV2{desiredLinkV1: desiredLinkV1{
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
				UDPPort: link.GRE.UDPPort,
			},
		}, MTU: link.MTU},
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot encode Link intent; nothing applied.")
		return 1
	}
	fmt.Fprintln(out, "Creating the local tunnel and saving reboot restoration...")
	if code := linkLifecycleCommand([]string{"ensure", "--stdin"}, bytes.NewReader(payload), out, errOut, options); code != 0 {
		fmt.Fprintln(errOut, "Tunnel could not be confirmed. Do NOT immediately recreate the same ID; check saved Links and persistence/recovery guidance below.")
		fmt.Fprintln(errOut, "If stage=persistence: check that systemd is PID 1, /etc/systemd/system and /usr/local/bin/stl have trusted root ownership, and systemctl can read its unit. Do not manually delete a possibly owned unit.")
		return code
	}
	if manualPair {
		fmt.Fprintln(out, "\nNEXT: configure the OTHER server using the details below (No Setup Link is needed):")
		printManualConnectionDetails(out, link)
		fmt.Fprintln(out, "You can see these details again in My tunnels -> Connection details.")
		fmt.Fprintln(out, "You can also export a GRE/IPIP Setup Link later in My tunnels -> Share.")
	} else {
		fmt.Fprintln(out, "\nShare this non-secret Setup Link with the OTHER server (available again from Manage -> Share):")
		if code := linkExportCommand([]string{"export", string(link.ID)}, out, errOut, options); code != 0 {
			fmt.Fprintln(errOut, "Local Link was ensured, but setup export failed; use stl link export with this Link ID.")
			return code
		}
		fmt.Fprintln(out, "On the other server: STL menu -> Import -> Plaintext GRE/IPIP -> paste -> review -> YES.")
	}
	fmt.Fprintln(out, "Local observed status (does not prove end-to-end connectivity):")
	if code := linkReadCommand([]string{"status", string(link.ID)}, out, errOut, options); code != 0 {
		fmt.Fprintln(errOut, "Local Link was ensured, but live status could not be verified. Reconcile before relying on it.")
		return code
	}
	diagnose, err := p.yesNo("Has the OTHER server already imported this Link? Run connectivity check now? [y/N]: ")
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
		fmt.Fprintln(errOut, "Peer check could not confirm traffic. Your saved local tunnel remains configured; check the other server and firewall.")
		return code
	}
	return 0
}
