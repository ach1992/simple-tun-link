package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

// Guided Spoof is presentation only: the exact public CLI delegates
// credential issuance, network admission and mutation to the one Engine.
// A handoff is read from a protected file, never echoed into the terminal.
// Spoof Source and Setup Code paths are real Linux filesystem paths, not
// 128-byte menu choices. Use the Linux PATH_MAX bound consistently with
// the existing verified-update menu; short confirmations stay bounded.
func askSpoofPath(p createPrompts, prompt string) (string, error) {
	fmt.Fprint(p.out, menuActionPrompt(p.out, "", prompt))
	result, err := readMenuAnswerBounded(p.reader, unix.PathMax)
	if err != nil {
		return "", err
	}
	if result == "q" || strings.EqualFold(result, "cancel") {
		return "", errCreateCancelled
	}
	return result, nil
}

func askSpoofSourceFile(p createPrompts) (string, error) {
	for {
		answer, err := askSpoofPath(p, "Local Source IPv4 list (Enter="+spoof.DefaultSourcesPath+"; q=back): ")
		if err != nil {
			return "", err
		}
		if answer == "" {
			answer = spoof.DefaultSourcesPath
		}
		for {
			if err := sourceReady(answer); err == nil {
				return answer, nil
			} else {
				menuNotice(p.out, "WARNING", err.Error())
			}
			retry, err := p.ask("Edit/create the Source file, then Enter=Recheck, c=change path, q=back: ")
			if err != nil {
				return "", err
			}
			if strings.EqualFold(retry, "c") {
				break
			}
			if retry != "" {
				menuProse(p.out, "Enter to Recheck, c to change path or q to cancel.")
			}
		}
	}
}

func askSpoofFilePath(p createPrompts, prompt string) (string, error) {
	for {
		value, err := askSpoofPath(p, prompt+" (absolute file path; q=back): ")
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" {
			return value, nil
		}
		menuProse(p.out, "Provide an absolute normalized file path, not a directory.")
	}
}

func askSpoofEndpoints(p createPrompts) (string, string, error) {
	for {
		a, err := p.ask("Creator A's REAL reachable IPv4:port/ICMP identifier (q=back): ")
		if err != nil {
			return "", "", err
		}
		b, err := p.ask("Recipient B's REAL reachable IPv4:port/ICMP identifier (q=back): ")
		if err != nil {
			return "", "", err
		}
		left, errA := netip.ParseAddrPort(a)
		right, errB := netip.ParseAddrPort(b)
		if errA == nil && errB == nil && left.IsValid() && right.IsValid() &&
			left.Addr().Is4() && right.Addr().Is4() &&
			left.Port() != 0 && right.Port() != 0 &&
			!left.Addr().IsUnspecified() && !right.Addr().IsUnspecified() &&
			!left.Addr().IsMulticast() && !right.Addr().IsMulticast() && left != right {
			return a, b, nil
		}
		menuProse(p.out, "Use two different, exact real IPv4 endpoints (example 192.0.2.10:42001).")
	}
}

func askSpoofPrivateIPs(p createPrompts, a, b string) (string, string, error) {
	left, _ := netip.ParseAddrPort(a)
	right, _ := netip.ParseAddrPort(b)
	for {
		aIP, err := p.ask("A private tunnel IPv4 without /32 (q=back): ")
		if err != nil {
			return "", "", err
		}
		bIP, err := p.ask("B private tunnel IPv4 without /32 (q=back): ")
		if err != nil {
			return "", "", err
		}
		first, errA := netip.ParseAddr(aIP)
		second, errB := netip.ParseAddr(bIP)
		if errA == nil && errB == nil && first.Is4() && second.Is4() &&
			first.IsPrivate() && second.IsPrivate() && first != second &&
			first != left.Addr() && first != right.Addr() &&
			second != left.Addr() && second != right.Addr() {
			return aIP, bIP, nil
		}
		menuProse(p.out, "Choose two different private RFC1918 IPv4 addresses, distinct from both real endpoints.")
	}
}

func askSpoofOuter(p createPrompts) (string, error) {
	for {
		menuOption(p.out, "1", "Auto (recommended)", "Find working IPv4 Source and outer profile independently on each server; self-recover")
		menuOption(p.out, "2", "UDP", "Only raw IPv4 UDP")
		menuOption(p.out, "3", "ICMP", "Only unsolicited ICMP Echo Reply")
		menuOption(p.out, "4", "TCP-looking", "Raw TCP RST-framed datagrams, NOT a TCP connection")
		menuOption(p.out, "5", "GRE", "STL experimental GRE packet framing")
		menuOption(p.out, "6", "IPIP", "STL experimental nested-IPv4 framing")
		menuOption(p.out, "7", "Protocol 58", "Bare IPv4 protocol-58 experimental framing")
		menuOption(p.out, "8", "Protocol 58 echo-shaped", "Experimental 58 wrapper (not standards-compliant ICMPv6)")
		menuOption(p.out, "9", "L2TPv3 IP/115", "Experimental L2TPv3-style data header, not the native L2TPv3 backend")
		value, err := p.ask("Outer Source/Transport discovery [1]: ")
		if err != nil {
			return "", err
		}
		switch strings.ToLower(value) {
		case "", "1", "auto":
			return "auto", nil
		case "2", "udp":
			return "udp", nil
		case "3", "icmp":
			return "icmp", nil
		case "4", "tcp":
			return "tcp", nil
		case "5", "gre":
			return "gre", nil
		case "6", "ipip":
			return "ipip", nil
		case "7", "proto58":
			return "proto58", nil
		case "8", "proto58-echo":
			return "proto58-echo", nil
		case "9", "l2tpv3":
			return "l2tpv3", nil
		default:
			menuProse(p.out, "Select Auto or a listed STL outer packet profile.")
		}
	}
}

func askSpoofTxPreference(p createPrompts, outer string) (string, error) {
	if outer != "auto" {
		return "", nil
	}
	for {
		candidate, err := p.ask("Optional outgoing profile lock for THIS server (Enter=Auto, else udp/icmp/tcp/gre/ipip/proto58/proto58-echo/l2tpv3): ")
		if err != nil {
			return "", err
		}
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" || candidate == "auto" {
			return "", nil
		}
		if spoof.ValidProfile(candidate) {
			return candidate, nil
		}
		menuProse(p.out, "Choose a known STL profile or Enter to keep automatic discovery.")
	}
}

func menuCreateSpoof(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	menuScreen(out, "Create / Spoof Direct TUN")
	menuProse(out, "Encrypted Linux private IPv4 TUN. No peer connection is needed now; Source lists belong separately to each server.")
	menuNotice(out, "WARNING", "Send only with Source IPs and peer destinations your network operator authorizes; STL does not verify Source ownership or override provider filtering.")
	source, err := askSpoofSourceFile(p)
	if err != nil {
		return p.failed(err)
	}
	outer, err := askSpoofOuter(p)
	if err != nil {
		return p.failed(err)
	}
	txProfile, err := askSpoofTxPreference(p, outer)
	if err != nil {
		return p.failed(err)
	}
	a, b, err := askSpoofEndpoints(p)
	if err != nil {
		return p.failed(err)
	}
	aExtras, err := p.ask("Optional A alternate receive IPv4:port endpoints (comma-separated, Enter=none): ")
	if err != nil {
		return p.failed(err)
	}
	bExtras, err := p.ask("Optional B alternate receive IPv4:port endpoints (comma-separated, Enter=none): ")
	if err != nil {
		return p.failed(err)
	}
	aPrimary, _ := netip.ParseAddrPort(a)
	bPrimary, _ := netip.ParseAddrPort(b)
	if _, err := parseSpoofAltInput(aExtras, aPrimary); err != nil {
		return p.failed(err)
	}
	if _, err := parseSpoofAltInput(bExtras, bPrimary); err != nil {
		return p.failed(err)
	}
	aIP, bIP, err := askSpoofPrivateIPs(p, a, b)
	if err != nil {
		return p.failed(err)
	}
	device, err := p.ask("Optional sending network interface (Enter=kernel route): ")
	if err != nil {
		return p.failed(err)
	}
	mtuRaw, err := p.ask("Local private TUN MTU (Enter=Auto, else 576..65431): ")
	if err != nil {
		return p.failed(err)
	}
	if _, err = parseSpoofMTU(mtuRaw); err != nil {
		return p.failed(err)
	}
	manageAnswer, err := p.ask("Manage exact Link-owned IPv4 ingress firewall rules on selected interface? (yes/Enter=no): ")
	if err != nil {
		return p.failed(err)
	}
	manageIngress := strings.EqualFold(manageAnswer, "yes") || strings.EqualFold(manageAnswer, "y")
	if manageAnswer != "" && !manageIngress && !strings.EqualFold(manageAnswer, "no") && !strings.EqualFold(manageAnswer, "n") {
		return p.failed(fmt.Errorf("answer yes or no for managed Spoof ingress"))
	}
	if manageIngress && device == "" {
		return p.failed(fmt.Errorf("managed ingress requires an exact local network interface; supply the sending/receiving interface"))
	}

	output, err := askSpoofFilePath(p, "Confidential Setup Code output file")
	if err != nil {
		return p.failed(err)
	}

	menuScreen(out, "Review / Spoof Link")
	menuField(out, "Outer carrier", outer)
	if txProfile != "" {
		menuField(out, "Local outgoing profile", txProfile)
	}
	menuField(out, "A real endpoint", a)
	menuField(out, "B real endpoint", b)
	if aExtras != "" {
		menuField(out, "A alternate receivers", aExtras)
	}
	if bExtras != "" {
		menuField(out, "B alternate receivers", bExtras)
	}
	menuField(out, "Private Link IPv4", aIP+" <-> "+bIP)
	menuField(out, "Local source list", source)
	if manageIngress {
		menuField(out, "Managed IPv4 INPUT", "ON (exact Link-owned rules on "+device+")")
	}
	if mtuRaw != "" {
		menuField(out, "Local TUN MTU", mtuRaw)
	}
	menuField(out, "Outgoing device", device)
	menuField(out, "Protected Setup Code", output)
	menuNotice(out, "WARNING", "Create provisions only this host's managed Link, protected credentials, TUN and restore intent. It does not prove peer connectivity. Transfer the Code privately only once.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		return p.failed(err)
	}
	yes, err := p.askAction("YES", "Type YES to create this pending Spoof Link (Enter=cancel): ")
	if err != nil {
		return p.failed(err)
	}
	if !strings.EqualFold(yes, "yes") {
		menuNotice(out, "INFO", "Cancelled. No new Spoof Link was created.")
		return 0
	}
	args := []string{"create-spoof", "--creator", a, "--recipient", b,
		"--creator-private", aIP, "--recipient-private", bIP,
		"--sources", source, "--outer", outer, "--output", output}
	if aExtras != "" {
		args = append(args, "--creator-alts", aExtras)
	}
	if bExtras != "" {
		args = append(args, "--recipient-alts", bExtras)
	}
	if txProfile != "" {
		args = append(args, "--tx-outer", txProfile)
	}
	if mtuRaw != "" {
		args = append(args, "--mtu", mtuRaw)
	}
	if manageIngress {
		args = append(args, "--manage-ingress")
	}
	if device != "" {
		args = append(args, "--device", device)
	}
	code := linkSpoofCommand(args, out, errOut, opts)
	if code == 0 {
		menuNotice(out, "OK", "Local Spoof Link provisioned; transfer the original confidential Code file to B, then Import on B. Link status is not proof of connectivity.")
	}
	return code
}

func menuImportSpoof(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, opts *runtimeOptions) int {
	p := createPrompts{reader: reader, out: out, errOut: errOut}
	menuScreen(out, "Import / Spoof Direct TUN")
	menuProse(out, "Transfer A's original confidential Setup Code to a protected 0600 file on this server. Never paste the secret into an ordinary shell command.")
	setupFile, err := askSpoofFilePath(p, "Original confidential Setup Code file on THIS server")
	if err != nil {
		return p.failed(err)
	}
	offer, err := readProtectedOffer(setupFile)
	if err != nil {
		menuNotice(out, "WARNING", "The protected Setup Code is missing, unsafe or invalid. No Link was changed.")
		return 1
	}
	source, err := askSpoofSourceFile(p)
	if err != nil {
		return p.failed(err)
	}
	txProfile, err := askSpoofTxPreference(p, offer.OuterProtocol())
	if err != nil {
		return p.failed(err)
	}
	device, err := p.ask("Optional sending network interface (Enter=kernel route): ")
	if err != nil {
		return p.failed(err)
	}
	mtuRaw, err := p.ask("Local private TUN MTU (Enter=Auto, else 576..65431): ")
	if err != nil {
		return p.failed(err)
	}
	if _, err = parseSpoofMTU(mtuRaw); err != nil {
		return p.failed(err)
	}
	manageAnswer, err := p.ask("Manage exact Link-owned IPv4 ingress firewall rules on selected interface? (yes/Enter=no): ")
	if err != nil {
		return p.failed(err)
	}
	manageIngress := strings.EqualFold(manageAnswer, "yes") || strings.EqualFold(manageAnswer, "y")
	if manageAnswer != "" && !manageIngress && !strings.EqualFold(manageAnswer, "no") && !strings.EqualFold(manageAnswer, "n") {
		return p.failed(fmt.Errorf("answer yes or no for managed Spoof ingress"))
	}
	if manageIngress && device == "" {
		return p.failed(fmt.Errorf("managed ingress requires an exact local network interface; supply the sending/receiving interface"))
	}

	menuScreen(out, "Review / recipient Spoof Link")
	menuField(out, "Link ID", string(offer.LinkID()))
	menuField(out, "Outer carrier", offer.OuterProtocol())
	if txProfile != "" {
		menuField(out, "Local outgoing profile", txProfile)
	}
	menuField(out, "B real receive endpoint", offer.RecipientEndpoint().String())
	menuField(out, "A real peer endpoint", offer.CreatorEndpoint().String())
	if len(offer.RecipientAlternates()) > 0 {
		menuField(out, "B alternate receivers", fmt.Sprint(offer.RecipientAlternates()))
	}
	if len(offer.CreatorAlternates()) > 0 {
		menuField(out, "A alternate receivers", fmt.Sprint(offer.CreatorAlternates()))
	}
	menuField(out, "Private IPv4 B -> A", offer.RecipientPrivateIPv4().String()+" -> "+offer.CreatorPrivateIPv4().String())
	menuField(out, "Local source list", source)
	if manageIngress {
		menuField(out, "Managed IPv4 INPUT", "ON (exact Link-owned rules on "+device+")")
	}
	if mtuRaw != "" {
		menuField(out, "Local TUN MTU", mtuRaw)
	}
	menuField(out, "Outgoing device", device)
	menuNotice(out, "WARNING", "B generates and retains its own private identity. This confirmed Import only provisions local resources; successful authentication is observed later.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		return p.failed(err)
	}
	yes, err := p.askAction("YES", "Type YES to import this original Spoof Link (Enter=cancel): ")
	if err != nil {
		return p.failed(err)
	}
	if !strings.EqualFold(yes, "yes") {
		menuNotice(out, "INFO", "Cancelled. No Spoof Link was imported.")
		return 0
	}
	args := []string{"import-spoof", "--setup", setupFile, "--sources", source}
	if txProfile != "" {
		args = append(args, "--tx-outer", txProfile)
	}
	if mtuRaw != "" {
		args = append(args, "--mtu", mtuRaw)
	}
	if manageIngress {
		args = append(args, "--manage-ingress")
	}
	if device != "" {
		args = append(args, "--device", device)
	}
	code := linkSpoofCommand(args, out, errOut, opts)
	if code == 0 {
		menuNotice(out, "OK", "Spoof Link imported; verify authenticated bilateral status and private application traffic on both ends.")
	}
	return code
}
