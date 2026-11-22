package main

import (
	"bufio"
	"io"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

// Guided Spoof is presentation only: the exact public CLI delegates
// credential issuance, network admission and mutation to the one Engine.
// A handoff is read from a protected file, never echoed into the terminal.
func askSpoofSourceFile(p createPrompts) (string, error) {
	for {
		answer, err := p.ask("Local Source IPv4 list (Enter=" + spoof.DefaultSourcesPath + "; q=back): ")
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
		value, err := p.ask(prompt + " (absolute file path; q=back): ")
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
		menuOption(p.out, "1", "UDP", "Raw UDP with a local receive port (default)")
		menuOption(p.out, "2", "ICMP", "Raw ICMP Echo Reply with a per-Link receive identifier")
		value, err := p.ask("Outer packet profile [1]: ")
		if err != nil {
			return "", err
		}
		switch strings.ToLower(value) {
		case "", "1", "udp":
			return "udp", nil
		case "2", "icmp":
			return "icmp", nil
		default:
			menuProse(p.out, "Choose 1 for UDP or 2 for ICMP. This setting is pinned in the offline Code.")
		}
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
	a, b, err := askSpoofEndpoints(p)
	if err != nil {
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
	output, err := askSpoofFilePath(p, "Confidential Setup Code output file")
	if err != nil {
		return p.failed(err)
	}

	menuScreen(out, "Review / Spoof Link")
	menuField(out, "Outer carrier", outer)
	menuField(out, "A real endpoint", a)
	menuField(out, "B real endpoint", b)
	menuField(out, "Private Link IPv4", aIP+" <-> "+bIP)
	menuField(out, "Local source list", source)
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
	device, err := p.ask("Optional sending network interface (Enter=kernel route): ")
	if err != nil {
		return p.failed(err)
	}
	menuScreen(out, "Review / recipient Spoof Link")
	menuField(out, "Link ID", string(offer.LinkID()))
	menuField(out, "Outer carrier", offer.OuterProtocol())
	menuField(out, "B real receive endpoint", offer.RecipientEndpoint().String())
	menuField(out, "A real peer endpoint", offer.CreatorEndpoint().String())
	menuField(out, "Private IPv4 B -> A", offer.RecipientPrivateIPv4().String()+" -> "+offer.CreatorPrivateIPv4().String())
	menuField(out, "Local source list", source)
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
	if device != "" {
		args = append(args, "--device", device)
	}
	code := linkSpoofCommand(args, out, errOut, opts)
	if code == 0 {
		menuNotice(out, "OK", "Spoof Link imported; verify authenticated bilateral status and private application traffic on both ends.")
	}
	return code
}
