package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"golang.org/x/sys/unix"
)

func plainBackendCapability(backend domain.Backend, mode domain.Encapsulation) linux.Capability {
	switch {
	case backend == domain.BackendGRE && mode == domain.EncapNative:
		return linux.CapabilityGRENative
	case backend == domain.BackendGRE && mode == domain.EncapFOU:
		return linux.CapabilityGREFOU
	case backend == domain.BackendGRE && mode == domain.EncapGUE:
		return linux.CapabilityGREGUE
	case backend == domain.BackendIPIP && mode == domain.EncapNative:
		return linux.CapabilityIPIPNative
	case backend == domain.BackendIPIP && mode == domain.EncapFOU:
		return linux.CapabilityIPIPFOU
	case backend == domain.BackendIPIP && mode == domain.EncapGUE:
		return linux.CapabilityIPIPGUE
	}
	return ""
}

func askPeerUnderlay(p createPrompts) (netip.Addr, error) {
	for {
		value, err := p.ask("Other server's reachable IPv4 address (public/private; q=back): ")
		if err != nil {
			return netip.Addr{}, err
		}
		peer, err := netip.ParseAddr(value)
		if err != nil || !peer.Is4() || !peer.IsGlobalUnicast() || peer.IsLoopback() || peer.IsLinkLocalUnicast() {
			fmt.Fprintln(p.out, "Enter an actual reachable IPv4 address for the OTHER server, like 192.0.2.20.")
			continue
		}
		return peer, nil
	}
}

func chooseManagedMTU(p createPrompts, mtu *domain.MTUPolicy) error {
	for {
		fmt.Fprintln(p.out, "MTU on THIS server (no remote measurement before a tunnel exists):")
		fmt.Fprintln(p.out, "  1  Auto (recommended: local estimate from protocol and route)")
		fmt.Fprintln(p.out, "  2  Manual (bytes, advanced)")
		fmt.Fprintln(p.out, "  3  Unmanaged (keep kernel/default setting)")
		choice, err := p.ask("Choose [1]: ")
		if err != nil {
			return err
		}
		switch choice {
		case "", "1":
			*mtu = domain.MTUPolicy{Mode: domain.MTUAuto}
			return nil
		case "2":
			raw, err := p.ask("MTU bytes (example 1300; q=back): ")
			if err != nil {
				return err
			}
			v, err := strconv.Atoi(raw)
			next := domain.MTUPolicy{Mode: domain.MTUManual, Bytes: v}
			if err != nil || next.Validate() != nil {
				fmt.Fprintln(p.out, "MTU must be a valid IPv4 byte count; try again.")
				continue
			}
			*mtu = next
			return nil
		case "3":
			*mtu = domain.MTUPolicy{Mode: domain.MTUUnmanagedExplicit}
			return nil
		default:
			fmt.Fprintln(p.out, "Choose 1, 2 or 3.")
		}
	}
}

type tunnelOption struct {
	backend domain.Backend
	mode    domain.Encapsulation
	manual  bool
}

// Capability hints are observational snapshots, not authorization to load
// modules, start strongSwan, or promise final Engine/admission success.
func menuCapabilitySnapshot(options *runtimeOptions) linux.CapabilityReport {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := (linux.CapabilityProbe{Runner: createRunner(options)}).Probe(ctx)
	if err != nil {
		return nil // unknown, never convert probe failure to "supported"
	}
	return report
}

func menuCapabilityHint(report linux.CapabilityReport, choice tunnelOption) (string, string) {
	capability := plainBackendCapability(choice.backend, choice.mode)
	switch choice.backend {
	case domain.BackendWireGuard:
		capability = linux.CapabilityWireGuard
	case domain.BackendIPsec:
		capability = linux.CapabilityIPsecXFRM
	}
	if report == nil || capability == "" {
		return "[Check needed]", menuBlue
	}
	status, found := report[capability]
	if !found {
		return "[Check needed]", menuBlue
	}
	if !status.Available {
		if status.ReasonCode == "fou_module_present_probe_failed" {
			return "[Needs setup]", menuYellow
		}
		// A failed read-only query is not proof that a kernel or provider
		// permanently lacks the capability. Never guess "Unsupported".
		return "[Check needed]", menuYellow
	}
	if choice.backend == domain.BackendIPsec {
		return "[Verify service]", menuBlue
	}
	return "[Precheck OK]", menuGreen
}

func menuTunnelOption(out io.Writer, number, name, description string, report linux.CapabilityReport, choice tunnelOption) {
	label, role := menuCapabilityHint(report, choice)
	coloredStatus := menuPaint(out, role, fmt.Sprintf("%-16s", label))
	optionNumber := menuPaint(out, menuCyan, fmt.Sprintf("%2s", number))
	// Default layout also works in redirected output; narrow PTYs split the
	// note rather than relying on terminal wrapping or misaligned ANSI width.
	narrow := false
	if file, ok := menuTerminal(out); ok {
		if ws, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
			narrow = int(ws.Col) < 83
		}
	}
	if narrow {
		fmt.Fprintf(out, "  %s  %-20s %s\n      %s\n", optionNumber, name, coloredStatus, menuPaint(out, menuDim, description))
	} else {
		fmt.Fprintf(out, "  %s  %-20s %s %s\n", optionNumber, name, coloredStatus, menuPaint(out, menuDim, description))
	}
}

// Explain shared prerequisites once: four UDP modes use one FOU
// observation, and both IPsec transports share XFRM+swanctl preflight.
// This help is observational; it never loads modules or fixes a host.
func menuCapabilityHelp(out io.Writer, report linux.CapabilityReport) {
	menuScreen(out, "Availability / explanation")
	menuSection(out, "How to read the badges")
	menuHealthLine(out, "Precheck OK", "OK", "Basic tool query passed; actual Create is checked again")
	menuHealthLine(out, "Needs setup", "WARNING", "A module was found, but runtime use is not confirmed")
	menuHealthLine(out, "Check needed", "WARNING", "A read-only query failed; permanent lack of support is NOT proven")
	menuHealthLine(out, "Verify service", "INFO", "IPsec still requires STL-exclusive strongSwan ownership")
	menuSection(out, "Host findings / shared prerequisites")
	if report == nil {
		menuNotice(out, "WARNING", "Host inspection timed out or failed; no support claim is possible.")
	} else {
		showGroup := func(label string, capabilities ...linux.Capability) {
			for _, c := range capabilities {
				if status, ok := report[c]; ok && !status.Available {
					menuField(out, label, status.Reason)
					return
				}
			}
		}
		showGroup("GRE native", linux.CapabilityGRENative)
		showGroup("IPIP native", linux.CapabilityIPIPNative)
		// Group all four only if they really failed for the SAME FOU
		// prerequisite. Otherwise do not imply that the other backend
		// or all its UDP modes failed.
		greFOU, grePresent := report[linux.CapabilityGREFOU]
		ipipFOU, ipipPresent := report[linux.CapabilityIPIPFOU]
		if grePresent && ipipPresent && !greFOU.Available && !ipipFOU.Available &&
			greFOU.ReasonCode != "" && greFOU.ReasonCode == ipipFOU.ReasonCode &&
			(greFOU.ReasonCode == "fou_probe_unconfirmed" ||
				greFOU.ReasonCode == "fou_module_present_probe_failed") {
			showGroup("FOU/GUE x4", linux.CapabilityGREFOU, linux.CapabilityGREGUE,
				linux.CapabilityIPIPFOU, linux.CapabilityIPIPGUE)
		} else {
			showGroup("GRE UDP x2", linux.CapabilityGREFOU, linux.CapabilityGREGUE)
			showGroup("IPIP UDP x2", linux.CapabilityIPIPFOU, linux.CapabilityIPIPGUE)
		}
		showGroup("WireGuard", linux.CapabilityWireGuard)
		showGroup("IPsec x2", linux.CapabilityIPsecXFRM)
	}
	menuSection(out, "Read-only checks / next steps")
	menuField(out, "FOU/GUE", "ip fou show")
	menuField(out, "FOU module", "modinfo fou")
	menuField(out, "IPsec tools", "command -v swanctl")
	menuField(out, "IPsec readiness", "stl doctor ipsec --json")
	menuNotice(out, "INFO", "Kernel modules, packages, network Links and services were NOT changed.")
}

// Keep common choices on one short screen; the six less common transports
// and no-Link workflows are visible only when the operator asks for them.
var basicTunnelOptions = map[string]tunnelOption{
	"1": {domain.BackendGRE, domain.EncapNative, false},
	"2": {domain.BackendWireGuard, domain.EncapUDP, false},
	"3": {domain.BackendIPIP, domain.EncapNative, false},
}
var manualTunnelOptions = map[string]tunnelOption{
	"1": {domain.BackendGRE, domain.EncapNative, true},
	"2": {domain.BackendIPIP, domain.EncapNative, true},
}
var advancedTunnelOptions = map[string]tunnelOption{
	"1": {domain.BackendGRE, domain.EncapFOU, false},
	"2": {domain.BackendGRE, domain.EncapGUE, false},
	"3": {domain.BackendIPIP, domain.EncapFOU, false},
	"4": {domain.BackendIPIP, domain.EncapGUE, false},
	"5": {domain.BackendIPsec, domain.EncapESP, false},
	"6": {domain.BackendIPsec, domain.EncapNATT, false},
}

// Only menu-visible selections; live capability admission still belongs to
// the canonical backend CLI/Engine at the moment it is invoked.
func selectTunnelSubmenu(input io.Reader, reader *bufio.Reader, out io.Writer, manual bool, report linux.CapabilityReport) (tunnelOption, bool) {
	for {
		var options map[string]tunnelOption
		if manual {
			options = manualTunnelOptions
			menuScreen(out, "Manual two-server configuration")
			menuTunnelOption(out, "1", "GRE / Native", "No encryption; optional key", report, manualTunnelOptions["1"])
			menuTunnelOption(out, "2", "IPIP / Native", "No encryption", report, manualTunnelOptions["2"])
		} else {
			options = advancedTunnelOptions
			menuScreen(out, "Advanced tunnel types")
			menuTunnelOption(out, "1", "GRE / FOU", "Unencrypted over UDP", report, advancedTunnelOptions["1"])
			menuTunnelOption(out, "2", "GRE / GUE", "Unencrypted over UDP", report, advancedTunnelOptions["2"])
			menuTunnelOption(out, "3", "IPIP / FOU", "Unencrypted over UDP", report, advancedTunnelOptions["3"])
			menuTunnelOption(out, "4", "IPIP / GUE", "Unencrypted over UDP", report, advancedTunnelOptions["4"])
			menuTunnelOption(out, "5", "IPsec / ESP", "Encrypted; requires strongSwan", report, advancedTunnelOptions["5"])
			menuTunnelOption(out, "6", "IPsec / NAT-T", "Encrypted UDP; strongSwan", report, advancedTunnelOptions["6"])
		}
		menuOption(out, "i", "Availability details", "Explain unavailable types")
		menuOption(out, "0", "Back", "Tunnel choices")
		fmt.Fprint(out, "Choose a type: ")
		value, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return tunnelOption{}, false
		}
		if err != nil {
			fmt.Fprintln(out, "Enter a short number, or 0 to return.")
			continue
		}
		if value == "" || value == "0" || strings.EqualFold(value, "q") {
			return tunnelOption{}, false
		}
		if strings.EqualFold(value, "i") {
			menuCapabilityHelp(out, report)
			menuAcknowledge(input, reader, out)
			continue
		}
		if selected, ok := options[value]; ok {
			return selected, true
		}
		fmt.Fprintln(out, "Not a listed type. Choose a number above.")
	}
}

// One Create entry for every backend. Ordinary GRE Native requires only one
// menu number. Manual and unusual transports have their own short submenus.
func menuCreate(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	report := menuCapabilitySnapshot(options)
	for {
		menuScreen(out, "CREATE TUNNEL / choose a type")
		menuTunnelOption(out, "1", "GRE / Native", "Default; not encrypted", report, basicTunnelOptions["1"])
		menuTunnelOption(out, "2", "WireGuard / UDP", "Encrypted", report, basicTunnelOptions["2"])
		menuTunnelOption(out, "3", "IPIP / Native", "Not encrypted", report, basicTunnelOptions["3"])
		menuOption(out, "4", "Manual connection", "Set up both ends by hand")
		menuOption(out, "5", "Advanced types", "FOU / GUE / IPsec")
		menuOption(out, "i", "Availability details", "Explain why a type is unavailable")
		menuOption(out, "0", "Back", "Main menu")
		fmt.Fprint(out, "Tunnel type [1]: ")
		value, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			menuNotice(out, "WARNING", "Enter a listed tunnel number.")
			continue
		}
		if value == "0" || strings.EqualFold(value, "q") {
			return 0
		}
		if strings.EqualFold(value, "i") {
			menuCapabilityHelp(out, report)
			menuAcknowledge(input, reader, out)
			continue
		}
		if value == "" {
			value = "1"
		}
		var picked tunnelOption
		var ok bool
		switch value {
		case "4":
			picked, ok = selectTunnelSubmenu(input, reader, out, true, report)
			if !ok {
				continue
			}
		case "5":
			picked, ok = selectTunnelSubmenu(input, reader, out, false, report)
			if !ok {
				continue
			}
		default:
			picked, ok = basicTunnelOptions[value]
			if !ok {
				menuNotice(out, "WARNING", "Choose one of the listed numbers.")
				continue
			}
		}
		menuScreen(out, "New tunnel / setup")
		switch picked.backend {
		case domain.BackendWireGuard:
			return menuCreateWireGuard(input, reader, out, errOut, options)
		case domain.BackendIPsec:
			return menuCreateIPsec(input, reader, out, errOut, options, picked.mode)
		default:
			return menuCreatePlain(input, reader, out, errOut, options, picked.backend, picked.mode, picked.manual, report)
		}
	}
}
