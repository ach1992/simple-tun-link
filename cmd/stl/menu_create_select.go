package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
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
func selectTunnelSubmenu(reader *bufio.Reader, out io.Writer, manual bool) (tunnelOption, bool) {
	for {
		var options map[string]tunnelOption
		if manual {
			options = manualTunnelOptions
			menuScreen(out, "Manual two-server configuration")
			menuOption(out, "1", "GRE / Native", "No encryption; optional key")
			menuOption(out, "2", "IPIP / Native", "No encryption")
		} else {
			options = advancedTunnelOptions
			menuScreen(out, "Advanced tunnel types")
			menuOption(out, "1", "GRE / FOU", "Unencrypted over UDP")
			menuOption(out, "2", "GRE / GUE", "Unencrypted over UDP")
			menuOption(out, "3", "IPIP / FOU", "Unencrypted over UDP")
			menuOption(out, "4", "IPIP / GUE", "Unencrypted over UDP")
			menuOption(out, "5", "IPsec / ESP", "Encrypted; requires strongSwan")
			menuOption(out, "6", "IPsec / NAT-T", "Encrypted UDP; strongSwan")
		}
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
		if selected, ok := options[value]; ok {
			return selected, true
		}
		fmt.Fprintln(out, "Not a listed type. Choose a number above.")
	}
}

// One Create entry for every backend. Ordinary GRE Native requires only one
// menu number. Manual and unusual transports have their own short submenus.
func menuCreate(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	for {
		menuScreen(out, "CREATE TUNNEL / choose a type")
		menuOption(out, "1", "GRE / Native", "Default; not encrypted")
		menuOption(out, "2", "WireGuard / UDP", "Encrypted")
		menuOption(out, "3", "IPIP / Native", "Not encrypted")
		menuOption(out, "4", "Manual connection", "Set up both ends by hand")
		menuOption(out, "5", "Advanced types", "FOU / GUE / IPsec")
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
		if value == "" {
			value = "1"
		}
		var picked tunnelOption
		var ok bool
		switch value {
		case "4":
			picked, ok = selectTunnelSubmenu(reader, out, true)
			if !ok {
				continue
			}
		case "5":
			picked, ok = selectTunnelSubmenu(reader, out, false)
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
			return menuCreatePlain(input, reader, out, errOut, options, picked.backend, picked.mode, picked.manual)
		}
	}
}
