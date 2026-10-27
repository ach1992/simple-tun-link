package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// Manage uses a numbered human selection and the exact canonical Engine.
func menuManage(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	links, err := savedMenuLinks(options)
	if err != nil {
		menuSessionErrorNotice(out, errOut, "Cannot load saved tunnels; inspect local State without changing it.")
		menuAcknowledge(input, reader, out)
		return 1
	}
	id, _, err := chooseMenuLink(reader, out, links, false)
	if err != nil {
		menuAcknowledge(input, reader, out)
		return 1
	}
	if id == "" {
		if len(links) == 0 {
			menuAcknowledge(input, reader, out)
		}
		return 0
	}
	var selected domain.Link
	found := false
	for _, record := range links {
		if record.Desired.ID == id {
			selected = record.Desired
			found = true
			break
		}
	}
	if !found {
		return 1
	}
	// Keep the selection visible on every subsequent screen. Never require
	// a human to memorize the opaque Link ID across submenus.
	for {
		menuScreen(out, "My tunnels / selected tunnel")
		menuField(out, "Type", fmt.Sprintf("%s / %s", selected.Backend, selected.Encapsulation))
		menuField(out, "Local IP", selected.Addresses.Local.String())
		menuField(out, "Other IP", selected.Addresses.Peer.String())
		menuSection(out, "Tunnel actions")
		menuOption(out, "1", "Local status", "Read-only")
		menuOption(out, "2", "Check connection", "Read-only diagnostics")
		if selected.Backend == domain.BackendWireGuardWSS {
			menuActionOption(out, "3", "Share Setup Link", "Original sender offer only; may require private file", "SHOW")
		} else {
			menuActionOption(out, "3", "Share Setup Link", "Copy original link safely", "SHOW")
		}
		menuOption(out, "4", "Connection details", "View both server settings")
		menuActionOption(out, "5", "Remove this tunnel", "Destructive; confirm", "REMOVE")
		menuActionOption(out, "6", "Delete receiver link", "Only the original menu-saved private offer", "DELETE")
		if selected.Backend == domain.BackendIPsec {
			menuActionOption(out, "7", "Connect IPsec", "Explicit IKEv2 initiation after peer import", "CONNECT")
		}
		menuOption(out, "0", "Back", "Main menu")
		fmt.Fprint(out, "Choose an action: ")
		action, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			fmt.Fprintln(out, "Enter a short action number.")
			continue
		}
		if action != "" && action != "0" && !strings.EqualFold(action, "q") && !strings.EqualFold(action, "b") {
			menuScreen(out, "Tunnel / result")
			menuField(out, "Type", fmt.Sprintf("%s / %s", selected.Backend, selected.Encapsulation))
			menuField(out, "Local IP", selected.Addresses.Local.String())
			menuField(out, "Other IP", selected.Addresses.Peer.String())
		}
		switch strings.ToLower(action) {
		case "", "0", "b", "q":
			return 0
		case "1", "s":
			if code := menuShowLocalStatus(id, out, errOut, options); code != 0 && !menuEscapeCapable(out) {
				fmt.Fprintln(out, "Local status not confirmed. Saved tunnel unchanged.")
			}
		case "2", "d":
			if code := menuCheckOneConnection(id, out, errOut, options); code != 0 && !menuEscapeCapable(out) {
				fmt.Fprintln(out, "Connection not verified; check peer setup and firewall.")
			}
		case "3", "e":
			if selected.Backend == domain.BackendGRE || selected.Backend == domain.BackendIPIP {
				if code := menuSharePlainLink(id, out, errOut, options); code != 0 {
					menuProse(out, "Setup Link cannot be rebuilt from the current saved state. No network changes made.")
				}
			} else {
				// No backend/Engine mutation. Display only the exactly
				// saved original receiver secret after a fresh TTY consent,
				// and verify full current Link identity before disclosure.
				menuSensitiveHandoffAction(input, reader, out, errOut, options, selected, false)
			}
		case "4", "i":
			current, err := savedMenuLinks(options)
			if err != nil {
				menuNotice(out, "FAILED", "Cannot read saved tunnel settings; nothing changed.")
				menuAcknowledge(input, reader, out)
				continue
			}
			found := false
			for _, record := range current {
				if record.Desired.ID == id {
					printManualConnectionDetails(out, record.Desired)
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintln(out, "This tunnel is no longer saved; return to My tunnels and select again.")
				return 0
			}
		case "5", "r":
			code := menuRemoveLink(input, reader, out, errOut, options, selected)
			menuAcknowledge(input, reader, out)
			return code
		case "6":
			if selected.Backend == domain.BackendGRE || selected.Backend == domain.BackendIPIP {
				menuNotice(out, "INFO", "Plaintext links are generated on demand; there is no private receiver file.")
				menuAcknowledge(input, reader, out)
				continue
			}
			menuSensitiveHandoffAction(input, reader, out, errOut, options, selected, true)
		case "7":
			if selected.Backend != domain.BackendIPsec {
				menuNotice(out, "WARNING", "Connect IPsec is available for saved IPsec tunnels only.")
				break
			}
			menuConnectIPsec(input, reader, out, errOut, options, selected)
		default:
			menuNotice(out, "WARNING", "Choose an available tunnel action.")
		}
		menuAcknowledge(input, reader, out)
	}
}

// A menu removal requires a real local TTY. Noninteractive consumers already
// have an explicit, versioned Engine-backed CLI remove command with matching
// Link-ID confirmation, and must never rely on terminal transcript parsing.
func menuRemoveLink(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, selected domain.Link) int {
	stdin, stdinOK := input.(*os.File)
	stdout, stdoutOK := out.(*os.File)
	if !stdinOK || !stdoutOK || !terminalIsInteractive(stdin) || !terminalIsInteractive(stdout) {
		fmt.Fprintln(errOut, "Manage removal requires an interactive terminal; use stl link remove <id> --confirm <id> for automation. No changes made.")
		return 2
	}
	menuActionSection(out, "Remove tunnel / preview", "REMOVE")
	menuHealthLine(out, "Current action", "WARNING", "PREVIEW ONLY - no tunnel has been removed")
	menuField(out, "Tunnel", fmt.Sprintf("%s / %s", selected.Backend, selected.Encapsulation))
	menuField(out, "Tunnel IPs", selected.Addresses.Local.String()+" -> "+selected.Addresses.Peer.String())
	menuField(out, "Underlay IPs", selected.Underlay.Local.String()+" -> "+selected.Underlay.Peer.String())
	menuNotice(out, "WARNING", "Removing this Link can disconnect applications using its tunnel IPs.")
	fmt.Fprintln(out, "Only this Link's verified resources will be removed; other Links remain isolated.")
	fmt.Fprintln(out, "A partial result is NOT safe to retry until its current state is inspected.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish a fresh terminal confirmation; no changes made.")
		return 2
	}
	fmt.Fprintf(out, "\nTo permanently REMOVE this tunnel, type %s (Enter cancels): ", menuActionToken(out, "REMOVE"))
	confirm, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && confirm != "REMOVE" {
		fmt.Fprintln(out, "Removal cancelled. No changes made.")
		return 0
	}
	if err != nil {
		fmt.Fprintln(errOut, "Invalid removal confirmation; no changes made.")
		return 2
	}

	// The confirmed desired Link is checked inside the canonical Engine's
	// per-Link lock, before backend inspection, planning or mutation. A menu-
	// level recheck here would be racy with concurrent Engine.Ensure.
	code := executeLinkMutationConditional("link_remove", domain.Link{}, selected.ID, false,
		out, errOut, options, &selected)
	if code == 0 {
		menuScreen(out, "Remove / complete")
		menuNotice(out, "OK", "Selected tunnel removed. Other Links were not selected for removal.")
	}
	return code
}
