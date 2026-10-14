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
		fmt.Fprintln(errOut, "Cannot load saved tunnels; check State directory permissions.")
		return 1
	}
	id, _, err := chooseMenuLink(reader, out, links, false)
	if err != nil {
		return 1
	}
	if id == "" {
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
	fmt.Fprintf(out, "Selected: %s / %s | THIS %s | OTHER %s\n",
		selected.Backend, selected.Encapsulation, selected.Addresses.Local, selected.Addresses.Peer)
	for {
		fmt.Fprintln(out, "\n  1  Status (local, read-only)")
		fmt.Fprintln(out, "  2  Check connection (read-only)")
		fmt.Fprintln(out, "  3  Share Setup Link (repeatable; encrypted links ask before showing)")
		fmt.Fprintln(out, "  4  Connection details (copy both server IPs / manual setup)")
		fmt.Fprintln(out, "  5  Remove this tunnel (asks for confirmation)")
		fmt.Fprintln(out, "  6  Delete saved receiver Setup Link (WireGuard / IPsec only)")
		fmt.Fprintln(out, "  0  Back")
		fmt.Fprint(out, "Choose an action: ")
		action, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			fmt.Fprintln(out, "Enter a short action number.")
			continue
		}
		switch strings.ToLower(action) {
		case "", "0", "b", "q":
			return 0
		case "1", "s":
			if code := linkReadCommand([]string{"status", string(id)}, out, errOut, options); code != 0 {
				fmt.Fprintln(out, "Local status is not confirmed. The saved Link was not changed.")
			}
		case "2", "d":
			if code := linkDiagnoseCommand([]string{"diagnose", string(id)}, out, errOut, options); code != 0 {
				fmt.Fprintln(out, "No confirmed end-to-end connectivity yet; check peer setup and firewall.")
			}
		case "3", "e":
			if selected.Backend == domain.BackendGRE || selected.Backend == domain.BackendIPIP {
				fmt.Fprintln(out, "Copy the one-line stl:// Setup Link below to the OTHER server:")
				if code := linkExportCommand([]string{"export", string(id)}, out, errOut, options); code != 0 {
					fmt.Fprintln(out, "Setup Link cannot be rebuilt from the current saved state. No network changes made.")
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
				fmt.Fprintln(out, "Cannot inspect current saved tunnel settings. Nothing was changed.")
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
			return menuRemoveLink(input, reader, out, errOut, options, selected)
		case "6":
			if selected.Backend == domain.BackendGRE || selected.Backend == domain.BackendIPIP {
				fmt.Fprintln(out, "Plaintext Setup Links are computed on request and no private receiver file exists to delete.")
				continue
			}
			menuSensitiveHandoffAction(input, reader, out, errOut, options, selected, true)
		default:
			fmt.Fprintln(out, "Choose a number from 0 to 6.")
		}
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
	fmt.Fprintln(out, "\nPREVIEW ONLY — no Link removal has occurred.")
	fmt.Fprintf(out, "Remove only Link %s (%s/%s): %s -> %s\n",
		selected.ID, safeMenuText(string(selected.Backend)), safeMenuText(string(selected.Encapsulation)),
		selected.Addresses.Local, selected.Addresses.Peer)
	fmt.Fprintf(out, "Underlay: %s -> %s\n", selected.Underlay.Local, selected.Underlay.Peer)
	fmt.Fprintln(out, "If confirmed, the canonical Engine will verify ownership, remove this Link's owned network resources,")
	fmt.Fprintln(out, "and reconcile saved Link state and owned persistence. Applications using this Link may disconnect.")
	fmt.Fprintln(out, "Other Links must remain isolated. A partial/uncertain failure requires state inspection before retrying.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		fmt.Fprintln(errOut, "Cannot establish a fresh terminal confirmation; no changes made.")
		return 2
	}
	fmt.Fprint(out, "To permanently REMOVE this tunnel, type REMOVE (Enter cancels): ")
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
	return executeLinkMutationConditional("link_remove", domain.Link{}, selected.ID, false,
		out, errOut, options, &selected)
}
