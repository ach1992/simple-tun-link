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

// Guided host-policy changes remain optional: creating/importing/inspecting a
// tunnel must not silently change another service's reverse-path filtering.
func menuSpoofRPFilter(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, selected domain.Link) {
	stdin, stdinOK := input.(*os.File)
	stdout, stdoutOK := out.(*os.File)
	if !stdinOK || !stdoutOK || !terminalIsInteractive(stdin) || !terminalIsInteractive(stdout) {
		menuNotice(out, "WARNING", "Host rp_filter changes require a fresh interactive confirmation. For scripting, use stl link rp-filter plan/apply with exact Link ID.")
		return
	}
	menuActionSection(out, "Spoof rp_filter / reverse-path filtering", "NETWORK")
	menuProse(out, "Use this ONLY when the receiving host's rp_filter blocks a working tunnel path. Loose usually allows asymmetric routes; Off disables the check for this incoming NIC and may require global all=0.")
	menuOption(out, "1", "Set Loose (2)", "Recommended first for asymmetric reverse routes")
	menuOption(out, "2", "Set Off (0)", "Allows complete disable, including all=0 if necessary")
	menuOption(out, "3", "Restore previous", "Undo this Link's owned settings; keep other Links")
	menuOption(out, "0", "Back", "No changes")
	fmt.Fprint(out, "Choose an action: ")
	choice, err := readMenuAnswer(reader)
	if err != nil {
		menuNotice(out, "WARNING", "No network settings changed.")
		return
	}
	mode := ""
	switch choice {
	case "1":
		mode = "loose"
	case "2":
		mode = "off"
	case "3":
		menuNotice(out, "WARNING", "STL will release only this Link's confirmed rp_filter claim and restore remaining managed/original values.")
		if err := clearQueuedMenuConfirmation(input, reader); err != nil {
			menuNotice(out, "WARNING", "No fresh confirmation available; nothing changed.")
			return
		}
		fmt.Fprint(out, "Type RESTORE to confirm (Enter cancels): ")
		answer, err := readMenuAnswer(reader)
		if err != nil || answer != "RESTORE" {
			menuNotice(out, "INFO", "Cancelled; nothing changed.")
			return
		}
		if linkSpoofRPFilterCommand([]string{"restore", string(selected.ID), "--confirm", string(selected.ID)}, out, errOut, options) != 0 {
			menuNotice(out, "WARNING", "Could not verify original rp_filter restoration; inspect details and retry using the same Link ID.")
		}
		return
	default:
		return
	}
	args := []string{"plan", string(selected.ID), "--mode", mode}
	// Under an ambiguous or DNAT topology the operator may need to specify
	// the actual ingress NIC, not blindly use the outbound interface.
	iface := strings.TrimSpace(selected.Spoof.IngressInterface)
	if iface == "" {
		fmt.Fprint(out, "Actual incoming network interface (Enter=auto-detect from local bind IPv4): ")
		iface, err = readMenuAnswer(reader)
		if err != nil {
			menuNotice(out, "WARNING", "No changes made.")
			return
		}
	}
	if iface != "" {
		args = append(args, "--interface", iface)
	}
	menuActionSection(out, "rp_filter / confirmed host plan", "PREVIEW")
	if linkSpoofRPFilterCommand(args, out, errOut, options) != 0 {
		menuNotice(out, "WARNING", "Cannot safely determine the incoming interface or current settings. Nothing changed. Specify a real incoming NIC or inspect Linux routing.")
		return
	}
	if mode == "off" {
		menuNotice(out, "WARNING", "Off can change effective reverse-path filtering on ALL other interfaces/services when all changes, possibly weaker OR stronger. This approves a host-level change, not just tunnel traffic.")
	}
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Fresh confirmation unavailable; nothing changed.")
		return
	}
	fmt.Fprint(out, "Type APPLY to approve the displayed rp_filter changes (Enter cancels): ")
	answer, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && answer != "APPLY" {
		menuNotice(out, "INFO", "Cancelled. No network change was requested.")
		return
	}
	if err != nil {
		menuNotice(out, "WARNING", "Invalid confirmation. Nothing changed.")
		return
	}
	apply := []string{"apply", string(selected.ID), "--mode", mode, "--confirm", string(selected.ID)}
	if iface != "" {
		apply = append(apply, "--interface", iface)
	}
	if linkSpoofRPFilterCommand(apply, out, errOut, options) != 0 {
		menuNotice(out, "WARNING", "Review host readback and durable rp_filter journal; an interrupted change is retryable using the same Link ID.")
	}
}
