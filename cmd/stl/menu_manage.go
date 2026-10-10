package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

// Manage is an operator-facing selector over the existing read and Engine
// lifecycle commands. It has no independent ownership or removal logic.
func menuManage(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	if code := linkReadCommand([]string{"list"}, out, errOut, options); code != 0 {
		return code
	}
	fmt.Fprint(out, "Manage Link ID (Enter returns to menu): ")
	idText, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && (idText == "" || strings.EqualFold(idText, "q")) {
		return 0
	}
	if err != nil || domain.LinkID(idText).Validate() != nil {
		fmt.Fprintln(errOut, "Invalid Link ID; no changes made.")
		return 2
	}
	id := domain.LinkID(idText)

	root := state.DefaultRoot
	if options != nil {
		root = options.stateRoot
	}
	if root == "" {
		fmt.Fprintln(errOut, "Local state root is unavailable; no changes made.")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), readOperationTimeout)
	snapshot, err := state.NewFileStore(root).Load(ctx)
	cancel()
	if err != nil {
		fmt.Fprintln(errOut, "Cannot inspect saved Link; no changes made.")
		return 1
	}
	record, found := snapshot.Find(id)
	if !found {
		fmt.Fprintln(errOut, "Link ID is not present in saved state; no changes made.")
		return 2
	}
	selected := summarizeLink(record.Desired)
	fmt.Fprintf(out, "Selected: %s | %s/%s | %s -> %s\n",
		selected.ID, safeMenuText(string(selected.Backend)), safeMenuText(string(selected.Encapsulation)),
		selected.LocalAddress, selected.PeerAddress)

	fmt.Fprint(out, "Action [s=status, r=remove, Enter=back]: ")
	action, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && (action == "" || strings.EqualFold(action, "b") || strings.EqualFold(action, "q")) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(errOut, "Invalid Manage action; no changes made.")
		return 2
	}
	switch strings.ToLower(action) {
	case "s":
		return linkReadCommand([]string{"status", idText}, out, errOut, options)
	case "r":
		return menuRemoveLink(input, reader, out, errOut, options, record.Desired)
	default:
		fmt.Fprintln(errOut, "Unknown Manage action; no changes made.")
		return 2
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
	fmt.Fprintf(out, "To REMOVE, type exact Link ID %s (Enter cancels): ", selected.ID)
	confirm, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && confirm != string(selected.ID) {
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
