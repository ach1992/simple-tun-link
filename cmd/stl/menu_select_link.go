package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
)

func savedMenuLinks(options *runtimeOptions) ([]state.LinkRecord, error) {
	root := createStateRoot(options)
	if root == "" {
		return nil, fmt.Errorf("local State directory is unavailable")
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		return nil, fmt.Errorf("cannot inspect saved tunnels")
	}
	return snapshot.Links, nil
}

// A displayed ordinal is only an ephemeral selection of a saved identity;
// the Engine still verifies exact owner and expected desired Link at removal.
func chooseMenuLink(reader *bufio.Reader, out io.Writer, links []state.LinkRecord, allowAll bool) (domain.LinkID, bool, error) {
	if len(links) == 0 {
		menuNotice(out, "INFO", "No saved tunnels. First create a tunnel or import a Setup Link.")
		return "", false, nil
	}
	menuSection(out, "Saved tunnels / not a connection test")
	for i, record := range links {
		l := record.Desired
		menuOption(out, strconv.Itoa(i+1),
			fmt.Sprintf("%s / %s", safeMenuText(string(l.Backend)), safeMenuText(string(l.Encapsulation))),
			fmt.Sprintf("%s -> %s", l.Addresses.Local.Addr(), l.Addresses.Peer.Addr()))
	}
	if allowAll {
		menuOption(out, "a", "Check all tunnels", "Read-only")
	}
	menuOption(out, "0", "Back", "Main menu")
	for {
		fmt.Fprint(out, "Choose tunnel number: ")
		raw, err := readMenuAnswer(reader)
		if errors.Is(err, io.EOF) {
			return "", false, nil
		}
		if err != nil {
			fmt.Fprintln(out, "Invalid input. Please enter a listed number.")
			continue
		}
		if raw == "" || raw == "0" || strings.EqualFold(raw, "q") {
			return "", false, nil
		}
		if allowAll && strings.EqualFold(raw, "a") {
			return "", true, nil
		}
		n, e := strconv.Atoi(raw)
		if e == nil && n >= 1 && n <= len(links) {
			return links[n-1].Desired.ID, false, nil
		}
		// An old copied ID remains usable for recovery, but humans do not
		// need to transcribe opaque IDs to manage their own Links.
		if domain.LinkID(raw).Validate() == nil {
			for _, record := range links {
				if string(record.Desired.ID) == raw {
					return record.Desired.ID, false, nil
				}
			}
		}
		fmt.Fprintln(out, "Not a listed tunnel. Pick its number, or 0 to return.")
	}
}

func menuDiagnose(_ io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	links, err := savedMenuLinks(options)
	if err != nil {
		fmt.Fprintln(errOut, "Cannot open the saved-tunnel list; check State-directory permissions. No probes run.")
		return 1
	}
	id, all, err := chooseMenuLink(reader, out, links, true)
	if err != nil {
		return 1
	}
	if !all && id == "" {
		return 0
	}
	menuNotice(out, "INFO", "Checking local identity and peer reachability (read-only, no repair).")
	var code int
	if all {
		code = menuCheckAllConnections(out, errOut, options)
	} else {
		code = menuCheckOneConnection(id, out, errOut, options)
	}
	if code != 0 && !menuEscapeCapable(out) {
		menuProse(out, "Some checks are unknown, blocked, or without peer replies. Check the OTHER server's setup and firewall.")
	}
	return code
}
