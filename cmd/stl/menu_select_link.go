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
		fmt.Fprintln(out, "No saved tunnels on this server yet. Create one from the main menu.")
		return "", false, nil
	}
	fmt.Fprintln(out, "\nSaved tunnels on THIS server (not an active connection test):")
	for i, record := range links {
		l := record.Desired
		fmt.Fprintf(out, "  %d  %-10s %-6s   %s -> %s\n",
			i+1, safeMenuText(string(l.Backend)), safeMenuText(string(l.Encapsulation)),
			l.Addresses.Local.Addr(), l.Addresses.Peer.Addr())
	}
	if allowAll {
		fmt.Fprintln(out, "  a  Check all tunnels")
	}
	fmt.Fprintln(out, "  0  Back")
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
	fmt.Fprintln(out, "Read-only check: tests local tunnel identity and bounded peer reachability; it does not repair anything.")
	var code int
	if all {
		code = linkDiagnoseCommand([]string{"diagnose", "--all"}, out, errOut, options)
	} else {
		code = linkDiagnoseCommand([]string{"diagnose", string(id)}, out, errOut, options)
	}
	if code != 0 {
		fmt.Fprintln(out, "Some checks are unknown, blocked, or without peer replies. Check the OTHER server's setup and firewall.")
	}
	return code
}
