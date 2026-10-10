package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/version"
)

// This is only a human-readable handoff to the independently reviewed
// installer. No second updater/uninstaller may be implemented in the TUI,
// and no arbitrary shell or downloaded code is executed by these handlers.
var menuReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$`)

func menuStateRoot(options *runtimeOptions) string {
	if options != nil {
		return options.stateRoot
	}
	return state.DefaultRoot
}

func menuSettings(out, errOut io.Writer, options *runtimeOptions) int {
	root := menuStateRoot(options)
	if root == "" {
		fmt.Fprintln(errOut, "Settings unavailable: local state root is not configured.")
		return 1
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		fmt.Fprintln(errOut, "Settings unavailable: saved state cannot be read; no changes made.")
		return 1
	}
	fmt.Fprintln(out, "\nSettings (read-only)")
	fmt.Fprintf(out, "  STL version: %s\n", safeMenuText(version.Version))
	fmt.Fprintf(out, "  Local state root: %s\n", safeMenuText(root))
	fmt.Fprintf(out, "  Saved Links: %d (not a connectivity check)\n", len(snapshot.Links))
	fmt.Fprintln(out, "  Per-Link settings belong to Create/Ensure; no global host settings are changed here.")
	return 0
}

func menuUpdate(reader *bufio.Reader, out, errOut io.Writer) int {
	fmt.Fprintln(out, "\nUpdate — guided handoff to the verified release installer")
	fmt.Fprintf(out, "Current binary version: %s\n", safeMenuText(version.Version))
	fmt.Fprintln(out, "This menu does not fetch or run executable code, and does not change the current installation.")
	fmt.Fprintln(out, "Verify an official release exists at https://github.com/ach1992/simple-tun-link/releases")
	fmt.Fprint(out, "Exact published release tag (e.g. v0.1.0; Enter cancels): ")
	tag, err := readMenuAnswer(reader)
	if errors.Is(err, io.EOF) || err == nil && tag == "" {
		fmt.Fprintln(out, "Update cancelled; no files changed.")
		return 0
	}
	if err != nil || !menuReleaseTag.MatchString(tag) {
		fmt.Fprintln(errOut, "Invalid release tag; no update attempted.")
		return 2
	}
	fmt.Fprintf(out, "Review official release: https://github.com/ach1992/simple-tun-link/releases/tag/%s\n", tag)
	fmt.Fprintf(out, "Exact-tag installer source: https://raw.githubusercontent.com/ach1992/simple-tun-link/%s/scripts/install.sh\n", tag)
	fmt.Fprintln(out, "Follow https://github.com/ach1992/simple-tun-link/blob/main/docs/INSTALL.md")
	fmt.Fprintln(out, "Download the complete installer to a private file, require successful HTTPS transfer and bash -n,")
	fmt.Fprintln(out, "inspect release notes/source, then invoke the installer with the verified exact tag:")
	fmt.Fprintf(out, "  sudo bash /path/to/verified/install.sh update --version %s\n", tag)
	fmt.Fprintln(out, "After the installer reports success, verify stl version --json and stlink version --json.")
	fmt.Fprintln(out, "No remote lookup, update, service restart or host change was performed by this menu.")
	return 0
}

func menuUninstall(out, errOut io.Writer, options *runtimeOptions) int {
	root := menuStateRoot(options)
	if root == "" {
		fmt.Fprintln(errOut, "Uninstall blocked: local state root is not configured.")
		return 1
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		fmt.Fprintln(errOut, "Uninstall blocked: saved state cannot be inspected. No files were removed.")
		return 1
	}
	fmt.Fprintln(out, "\nUninstall — safe operator handoff")
	fmt.Fprintln(out, "This menu never deletes Links, routes, firewall rules, services or STL files.")
	if len(snapshot.Links) != 0 {
		fmt.Fprintf(out, "BLOCKED: %d configured Link(s) remain in saved state.\n", len(snapshot.Links))
		fmt.Fprintln(out, "Review each Link, then explicitly remove it using the canonical Engine:")
		for _, record := range snapshot.Links {
			id := record.Desired.ID
			// A stable Link ID is validated by the domain; no arbitrary
			// display name/secret-bearing desired state is printed.
			if err := id.Validate(); err != nil {
				fmt.Fprintln(errOut, "Saved Link identity is invalid; uninstall guidance halted.")
				return 1
			}
			fmt.Fprintf(out, "  stl link remove %s --confirm %s\n", id, id)
		}
		fmt.Fprintln(out, "Return to Uninstall only after explicit removal and verification of every Link.")
		return 0
	}
	fmt.Fprintln(out, "Saved Link count is zero, but that alone is NOT proof uninstall is safe.")
	fmt.Fprintln(out, "In an operator-controlled shell, check the canonical pre-uninstall read contract:")
	fmt.Fprintln(out, "  sudo stl maintenance pre-uninstall --json")
	fmt.Fprintln(out, "The verified installer must additionally hold exclusive maintenance locking")
	fmt.Fprintln(out, "and refuse ambiguous committed state or any still-owned systemd identity.")
	fmt.Fprintln(out, "After the preflight is ready, obtain/review the trusted installer from the exact")
	fmt.Fprintln(out, "published STL release, then run:")
	fmt.Fprintln(out, "  sudo bash /path/to/verified/install.sh uninstall")
	fmt.Fprintln(out, "See https://github.com/ach1992/simple-tun-link/blob/main/docs/INSTALL.md")
	fmt.Fprintln(out, "No uninstall or host change was performed by this menu.")
	return 0
}
