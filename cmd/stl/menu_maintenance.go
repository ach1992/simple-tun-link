package main

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/version"
	"golang.org/x/sys/unix"
)

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
	menuSection(out, "Settings / read-only")
	menuField(out, "STL version", safeMenuText(version.Version))
	menuField(out, "Repository", "github.com/ach1992/simple-tun-link")
	menuField(out, "OS / Architecture", runtime.GOOS+" / "+runtime.GOARCH)
	var info unix.Utsname
	if unix.Uname(&info) == nil {
		menuField(out, "Kernel", safeMenuText(unix.ByteSliceToString(info.Release[:])))
	}
	menuField(out, "IPv4 candidate", safeMenuText(localAddressCandidate()))
	menuField(out, "State directory", safeMenuText(root))
	menuField(out, "Saved tunnels", fmt.Sprintf("%d (not a connection test)", len(snapshot.Links)))
	menuNotice(out, "INFO", "Advanced tunnel/MTU settings belong to each tunnel. No host settings changed.")
	return 0
}

// This page cannot safely infer that "uninstall" also authorizes erasing
// separately retained receiver secrets, unowned host resources, or unknown
// partial Link state. The canonical Engine removes one verified Link at a
// time; the installer separately checks the maintenance lock and receipts.
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
	menuSection(out, "Uninstall / preparation only")
	menuField(out, "Saved tunnels", fmt.Sprintf("%d", len(snapshot.Links)))
	if len(snapshot.Links) != 0 {
		hasProtected := false
		for _, record := range snapshot.Links {
			if err := record.Desired.ID.Validate(); err != nil {
				fmt.Fprintln(errOut, "Saved Link identity is invalid; uninstall guidance halted.")
				return 1
			}
			if record.Desired.Backend == domain.BackendWireGuard || record.Desired.Backend == domain.BackendIPsec {
				hasProtected = true
			}
		}
		menuNotice(out, "WARNING", fmt.Sprintf("Uninstall blocked: %d saved tunnel(s) must be safely removed first.", len(snapshot.Links)))
		if hasProtected {
			menuSection(out, "First / protected WireGuard or IPsec receiver links")
			menuProse(out, "BEFORE removing each such tunnel, decide whether to KEEP or DELETE its separately saved private receiver Setup Link.")
			menuField(out, "Delete", "My tunnels -> select tunnel -> Delete receiver link -> type DELETE")
			menuProse(out, "Deletion needs the original saved tunnel identity and a fresh confirmation; it cannot safely be done from this page after tunnel removal.")
			menuField(out, "Keep", "The protected receiver Setup Link survives tunnel removal and STL uninstall. The administrator must protect or retire it later.")
		}
		menuSection(out, "Then / remove saved tunnels")
		menuField(out, "1", "My tunnels -> select tunnel -> Remove this tunnel")
		menuField(out, "2", "Return here after all removals are confirmed")
		menuNotice(out, "INFO", "A one-click wipe risks shared resources, uncertain State and irreplaceable private handoffs.")
		menuField(out, "Advanced CLI", "stl link list --json")
		return 0
	}
	menuNotice(out, "INFO", "No saved tunnels. This alone does not prove uninstall can proceed.")
	menuSection(out, "Final owner checks")
	menuField(out, "1. Read-only proof", "sudo stl maintenance pre-uninstall --json")
	menuField(out, "2. Trusted installer", "sudo bash /path/to/verified/install.sh uninstall")
	menuField(out, "Reference", "https://github.com/ach1992/simple-tun-link/blob/main/docs/INSTALL.md")
	menuNotice(out, "WARNING", "Uninstall never silently deletes saved credentials or State; back them up and retire deliberately.")
	return 0
}
