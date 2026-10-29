package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
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
		fmt.Fprintln(errOut, "Next: inspect the configured STL State directory ownership and permissions read-only; do not replace or delete State.")
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

// The menu owns explicit consent, not the resource/installer lifecycle.
type menuUninstallOps struct {
	canAct    func(io.Reader, io.Writer) bool
	preflight func(context.Context) error
	install   func(context.Context, io.Writer, io.Writer, ...string) error
	verify    func() bool
}

func installedSTLAbsent() bool {
	for _, path := range []string{"/usr/local/bin/stl", "/usr/local/bin/stlink",
		"/usr/local/lib/simple-tun-link/install-record"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func productionMenuUninstallOps() menuUninstallOps {
	return menuUninstallOps{
		canAct: menuCanUpdateNow,
		preflight: func(ctx context.Context) error {
			return inspectUninstallReady(ctx, state.DefaultRoot,
				linux.SystemdPersistence{Runner: linux.ExecRunner{}}, trustedStatePath)
		},
		install: runEmbeddedInstaller,
		verify:  installedSTLAbsent,
	}
}

// No silent cleanup of saved Links, credentials, foreign services or State.
func menuUninstall(input io.Reader, reader *bufio.Reader, out, errOut io.Writer, options *runtimeOptions) int {
	return menuUninstallWithOps(input, reader, out, errOut, options, productionMenuUninstallOps())
}

func menuUninstallWithOps(input io.Reader, reader *bufio.Reader, out, errOut io.Writer,
	options *runtimeOptions, ops menuUninstallOps) int {
	root := menuStateRoot(options)
	if root == "" {
		fmt.Fprintln(errOut, "Uninstall blocked: local state root is not configured.")
		return 1
	}
	snapshot, err := state.NewFileStore(root).Load(context.Background())
	if err != nil {
		fmt.Fprintln(errOut, "Uninstall blocked: saved state cannot be inspected. No files were removed.")
		fmt.Fprintln(errOut, "Next: inspect the configured STL State directory and backups read-only; reconcile ownership before attempting uninstall.")
		return 1
	}
	menuActionSection(out, "Uninstall / verified canonical removal", "UNINSTALL")
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
			menuField(out, "Keep", "The private Setup Link survives tunnel removal and STL uninstall; keep it protected.")
			menuField(out, "Why now?", "DELETE requires the original saved tunnel and a fresh confirmation before REMOVE.")
		}
		menuSection(out, "Then / remove saved tunnels")
		menuField(out, "1", "My tunnels -> select tunnel -> Remove this tunnel")
		menuField(out, "2", "Return here after all removals are confirmed")
		menuNotice(out, "INFO", "Uninstall is read-only here; only confirmed individual Link removals can proceed.")
		menuField(out, "Advanced CLI", "stl link list --json")
		return 0
	}
	if !uninstallSnapshotEmpty(snapshot) {
		menuNotice(out, "WARNING", "Saved pending operations remain even though no Link is listed.")
		menuField(out, "Reason", "saved_or_pending_links")
		menuField(out, "NEXT ACTION", "Use STL's Link/recovery workflow to reconcile pending operations before Uninstall.")
		return 0
	}
	menuNotice(out, "INFO", "Zero saved Links. STL will inspect private State and the restore unit.")
	if ops.canAct == nil || ops.preflight == nil || ops.install == nil || ops.verify == nil {
		menuNotice(out, "WARNING", "Canonical Uninstall is unavailable; nothing changed.")
		return 0
	}
	if !ops.canAct(input, out) {
		menuField(out, "Reason", "installed_root_terminal_required")
		menuField(out, "Read-only proof", "sudo stl maintenance pre-uninstall --json")
		menuField(out, "NEXT ACTION", "Run sudo stl menu on this host and choose Uninstall (7); no external installer download is needed.")
		return 0
	}
	previewCtx, done := context.WithTimeout(context.Background(), 20*time.Second)
	checkErr := ops.preflight(previewCtx)
	done()
	if checkErr != nil {
		reason, next := uninstallGateGuidance(checkErr)
		menuNotice(out, "WARNING", "Canonical Uninstall preflight rejected this host; no changes attempted.")
		menuField(out, "Reason", reason)
		menuField(out, "NEXT ACTION", next)
		return 0
	}
	menuField(out, "Verification", "No saved Links, pending operations or restore unit; check repeats under exclusive lock")
	menuNotice(out, "WARNING", "Uninstall removes the STL executable, alias and install record. Protected State, credentials and shared packages are retained.")
	if err := clearQueuedMenuConfirmation(input, reader); err != nil {
		menuNotice(out, "WARNING", "Fresh terminal confirmation unavailable; no removal attempted.")
		return 2
	}
	fmt.Fprintf(out, "Type %s to uninstall STL (Enter cancels): ", menuActionToken(out, "UNINSTALL"))
	confirm, err := readMenuAnswer(reader)
	if err != nil || confirm != "UNINSTALL" {
		menuNotice(out, "INFO", "Uninstall cancelled. Nothing changed.")
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var child menuInstallerOutput
	childOut, childErr := child.streams()
	menuNotice(out, "INFO", "Canonical installer verifying ownership and removing only STL-owned binaries. Raw child output is hidden.")
	installErr := ops.install(ctx, childOut, childErr, "uninstall")
	if installErr != nil {
		child.failure(out, "uninstall", installErr, ctx)
		menuNotice(out, "FAILED", "Uninstall was not confirmed. Inspect installed identity and recovery evidence.")
	} else if !ops.verify() {
		menuNotice(out, "FAILED", "Installer returned success but the STL installation remains; inspect executable and record.")
	} else {
		menuNotice(out, "OK", "STL uninstalled. The menu is closing; protected State and credentials are preserved.")
	}
	// After any installer invocation, the running binary may have changed.
	return menuUpdatedExecutable
}
