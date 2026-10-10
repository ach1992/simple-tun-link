package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// uninstallUnitInspector uses the same identity and enablement semantics as
// canonical Engine persistence. This is a read-only proof, not cleanup.
type uninstallUnitInspector interface {
	IsRestoreInstalled(context.Context) (bool, error)
}

type uninstallPreflightResult struct {
	SchemaVersion int  `json:"schema_version"`
	Ready         bool `json:"ready"`
}

// trustedStatePath enforces the production root-owned state-chain policy.
// A shell-level check for "a directory exists" is not a reliable witness.
func trustedStatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("state path must be absolute and canonical")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state path contains a symlink")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("state path is not trusted/root-owned")
		}
		if current == path {
			if !info.IsDir() {
				return fmt.Errorf("state root must be a directory")
			}
		} else if !info.IsDir() {
			return fmt.Errorf("state root parent is not a directory")
		}
		if current == "/" {
			break
		}
	}
	return nil
}

// inspectUninstallState deliberately treats a missing state.json inside an
// existing state root as ambiguous, unlike a never-used missing root. The
// Engine's HasCommittedState/Load own schema and desired Link validation.
func inspectUninstallState(ctx context.Context, root string, trust func(string) error) (bool, error) {
	rootInfo, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := trust(filepath.Dir(root)); err != nil {
			return false, fmt.Errorf("missing state root has an untrusted parent")
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot inspect state root: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("state root is not a trusted directory")
	}
	if err := trust(root); err != nil {
		return false, fmt.Errorf("untrusted state root: %w", err)
	}
	path := filepath.Join(root, "state.json")
	entry, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("existing Link state root has no committed state snapshot")
	}
	if err != nil {
		return false, fmt.Errorf("cannot inspect Link state snapshot: %w", err)
	}
	if !entry.Mode().IsRegular() || entry.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("Link state snapshot is not a private regular file")
	}
	if root == state.DefaultRoot {
		stat, ok := entry.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false, fmt.Errorf("Link state snapshot is not root-owned")
		}
	}
	store := state.NewFileStore(root)
	committed, err := store.HasCommittedState(ctx)
	if err != nil || !committed {
		return false, fmt.Errorf("cannot prove durable committed Link state")
	}
	snapshot, err := store.Load(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot decode valid committed Link state")
	}
	if len(snapshot.Links) != 0 {
		return false, fmt.Errorf("configured Links remain; use Engine removal before uninstall")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(entry, after) {
		return false, fmt.Errorf("Link state identity changed during uninstall preflight")
	}
	return true, nil
}

func inspectUninstallReady(ctx context.Context, root string, unit uninstallUnitInspector,
	trust func(string) error) error {
	if unit == nil || trust == nil {
		return fmt.Errorf("uninstall inspectors are unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := inspectUninstallState(ctx, root, trust); err != nil {
		return err
	}
	installed, err := unit.IsRestoreInstalled(ctx)
	if err != nil {
		return fmt.Errorf("cannot prove restore-unit absence: %w", err)
	}
	if installed {
		return fmt.Errorf("Engine restore unit is still installed; reconcile it through stl")
	}
	// Re-observe canonical state after the potentially blocking systemctl call.
	// Exclusive maintenance exclusion prevents STL mutations meanwhile.
	if _, err := inspectUninstallState(ctx, root, trust); err != nil {
		return err
	}
	return nil
}

func uninstallPreflightCommand(args []string, out, errOut io.Writer) int {
	if len(args) != 2 || args[0] != "pre-uninstall" || args[1] != "--json" {
		return readCommandError(out, errOut, true, stlerr.CodeInvalid, "pre_uninstall",
			"usage: stl maintenance pre-uninstall --json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := linux.SystemdPersistence{Runner: linux.ExecRunner{}}
	err := inspectUninstallReady(ctx, state.DefaultRoot, manager, trustedStatePath)
	if err != nil {
		return readCommandError(out, errOut, true, stlerr.CodeState, "pre_uninstall",
			"STL state or restore-unit absence cannot be proven; reconcile before uninstall")
	}
	if err := json.NewEncoder(out).Encode(uninstallPreflightResult{SchemaVersion: jsonSchemaVersion, Ready: true}); err != nil {
		fmt.Fprintln(errOut, "cannot encode uninstall preflight result")
		return 1
	}
	return 0
}
