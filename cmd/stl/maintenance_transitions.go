package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// No linked-file or unknown-State adoption is permitted. The caller is the
// canonical installer holding its existing exclusive FD 9 maintenance lock.
func installerLockInherited(fd int, path string) error {
	var held syscall.Stat_t
	if err := syscall.Fstat(fd, &held); err != nil {
		return errors.New("canonical installer lock not inherited")
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() {
		return errors.New("canonical installer lock identity unavailable")
	}
	live, ok := current.Sys().(*syscall.Stat_t)
	if !ok || live.Dev != held.Dev || live.Ino != held.Ino {
		return errors.New("canonical installer lock identity changed")
	}
	// A separate process' lock is not sufficient: only the same inherited
	// open file description can re-acquire this nonblocking exclusive flock.
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("canonical installer does not own exclusive lock")
	}
	return nil
}

func retireOrphanStateRoot(root string, trust func(string) error) error {
	if trust == nil {
		return errors.New("state trust checker unavailable")
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return trust(filepath.Dir(root))
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state root cannot be inspected for retirement")
	}
	if err := trust(root); err != nil {
		return errors.New("state root is untrusted")
	}
	path := filepath.Join(root, "state.json")
	if _, err := os.Lstat(path); err == nil {
		// Never delete or rewrite the committed State as part of Uninstall.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("state snapshot identity cannot be inspected")
	}
	if err := inspectOrphanLockOnlyRoot(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return errors.New("cannot enumerate orphan state root")
	}
	if len(entries) == 1 {
		locks := filepath.Join(root, "locks")
		files, err := os.ReadDir(locks)
		if err != nil {
			return errors.New("cannot enumerate STL lock inventory")
		}
		for _, f := range files {
			if err := os.Remove(filepath.Join(locks, f.Name())); err != nil {
				return errors.New("cannot retire STL-owned lock file")
			}
		}
		if err := os.Remove(locks); err != nil {
			return errors.New("cannot retire empty STL lock directory")
		}
	}
	if err := os.Remove(root); err != nil {
		return errors.New("cannot retire empty STL State root")
	}
	return nil
}

// The schema of older published Stable tags is an explicit compatibility
// contract, not a heuristic based on arbitrary semantic-version order.
var downgradeStableTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func publishedStateSchema(tag string) (int, error) {
	m := downgradeStableTag.FindStringSubmatch(tag)
	if len(m) != 4 || m[1] != "0" || m[2] != "1" {
		return 0, errors.New("requested target has no verified State schema contract")
	}
	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return 0, errors.New("this release has no verified historical State schema contract")
	}
	switch patch {
	case 8, 9:
		return 3, nil
	case 10, 11, 12:
		return 4, nil
	default:
		return 0, errors.New("this release has no verified historical State schema contract")
	}
}

// A downgrade with even one Link, journal or retained resource receipt is
// intentionally refused by inspectUninstallReady. Converting an EMPTY v4
// snapshot to v3 is safe because there are exactly two keys and no data to
// discard; it is not a general-purpose State migration.
func stageEmptyStateForDowngrade(root, target string) error {
	schema, err := publishedStateSchema(target)
	if err != nil {
		return err
	}
	p := filepath.Join(root, "state.json")
	info, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		info.Size() > 1<<20 || info.Size() == 0 {
		return errors.New("State file cannot be safely read for downgrade")
	}
	if root == state.DefaultRoot {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Nlink != 1 {
			return errors.New("State owner or link identity is untrusted")
		}
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return errors.New("cannot read State before downgrade")
	}
	after, err := os.Lstat(p)
	if err != nil || !os.SameFile(info, after) {
		return errors.New("State identity changed before downgrade")
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fields); err != nil || len(fields) != 2 {
		return errors.New("State has unknown or retained data; downgrade refused")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("State has trailing data; downgrade refused")
	}
	var current int
	if err := json.Unmarshal(fields["schema_version"], &current); err != nil ||
		(current != 3 && current != 4) {
		return errors.New("State schema is not eligible for downgrade")
	}
	var links []json.RawMessage
	if err := json.Unmarshal(fields["links"], &links); err != nil || len(links) != 0 {
		return errors.New("State still contains Link data; downgrade refused")
	}
	if current <= schema {
		return nil
	}
	// Any other non-empty records would have been rejected by the strict
	// two-field proof, and the canonical Engine preflight runs first.
	if schema != 3 || current != 4 {
		return errors.New("no lossless downlevel State representation is known")
	}
	tmp, err := os.CreateTemp(root, ".stl-empty-state-downlevel-*")
	if err != nil {
		return errors.New("cannot stage downgraded empty State")
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := io.WriteString(tmp, "{\"schema_version\":3,\"links\":[]}\n"); err != nil {
		tmp.Close()
		return errors.New("cannot write empty downlevel State")
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return errors.New("cannot set private downlevel State mode")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return errors.New("cannot sync downlevel State bytes")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("cannot close downlevel State")
	}
	if err := os.Rename(name, p); err != nil {
		return errors.New("cannot publish compatible empty State")
	}
	directory, err := os.Open(root)
	if err != nil {
		return errors.New("State directory sync unavailable after publication")
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("downlevel State publication durability unverified")
	}
	return nil
}

// Called by the already-owner-verified canonical installer under its exclusive
// maintenance lock. These private commands are not a second install engine.
func maintenanceTransitionCommand(args []string, out, errOut io.Writer) int {
	action, target := "", ""
	if len(args) == 2 && (args[0] == "retire-empty-state" || args[0] == "retire-orphan-restore") && args[1] == "--json" {
		action = args[0]
	} else if len(args) == 4 && args[0] == "stage-downgrade" &&
		args[1] == "--target" && args[3] == "--json" {
		action, target = args[0], args[2]
	} else {
		return readCommandError(out, errOut, true, stlerr.CodeInvalid,
			"maintenance_transition", "usage: maintenance retire-orphan-restore --json OR retire-empty-state --json OR stage-downgrade --target vX.Y.Z --json")
	}
	fail := func(reason, next string) int {
		e := stlerr.New(stlerr.CodeState, action, "", "", "Safe STL maintenance transition was not verified")
		e.ReasonCode, e.NextStep = reason, next
		return readCommandPublicError(out, errOut, true, e)
	}
	if os.Geteuid() != 0 {
		return fail("root_required", "Run this operation only through the installed root STL menu.")
	}
	if err := installerLockInherited(9, "/usr/local/lib/simple-tun-link/.maintenance.lock"); err != nil {
		return fail("canonical_installer_lock_required", "Use STL's confirmed Update/Uninstall menu; the embedded installer must own the exclusive maintenance lock.")
	}
	ctx, done := context.WithTimeout(context.Background(), 15*time.Second)
	defer done()
	manager := linux.SystemdPersistence{Runner: linux.ExecRunner{}}
	if action != "retire-orphan-restore" {
		if err := inspectUninstallReady(ctx, state.DefaultRoot, manager, trustedStatePath); err != nil {
			reason, next := uninstallGateGuidance(err)
			return fail(reason, next)
		}
	}
	var err error
	switch action {
	case "retire-orphan-restore":
		err = retireOrphanRestoreUnit(ctx, state.DefaultRoot, manager, trustedStatePath)
	case "retire-empty-state":
		err = retireOrphanStateRoot(state.DefaultRoot, trustedStatePath)
	default:
		err = stageEmptyStateForDowngrade(state.DefaultRoot, target)
	}
	if err != nil {
		return fail("maintenance_transition_unverified", "Preserve State and installer recovery evidence; inspect STL Link ownership and target compatibility before retrying.")
	}
	if err := json.NewEncoder(out).Encode(uninstallPreflightResult{SchemaVersion: jsonSchemaVersion, Ready: true}); err != nil {
		fmt.Fprintln(errOut, "cannot encode maintenance completion")
		return 1
	}
	return 0
}

// Only these exact actions can reach the private mutating transition route.
func isMaintenanceTransition(args []string) bool {
	return len(args) > 0 && (strings.EqualFold(args[0], "retire-empty-state") ||
		strings.EqualFold(args[0], "retire-orphan-restore") ||
		strings.EqualFold(args[0], "stage-downgrade"))
}
