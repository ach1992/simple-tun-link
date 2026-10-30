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
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/state"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"golang.org/x/sys/unix"
)

var errOwnedRestoreUnitPresent = errors.New("Engine restore unit is still installed; reconcile it through STL")

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

// Only files produced by STL's file-lock manager are eligible for automatic
// zero-Link cleanup. An absent State snapshot with ANY other contents is not
// evidence that the host's resource ownership has been reconciled.
var orphanLockName = regexp.MustCompile(`^[0-9a-f]{64}\.lock$`)

func inspectOrphanLockOnlyRoot(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return errors.New("cannot inspect uncommitted state root")
	}
	if len(entries) == 0 {
		return nil
	}
	if len(entries) != 1 || entries[0].Name() != "locks" {
		return errors.New("state root has unrecognized retained files")
	}
	locksPath := filepath.Join(root, "locks")
	info, err := os.Lstat(locksPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state lock directory has unverified identity")
	}
	if root == state.DefaultRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("state lock directory is not root-owned")
		}
	}
	files, err := os.ReadDir(locksPath)
	if err != nil || len(files) > 4096 {
		return errors.New("state lock inventory cannot be verified")
	}
	for _, entry := range files {
		if !orphanLockName.MatchString(entry.Name()) {
			return errors.New("state lock inventory contains an unknown entry")
		}
		file, err := os.Lstat(filepath.Join(locksPath, entry.Name()))
		if err != nil || !file.Mode().IsRegular() || file.Mode().Perm()&0o077 != 0 || file.Size() != 0 {
			return errors.New("state lock inventory has an unverified file")
		}
		stat, ok := file.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || (root == state.DefaultRoot && stat.Uid != 0) {
			return errors.New("state lock inventory has an untrusted owner or hardlink")
		}
	}
	return nil
}

func uninstallSnapshotEmpty(s state.Snapshot) bool {
	return len(s.Links) == 0 && len(s.PendingSenders) == 0 &&
		len(s.PendingIPsec) == 0 && len(s.IPsecVICIOperations) == 0 &&
		len(s.IPsecReapplyOperations) == 0 && len(s.IPsecRemoveOperations) == 0 &&
		len(s.IPsecXFRMOperations) == 0 && len(s.IPsecRemovalReceipts) == 0 &&
		len(s.RemovalReceipts) == 0 && len(s.WSSCrashOperations) == 0 &&
		len(s.QUICCrashOperations) == 0
}

// Uninstall removes only the verified installer-owned core binary and record;
// it deliberately keeps State and historical retirement tombstones. A receipt
// cannot be treated as a pending credential merely because it is retained:
// only a VALID, fully retired original receipt can be left behind. Loading the
// committed Snapshot above verifies all receipt identities and uniqueness.
// Keep uninstallSnapshotEmpty stricter for downgrade: older State readers must
// not discard even retired historical reservations or receipts.
func uninstallSnapshotReady(s state.Snapshot) bool {
	withoutReceipts := s
	withoutReceipts.RemovalReceipts = nil
	withoutReceipts.IPsecRemovalReceipts = nil
	if !uninstallSnapshotEmpty(withoutReceipts) {
		return false
	}
	for _, receipt := range s.RemovalReceipts {
		if !receipt.Retired {
			return false
		}
		if receipt.Backend == domain.BackendWireGuardWSS &&
			!state.ValidWSSOriginalTerminationProof(receipt.WSSOriginalTermination) {
			return false
		}
		if receipt.Backend == domain.BackendWireGuardQUIC &&
			!state.ValidQUICOriginalTerminationProof(receipt.QUICOriginalTermination) {
			return false
		}
	}
	for _, receipt := range s.IPsecRemovalReceipts {
		if !receipt.Retired {
			return false
		}
	}
	return true
}

// Only destructive maintenance relies on Retired receipt fields. Reject
// duplicate or case-aliased keys at EVERY nesting level before a typed
// Snapshot can hide an unfinished receipt behind a later "retired":true.
// Preserve the ordinary FileStore reader contract outside this gate.
func verifyMaintenanceJSONUnique(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := walkMaintenanceJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("ambiguous nested State JSON; maintenance refused")
	}
	return nil
}

// encoding/json v1 matches decoded struct field names using Unicode
// SimpleFold (including long-s and Kelvin-sign aliases), not ToLower.
// Normalize each rune to the smallest member of its SimpleFold cycle,
// mirroring encoding/json.foldName without quadratic key comparisons.
// This is a maintenance-only ambiguity check, not a change to State decoding.
func maintenanceJSONFoldFieldName(name string) string {
	return strings.Map(func(r rune) rune {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				return next
			}
			r = next
		}
	}, name)
}

func walkMaintenanceJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("State JSON nesting is too deep for maintenance")
	}
	value, err := decoder.Token()
	if err != nil {
		return errors.New("State JSON token cannot be verified")
	}
	delim, isDelim := value.(json.Delim)
	if !isDelim {
		return nil // Primitive values are checked by the canonical typed reader.
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			field, err := decoder.Token()
			if err != nil {
				return errors.New("State JSON key cannot be verified")
			}
			key, ok := field.(string)
			if !ok {
				return errors.New("State JSON object key is invalid")
			}
			folded := maintenanceJSONFoldFieldName(key)
			if _, duplicate := seen[folded]; duplicate {
				return errors.New("duplicate or aliased nested State field; maintenance refused")
			}
			seen[folded] = struct{}{}
			if err := walkMaintenanceJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return errors.New("State JSON object termination is invalid")
		}
	case '[':
		for decoder.More() {
			if err := walkMaintenanceJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return errors.New("State JSON array termination is invalid")
		}
	default:
		return errors.New("State JSON contains an unexpected delimiter")
	}
	return nil
}

// readUnambiguousUninstallState pins the actual regular inode and inspects
// the ORIGINAL bounded JSON bytes, not FileStore's permissive decoded
// Snapshot. Under its existing maintenance lock, Uninstall must not decide
// zero Links from a duplicate or aliased field that json.Unmarshal hides.
func readUnambiguousUninstallState(path string, expected os.FileInfo) ([]byte, error) {
	const maxStateBytes = 16 << 20 // FileStore's current authoritative bound.
	if !expected.Mode().IsRegular() || expected.Size() <= 0 || expected.Size() > maxStateBytes {
		return nil, errors.New("uninstall State size/type is untrusted")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot pin original State for Uninstall")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) ||
		opened.Mode().Perm()&0o077 != 0 || opened.Size() != expected.Size() {
		return nil, errors.New("Uninstall State identity or privacy changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxStateBytes || int64(len(raw)) != opened.Size() {
		return nil, errors.New("Uninstall State read is incomplete or untrusted")
	}
	if err := verifyMaintenanceJSONUnique(raw); err != nil {
		return nil, err
	}
	if _, err := strictStateTopLevelFields(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// inspectUninstallState accepts a *strictly verified* lock-only footprint as
// a never-committed state. Any pending intent or non-STL file fails closed.
// This is observational; only the canonical installer may clean the footprint
// after acquiring its exclusive maintenance lock and an explicit UNINSTALL.
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
		if err := inspectOrphanLockOnlyRoot(root); err != nil {
			return false, fmt.Errorf("existing Link state root has no committed state snapshot: %w", err)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot inspect Link state snapshot: %w", err)
	}
	if !entry.Mode().IsRegular() || entry.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("Link state snapshot is not a private regular file")
	}
	if root == state.DefaultRoot {
		stat, ok := entry.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Nlink != 1 {
			return false, fmt.Errorf("Link state snapshot owner or hardlink identity is untrusted")
		}
	}
	original, err := readUnambiguousUninstallState(path, entry)
	if err != nil {
		return false, fmt.Errorf("cannot prove unambiguous committed Link state: %w", err)
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
	if !uninstallSnapshotReady(snapshot) {
		withoutReceipts := snapshot
		withoutReceipts.RemovalReceipts = nil
		withoutReceipts.IPsecRemovalReceipts = nil
		if uninstallSnapshotEmpty(withoutReceipts) {
			return false, errors.New("protected credential retirement remains unfinished or unverified")
		}
		return false, fmt.Errorf("saved Links or pending operations remain; use Engine reconciliation before uninstall")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(entry, after) {
		return false, fmt.Errorf("Link state identity changed during uninstall preflight")
	}
	verified, err := readUnambiguousUninstallState(path, entry)
	if err != nil || !bytes.Equal(original, verified) {
		return false, fmt.Errorf("Link state changed during uninstall preflight")
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
		return errOwnedRestoreUnitPresent
	}
	// Re-observe canonical state after the potentially blocking systemctl call.
	// Exclusive maintenance exclusion prevents STL mutations meanwhile.
	if _, err := inspectUninstallState(ctx, root, trust); err != nil {
		return err
	}
	return nil
}

// retireOrphanRestoreUnit is an explicitly confirmed installer reconciliation,
// not a way to tear down persistence for a working Link. The caller holds the
// inherited exclusive canonical maintenance lock before reaching this code.
func retireOrphanRestoreUnit(ctx context.Context, root string, unit interface {
	uninstallUnitInspector
	RemoveRestore(context.Context) error
}, trust func(string) error) error {
	if unit == nil || trust == nil {
		return errors.New("restore-unit retirement prerequisites unavailable")
	}
	if _, err := inspectUninstallState(ctx, root, trust); err != nil {
		return err
	}
	present, err := unit.IsRestoreInstalled(ctx)
	if err != nil {
		return fmt.Errorf("restore-unit ownership or enablement unverified: %w", err)
	}
	if present {
		if err := unit.RemoveRestore(ctx); err != nil {
			return fmt.Errorf("owned restore-unit retirement incomplete: %w", err)
		}
	}
	present, err = unit.IsRestoreInstalled(ctx)
	if err != nil || present {
		return errors.New("restore-unit retirement absence is unverified")
	}
	if _, err := inspectUninstallState(ctx, root, trust); err != nil {
		return fmt.Errorf("State changed during restore-unit retirement: %w", err)
	}
	return nil
}

// User-facing categories are authored constants; never surface raw state,
// filesystem or systemd error strings, which may contain private paths.
func uninstallGateGuidance(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "no committed state snapshot"):
		return "state_root_unverified", "STL found an existing State folder without state.json and with unfamiliar files. Do not delete them manually; inspect STL state ownership before retrying."
	case strings.Contains(message, "saved Links or pending operations remain"):
		return "saved_or_pending_links", "Open My tunnels in STL and remove each verified Link; reconcile pending operations through STL before retrying Uninstall."
	case strings.Contains(message, "protected credential retirement remains"):
		return "credential_retirement_pending", "The Link was removed but a protected credential retirement receipt is unfinished or unverified. Use the exact STL receipt-bound retire-wss, credential retire, or retire-ipsec recovery operation as applicable; never delete State or credentials manually."
	case strings.Contains(message, "downgrade requires a canonical empty State"):
		return "downgrade_state_history_retained", "Downgrade requires a truly empty, canonical State with no historical retirement receipts. Keep the current v4-capable STL and preserve State; do not delete receipts to force an older binary."
	case strings.Contains(message, "Engine restore unit is still installed"):
		return "restore_unit_present", "A retained STL restore unit must be reconciled through STL before Uninstall; inspect its installed/enabled status read-only."
	case strings.Contains(message, "cannot prove restore-unit absence"):
		return "restore_unit_unverified", "Inspect systemctl show simple-tun-link-restore.service read-only; STL cannot prove the service is absent."
	case strings.Contains(message, "untrusted state"), strings.Contains(message, "cannot decode valid committed Link state"), strings.Contains(message, "cannot prove durable committed Link state"), strings.Contains(message, "cannot prove unambiguous committed Link state"):
		return "state_integrity_unverified", "STL could not verify private State. Preserve existing files; inspect ownership and State integrity before retrying."
	default:
		return "uninstall_preflight_unverified", "STL could not prove safe uninstall prerequisites. Check saved Links, retained operations, STL State and restore-unit status read-only."
	}
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
		failure := stlerr.New(stlerr.CodeState, "pre_uninstall", "", "", "STL cannot prove safe Uninstall prerequisites")
		failure.ReasonCode, failure.NextStep = uninstallGateGuidance(err)
		return readCommandPublicError(out, errOut, true, failure)
	}
	if err := json.NewEncoder(out).Encode(uninstallPreflightResult{SchemaVersion: jsonSchemaVersion, Ready: true}); err != nil {
		fmt.Fprintln(errOut, "cannot encode uninstall preflight result")
		return 1
	}
	return 0
}
