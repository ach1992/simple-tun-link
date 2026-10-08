package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	managedSystemdMarker   = "# Managed by simple-tun-link; do not edit manually."
	restoreSystemdUnitName = "simple-tun-link-restore.service"
)

type SystemdPersistence struct {
	Runner          Runner
	UnitDir         string
	SystemctlBinary string
	// VerifyExecutable is an isolated unit-test seam. Production uses strict
	// root-owned executable/path verification before any unit side effects.
	VerifyExecutable func(string) error
	// VerifyUnitPath is an isolated, non-production test seam. Production uses
	// VerifyTrustedSystemdUnitPath and never accepts writable unit identities.
	VerifyUnitPath func(string) error
	// The following unexported seams exercise filesystem failure paths after
	// rename in isolated tests; ordinary production instances leave them nil.
	afterUnitPublish    func() error
	beforeUnitMutation  func(string)
	afterUnitTransition func(string)
	syncUnitDirectory   func(string) error
	restoreAfterFailure func(string, string, []byte, bool) error
}

// unitPublicationError distinguishes an error before the atomic rename from
// one after the desired unit content was published. An uncertain publication
// must not be compensated like an unchanged filesystem transaction.
type unitPublicationError struct {
	cause error
	// Generated, STL-owned recovery path only; arbitrary failing subprocess
	// output and error details must not leak through the public error.
	recoveryPath string
}

func (e *unitPublicationError) Error() string {
	if e.recoveryPath != "" {
		return fmt.Sprintf("systemd unit publication incomplete; protected recovery material retained at %q", e.recoveryPath)
	}
	return "systemd unit publication completed but subsequent durability step failed"
}
func (e *unitPublicationError) Unwrap() error { return e.cause }

// EnsureRestore installs/updates STL's single restore unit and enables it for
// future boots. It deliberately never uses --now, start, or restart, so adding
// persistence cannot mutate live Link state.
func (p SystemdPersistence) EnsureRestore(ctx context.Context, stlExecutable string) (func(context.Context) error, bool, error) {
	if p.Runner == nil {
		return nil, false, fmt.Errorf("systemd runner is required")
	}
	content, err := renderRestoreSystemdUnit(stlExecutable)
	if err != nil {
		return nil, false, err
	}
	verify := p.VerifyExecutable
	if verify == nil {
		verify = VerifyTrustedSTLExecutable
	}
	if err := verify(stlExecutable); err != nil {
		return nil, false, fmt.Errorf("refusing unsafe STL restore executable: %w", err)
	}
	unitDir := p.UnitDir
	if unitDir == "" {
		unitDir = "/etc/systemd/system"
	}
	path := filepath.Join(unitDir, restoreSystemdUnitName)
	if err := p.verifyUnitDirectoryForCreate(unitDir); err != nil {
		return nil, false, fmt.Errorf("unsafe systemd restore unit directory: %w", err)
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return nil, false, fmt.Errorf("create systemd unit directory: %w", err)
	}
	if err := p.verifyUnitPath(path); err != nil {
		return nil, false, fmt.Errorf("unsafe systemd restore unit identity: %w", err)
	}

	prior, _, readErr := readRegularUnit(path)
	existed := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read systemd unit: %w", readErr)
	}
	if existed {
		if !isOwnedSystemdUnit(prior) {
			return nil, false, fmt.Errorf("refusing to overwrite non-STL systemd unit %q", restoreSystemdUnitName)
		}
		if err := p.guardExactPublishedUnit(path, prior); err != nil {
			return nil, false, fmt.Errorf("refusing unverified STL unit identity: %w", err)
		}
	}

	systemctl := p.SystemctlBinary
	if systemctl == "" {
		systemctl = "systemctl"
	}
	wasEnabled, err := p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
	if err != nil {
		return nil, false, err
	}
	// An enabled identity without our owned file is ambiguous. Refuse to take it
	// over instead of assuming that STL owns systemd's enablement symlinks.
	if !existed && wasEnabled {
		return nil, false, fmt.Errorf("refusing to take over enabled systemd unit %q without an STL-owned unit file", restoreSystemdUnitName)
	}

	fileChanged := !existed || string(prior) != content
	if fileChanged {
		// The systemctl inspection may have allowed an administrator to
		// replace the existing unit. Never overwrite a changed identity.
		if existed {
			if err := p.guardExactPublishedUnit(path, prior); err != nil {
				return nil, false, fmt.Errorf("cannot replace changed STL unit: %w", err)
			}
		}
		if err := p.publishOwnedUnit(unitDir, path, []byte(content), prior, existed); err != nil {
			var publication *unitPublicationError
			if errors.As(err, &publication) {
				// This is not a definitely-uncommitted change: the new unit
				// may already be visible. Verify the exact owned content
				// before attempting to restore the previous identity.
				reconcileErr := p.compensatePublishedUnit(ctx, systemctl, unitDir, path, []byte(content), prior, existed, wasEnabled, true, false)
				return nil, false, errors.Join(fmt.Errorf("systemd restore unit publication failed after rename: %w", err), reconcileErr)
			}
			// A conflict during atomic transition is already being preserved
			// for manual reconciliation; a blind compensating overwrite would
			// defeat the ownership guarantee.
			return nil, false, err
		}
		if _, err := p.Runner.Run(ctx, systemctl, "daemon-reload"); err != nil {
			repairErr := p.compensatePublishedUnit(ctx, systemctl, unitDir, path, []byte(content), prior, existed, wasEnabled, true, false)
			return nil, false, errors.Join(fmt.Errorf("systemd daemon-reload: %w", err), repairErr)
		}
	}

	enabledChanged := false
	if !wasEnabled {
		if err := p.guardExactPublishedUnit(path, []byte(content)); err != nil {
			return nil, false, fmt.Errorf("cannot enable changed STL unit identity: %w", err)
		}
		_, enableErr := p.Runner.Run(ctx, systemctl, "enable", restoreSystemdUnitName)
		if enableErr == nil {
			var durable bool
			durable, enableErr = p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
			if enableErr == nil && !durable {
				enableErr = fmt.Errorf("systemd restore unit is not durably enabled")
			}
		}
		if enableErr != nil {
			repairErr := p.compensatePublishedUnit(ctx, systemctl, unitDir, path, []byte(content), prior, existed, wasEnabled, fileChanged, true)
			return nil, false, errors.Join(fmt.Errorf("enable STL systemd unit: %w", enableErr), repairErr)
		}
		enabledChanged = true
	}
	if err := p.guardExactPublishedUnit(path, []byte(content)); err != nil {
		return nil, false, fmt.Errorf("cannot verify owned STL restore unit after activation: %w", err)
	}
	if !fileChanged && !enabledChanged {
		return func(context.Context) error { return nil }, false, nil
	}

	undo := func(undoCtx context.Context) error {
		return p.compensatePublishedUnit(undoCtx, systemctl, unitDir, path, []byte(content), prior, existed, wasEnabled, fileChanged, enabledChanged)
	}
	return undo, true, nil
}

// compensatePublishedUnit is the single ownership-aware compensation path
// for post-rename durability errors, daemon-reload/enable failures, and the
// rollback closure returned to Engine. Every destructive action is gated by
// the exact STL-owned contents published by this operation.
func (p SystemdPersistence) compensatePublishedUnit(ctx context.Context, systemctl, unitDir, path string, published, prior []byte, existed, wasEnabled, fileChanged, enableAttempted bool) error {
	if existed && !isOwnedSystemdUnit(prior) {
		return fmt.Errorf("systemd unit compensation incomplete: prior unit ownership is unproven")
	}
	// For Engine rollback, keep its already-bounded cleanup budget. For a
	// canceled original caller (such as a timed-out daemon-reload), grant a
	// fresh bounded window for owned compensation.
	repairBase := ctx
	if ctx.Err() != nil {
		repairBase = context.WithoutCancel(ctx)
	}
	repairCtx, cancel := context.WithTimeout(repairBase, 30*time.Second)
	defer cancel()
	if err := repairCtx.Err(); err != nil {
		return fmt.Errorf("systemd unit compensation incomplete: %w", err)
	}
	if err := p.guardExactPublishedUnit(path, published); err != nil {
		return fmt.Errorf("systemd unit compensation uncertain: %w", err)
	}

	// A failed enable may have created an enablement symlink before returning
	// an error. Only disable after verifying this operation's exact owned
	// unit; never disable an ambiguous identity if unit ownership changed.
	if enableAttempted && !wasEnabled {
		if _, err := p.Runner.Run(repairCtx, systemctl, "disable", restoreSystemdUnitName); err != nil {
			return fmt.Errorf("systemd unit compensation incomplete: disable owned enablement: %w", err)
		}
		if err := p.guardExactPublishedUnit(path, published); err != nil {
			return fmt.Errorf("systemd unit compensation uncertain after disable: %w", err)
		}
		enabled, err := p.isEnabled(repairCtx, systemctl, restoreSystemdUnitName)
		if err != nil {
			return fmt.Errorf("systemd unit compensation incomplete: inspect disable outcome: %w", err)
		}
		if enabled {
			return fmt.Errorf("systemd unit compensation incomplete: owned unit remains enabled after disable")
		}
	}

	if fileChanged {
		// Re-read after external systemctl work, immediately before replacing
		// or deleting the operation's published file.
		if err := p.guardExactPublishedUnit(path, published); err != nil {
			return fmt.Errorf("systemd unit compensation uncertain before file restoration: %w", err)
		}
		if err := p.restorePublishedUnitWithSeam(unitDir, path, published, prior, existed); err != nil {
			return fmt.Errorf("systemd unit compensation incomplete: %w", err)
		}
		// A successful write alone is not proof that prior identity returned.
		if err := p.verifyPriorUnit(path, prior, existed); err != nil {
			return fmt.Errorf("systemd unit compensation incomplete: %w", err)
		}
	}
	if _, err := p.Runner.Run(repairCtx, systemctl, "daemon-reload"); err != nil {
		return fmt.Errorf("systemd unit compensation incomplete: daemon-reload failed: %w", err)
	}
	if err := p.verifyPriorUnit(path, prior, existed); err != nil {
		return fmt.Errorf("systemd unit compensation incomplete after daemon-reload: %w", err)
	}
	enabled, err := p.isEnabled(repairCtx, systemctl, restoreSystemdUnitName)
	if err != nil {
		return fmt.Errorf("systemd unit compensation incomplete: inspect enablement: %w", err)
	}
	if enabled != wasEnabled {
		return fmt.Errorf("systemd unit compensation incomplete: prior enablement was not preserved")
	}
	return nil
}

func (p SystemdPersistence) restorePublishedUnitWithSeam(dir, path string, published, prior []byte, existed bool) error {
	if p.restoreAfterFailure != nil {
		// A deterministic test seam for incomplete or dishonest restoration.
		// Production uses the atomic guarded restore path below.
		return p.restoreAfterFailure(dir, path, prior, existed)
	}
	return p.restorePublishedUnit(dir, path, published, prior, existed)
}

// guardExactPublishedUnit refuses symlinks, nonregular files, foreign content
// and unexpected edits. A marker alone is never sufficient proof that a
// changed unit still belongs to this operation.
func (p SystemdPersistence) guardExactPublishedUnit(path string, expected []byte) error {
	if err := p.verifyUnitPath(path); err != nil {
		return fmt.Errorf("untrusted privileged systemd unit path: %w", err)
	}
	current, opened, err := readRegularUnit(path)
	if err != nil {
		return fmt.Errorf("cannot safely inspect unit contents: %w", err)
	}
	// Validate ownership on the actual opened inode as well as the earlier
	// path identity. An in-place chmod/chown between Lstat and open must not
	// elevate an untrusted unit with otherwise identical contents.
	if p.VerifyUnitPath == nil {
		if err := protectedRootOwnership(opened); err != nil {
			return fmt.Errorf("opened systemd unit lost trusted root ownership: %w", err)
		}
	}
	if !isOwnedSystemdUnit(current) || !bytes.Equal(current, expected) {
		return fmt.Errorf("current unit is not the exact STL-owned content published by this operation")
	}
	return nil
}

func (p SystemdPersistence) verifyPriorUnit(path string, prior []byte, existed bool) error {
	if !existed {
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("newly created STL unit is not proven absent")
	}
	// A successful filesystem write alone is not proof that the prior
	// privileged unit was safely restored. Recheck ownership, regular-file
	// type and exact contents with the bounded descriptor reader.
	if err := p.guardExactPublishedUnit(path, prior); err != nil {
		return fmt.Errorf("prior STL-owned contents do not match or identity is untrusted: %w", err)
	}
	return nil
}

// IsRestoreInstalled safely distinguishes a fresh host from missing desired
// state on a host whose restore unit is already installed. A foreign unit or
// enabled identity without a proven owned file is never treated as absent.
func (p SystemdPersistence) IsRestoreInstalled(ctx context.Context) (bool, error) {
	if p.Runner == nil {
		return false, fmt.Errorf("systemd runner is required")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	unitDir := p.UnitDir
	if unitDir == "" {
		unitDir = "/etc/systemd/system"
	}
	unitPath := filepath.Join(unitDir, restoreSystemdUnitName)
	content, _, err := readRegularUnit(unitPath)
	if err == nil {
		if !isOwnedSystemdUnit(content) {
			return false, fmt.Errorf("unowned systemd restore unit identity")
		}
		if err := p.guardExactPublishedUnit(unitPath, content); err != nil {
			return false, fmt.Errorf("unverified systemd restore unit identity: %w", err)
		}
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect restore unit: %w", err)
	}
	if err := p.verifyUnitPath(unitPath); err != nil {
		return false, fmt.Errorf("cannot trust missing restore unit directory identity: %w", err)
	}
	systemctl := p.SystemctlBinary
	if systemctl == "" {
		systemctl = "systemctl"
	}
	enabled, err := p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
	if err != nil {
		return false, err
	}
	if enabled {
		return false, fmt.Errorf("enabled systemd restore identity lacks an STL-owned unit")
	}
	return false, nil
}

// RemoveRestore disables and removes only STL's owned restore unit. Failures
// preserve or restore the prior owned file/enabled state where possible.
func (p SystemdPersistence) RemoveRestore(ctx context.Context) error {
	if p.Runner == nil {
		return fmt.Errorf("systemd runner is required")
	}
	unitDir := p.UnitDir
	if unitDir == "" {
		unitDir = "/etc/systemd/system"
	}
	path := filepath.Join(unitDir, restoreSystemdUnitName)
	prior, _, err := readRegularUnit(path)
	systemctl := p.SystemctlBinary
	if systemctl == "" {
		systemctl = "systemctl"
	}
	if errors.Is(err, os.ErrNotExist) {
		// A missing canonical unit in an untrusted directory chain does
		// not prove a safe missing identity.
		if err := p.verifyUnitPath(path); err != nil {
			return fmt.Errorf("cannot trust missing restore unit directory identity: %w", err)
		}
		// The unit file being absent alone does not prove its systemd
		// enablement links are absent. Never disable a foreign identity.
		enabled, inspectErr := p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
		if inspectErr != nil {
			return fmt.Errorf("cannot verify absent STL restore unit identity: %w", inspectErr)
		}
		if enabled {
			return fmt.Errorf("refusing to claim complete cleanup: enabled systemd restore identity lacks an STL-owned unit")
		}
		if err := p.verifyPriorUnit(path, nil, false); err != nil {
			return fmt.Errorf("cannot verify missing restore unit still absent: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read systemd unit: %w", err)
	}
	if !isOwnedSystemdUnit(prior) {
		return fmt.Errorf("refusing to remove non-STL systemd unit %q", restoreSystemdUnitName)
	}
	if err := p.guardExactPublishedUnit(path, prior); err != nil {
		return fmt.Errorf("refusing to remove unverified owned unit: %w", err)
	}

	wasEnabled, err := p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
	if err != nil {
		return err
	}
	if wasEnabled {
		if _, err := p.Runner.Run(ctx, systemctl, "disable", restoreSystemdUnitName); err != nil {
			return fmt.Errorf("disable STL systemd unit: %w", err)
		}
	}
	if err := p.guardExactPublishedUnit(path, prior); err != nil {
		return fmt.Errorf("STL unit identity changed before owned removal; cleanup incomplete: %w", err)
	}
	if err := p.retireOwnedUnit(unitDir, path, prior, "delete"); err != nil {
		// Guarded compensation is safe even after an identity conflict:
		// it refuses foreign canonical files, but it can exclusively
		// reinstate the previous owned unit if the canonical path is absent.
		// Never discard foreign recovery material retained by retirement.
		restoreErr := p.compensateRemovedUnit(ctx, systemctl, unitDir, path, prior, wasEnabled)
		return errors.Join(fmt.Errorf("remove STL systemd unit: %w", err), restoreErr)
	}
	if _, err := p.Runner.Run(ctx, systemctl, "daemon-reload"); err != nil {
		restoreErr := p.compensateRemovedUnit(ctx, systemctl, unitDir, path, prior, wasEnabled)
		return errors.Join(fmt.Errorf("systemd daemon-reload after remove: %w", err), restoreErr)
	}
	if err := p.verifyPriorUnit(path, nil, false); err != nil {
		return fmt.Errorf("STL restore unit cleanup incomplete: unit identity did not remain absent: %w", err)
	}
	stillEnabled, err := p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
	if err != nil {
		return fmt.Errorf("STL restore unit cleanup incomplete: cannot verify disabled identity: %w", err)
	}
	if stillEnabled {
		return fmt.Errorf("STL restore unit cleanup incomplete: unit remains enabled after removal")
	}
	return nil
}

// compensateRemovedUnit restores a previously proven-owned file only when
// the current identity is either still exactly prior or absent. An operator's
// independently installed/replaced unit is never overwritten. Restoration
// after deletion uses an exclusive no-replace hardlink publication.
func (p SystemdPersistence) compensateRemovedUnit(ctx context.Context, systemctl, dir, path string, prior []byte, wasEnabled bool) error {
	repairBase := ctx
	if ctx.Err() != nil {
		repairBase = context.WithoutCancel(ctx)
	}
	repairCtx, cancel := context.WithTimeout(repairBase, 30*time.Second)
	defer cancel()
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := writeOwnedUnitIfAbsent(dir, path, prior, 0o644); err != nil {
			return fmt.Errorf("STL unit removal compensation incomplete: cannot restore owned file without replacement: %w", err)
		}
	case err != nil:
		return fmt.Errorf("STL unit removal compensation uncertain: cannot inspect unit identity: %w", err)
	case info.Mode().IsRegular():
		if err := p.guardExactPublishedUnit(path, prior); err != nil {
			return fmt.Errorf("STL unit removal compensation uncertain: %w", err)
		}
	default:
		return fmt.Errorf("STL unit removal compensation uncertain: foreign or nonregular file occupies unit identity")
	}
	if err := p.verifyPriorUnit(path, prior, true); err != nil {
		return fmt.Errorf("STL unit removal compensation incomplete: %w", err)
	}
	if _, err := p.Runner.Run(repairCtx, systemctl, "daemon-reload"); err != nil {
		return fmt.Errorf("STL unit removal compensation incomplete: reload: %w", err)
	}
	if err := p.guardExactPublishedUnit(path, prior); err != nil {
		return fmt.Errorf("STL unit removal compensation uncertain after reload: %w", err)
	}
	if wasEnabled {
		if _, err := p.Runner.Run(repairCtx, systemctl, "enable", restoreSystemdUnitName); err != nil {
			return fmt.Errorf("STL unit removal compensation incomplete: re-enable: %w", err)
		}
		if err := p.guardExactPublishedUnit(path, prior); err != nil {
			return fmt.Errorf("STL unit removal compensation uncertain after re-enable: %w", err)
		}
	}
	enabled, err := p.isEnabled(repairCtx, systemctl, restoreSystemdUnitName)
	if err != nil {
		return fmt.Errorf("STL unit removal compensation incomplete: enablement verification: %w", err)
	}
	if enabled != wasEnabled {
		return fmt.Errorf("STL unit removal compensation incomplete: previous enablement was not restored")
	}
	return nil
}

// writeOwnedUnitIfAbsent publishes a fully synced temporary file under the
// canonical name only if no other actor created a replacement in the meantime.
func writeOwnedUnitIfAbsent(dir, path string, contents []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, ".stl-recover-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Hard-link creation is atomic and returns EEXIST rather than replacing
	// a symlink or unit created by an independent administrator.
	if err := os.Link(tmp.Name(), path); err != nil {
		return err
	}
	// The new unit now exists at its canonical path. A directory fsync
	// failure is post-publication uncertainty, not a definitely-aborted
	// create; EnsureRestore must attempt guarded owned compensation.
	if err := syncOwnedDir(dir); err != nil {
		return &unitPublicationError{cause: err}
	}
	return nil
}

func (p SystemdPersistence) isEnabled(ctx context.Context, systemctl, name string) (bool, error) {
	result, err := p.Runner.Run(ctx, systemctl, "is-enabled", name)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, fmt.Errorf("systemd enablement inspection canceled: %w", ctxErr)
	}
	state := strings.TrimSpace(string(result.Stdout))
	// systemctl is-enabled legitimately exits nonzero for disabled (1) and
	// not-found (4). Only a completed process with the matching exit status
	// proves a negative result: partial stdout from a timed-out subprocess,
	// unrelated command failure, or transport error must never be accepted.
	if state == "disabled" || state == "not-found" {
		expectedCode := 1
		if state == "not-found" {
			expectedCode = 4
		}
		var commandErr *CommandError
		if !errors.As(err, &commandErr) || commandErr.TimedOut || commandErr.Canceled || commandErr.ExitCode != expectedCode {
			return false, fmt.Errorf("cannot verify systemd unit is %s: command execution did not complete with expected status: %w", state, errOrUnexpectedStatus(err))
		}
		return false, nil
	}
	switch state {
	case "enabled":
		// Only permanent enablement proves execution after reboot. A failed
		// inspection cannot be promoted to success by its stdout alone.
		if err != nil {
			return false, fmt.Errorf("inspect durable systemd enablement: %w", err)
		}
		return true, nil
	case "enabled-runtime", "linked-runtime":
		return false, fmt.Errorf("systemd unit is only enabled/linked at runtime, not durably persisted")
	case "linked", "alias", "indirect", "static", "masked", "masked-runtime", "generated", "transient":
		return false, fmt.Errorf("refusing ambiguous or administrator-managed systemd unit state %q", state)
	case "":
		if err == nil {
			return false, fmt.Errorf("systemctl is-enabled returned no state")
		}
		return false, fmt.Errorf("inspect systemd unit enablement: %w", err)
	default:
		if err != nil {
			return false, fmt.Errorf("inspect systemd unit enablement: %w", err)
		}
		return false, fmt.Errorf("unsupported systemd enablement state %q", state)
	}
}

// When systemctl produced a recognizable token but a nil/invalid exit
// status, construct an explicit diagnostic without assuming a command ran.
func errOrUnexpectedStatus(err error) error {
	if err != nil {
		return err
	}
	return errors.New("unexpected systemctl exit status")
}

func renderRestoreSystemdUnit(stlExecutable string) (string, error) {
	if !filepath.IsAbs(stlExecutable) || filepath.Base(stlExecutable) != "stl" || strings.ContainsAny(stlExecutable, "\r\n\x00") {
		return "", fmt.Errorf("STL executable must be an absolute path ending in /stl")
	}
	if strings.ContainsAny(stlExecutable, " \t\\\"'%;") {
		return "", fmt.Errorf("STL executable path contains unsupported systemd characters")
	}
	return fmt.Sprintf(`%s
[Unit]
Description=Restore simple-tun-link Links
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=35min
ExecStart=%s link restore --all

[Install]
WantedBy=multi-user.target
`, managedSystemdMarker, stlExecutable), nil
}

func isOwnedSystemdUnit(content []byte) bool {
	return strings.HasPrefix(string(content), managedSystemdMarker+"\n")
}

// The compatibility wrappers remain for isolated tests of publication
// failures. They only create *absent* units; production replacements and
// rollback use SystemdPersistence's guarded atomic transitions.
func writeAtomicFile(dir, path string, content []byte, mode os.FileMode) error {
	return writeAtomicFileWithHook(dir, path, content, mode, nil)
}

func writeAtomicFileWithHook(dir, path string, content []byte, mode os.FileMode, afterPublish func() error) error {
	if err := writeOwnedUnitIfAbsent(dir, path, content, mode); err != nil {
		return err
	}
	if afterPublish != nil {
		if err := afterPublish(); err != nil {
			return &unitPublicationError{cause: err}
		}
	}
	return nil
}

func syncOwnedDir(path string) error {
	// Directory durability must not open an intervening symlink or nonregular
	// object by pathname. O_DIRECTORY plus O_NONBLOCK avoids an unbounded open
	// on a substituted FIFO during failure compensation.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open owned unit directory for sync: %w", err)
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	return dir.Sync()
}
