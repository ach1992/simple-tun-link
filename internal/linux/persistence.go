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
	// The following unexported seams exercise filesystem failure paths after
	// rename in isolated tests; ordinary production instances leave them nil.
	afterUnitPublish    func() error
	restoreAfterFailure func(string, string, []byte, bool) error
}

// unitPublicationError distinguishes an error before the atomic rename from
// one after the desired unit content was published. An uncertain publication
// must not be compensated like an unchanged filesystem transaction.
type unitPublicationError struct{ cause error }

func (e *unitPublicationError) Error() string {
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
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return nil, false, fmt.Errorf("create systemd unit directory: %w", err)
	}

	prior, readErr := os.ReadFile(path)
	existed := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read systemd unit: %w", readErr)
	}
	if existed && !isOwnedSystemdUnit(prior) {
		return nil, false, fmt.Errorf("refusing to overwrite non-STL systemd unit %q", restoreSystemdUnitName)
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
		if err := writeAtomicFileWithHook(unitDir, path, []byte(content), 0o644, p.afterUnitPublish); err != nil {
			var publication *unitPublicationError
			if errors.As(err, &publication) {
				// This is not a definitely-uncommitted change: the new unit
				// may already be visible. Verify the exact owned content
				// before attempting to restore the previous identity.
				reconcileErr := p.reconcileFailedUnitPublication(ctx, systemctl, unitDir, path, []byte(content), prior, existed, wasEnabled)
				return nil, false, errors.Join(fmt.Errorf("systemd restore unit publication failed after rename: %w", err), reconcileErr)
			}
			return nil, false, err
		}
		if _, err := p.Runner.Run(ctx, systemctl, "daemon-reload"); err != nil {
			restoreErr := restoreSystemdFile(unitDir, path, prior, existed)
			_, reloadErr := p.Runner.Run(context.WithoutCancel(ctx), systemctl, "daemon-reload")
			return nil, false, errors.Join(fmt.Errorf("systemd daemon-reload: %w", err), restoreErr, reloadErr)
		}
	}

	enabledChanged := false
	if !wasEnabled {
		_, enableErr := p.Runner.Run(ctx, systemctl, "enable", restoreSystemdUnitName)
		if enableErr == nil {
			var durable bool
			durable, enableErr = p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
			if enableErr == nil && !durable {
				enableErr = fmt.Errorf("systemd restore unit is not durably enabled")
			}
		}
		if enableErr != nil {
			_, disableErr := p.Runner.Run(context.WithoutCancel(ctx), systemctl, "disable", restoreSystemdUnitName)
			var restoreErr, reloadErr error
			if fileChanged {
				restoreErr = restoreSystemdFile(unitDir, path, prior, existed)
				_, reloadErr = p.Runner.Run(context.WithoutCancel(ctx), systemctl, "daemon-reload")
			}
			return nil, false, errors.Join(fmt.Errorf("enable STL systemd unit: %w", enableErr), disableErr, restoreErr, reloadErr)
		}
		enabledChanged = true
	}
	if !fileChanged && !enabledChanged {
		return func(context.Context) error { return nil }, false, nil
	}

	undo := func(undoCtx context.Context) error {
		if err := undoCtx.Err(); err != nil {
			return err
		}
		var errs []error
		if enabledChanged {
			if _, err := p.Runner.Run(undoCtx, systemctl, "disable", restoreSystemdUnitName); err != nil {
				errs = append(errs, fmt.Errorf("disable STL systemd unit: %w", err))
			}
		}
		if fileChanged {
			if err := restoreSystemdFile(unitDir, path, prior, existed); err != nil {
				errs = append(errs, err)
			} else if _, err := p.Runner.Run(undoCtx, systemctl, "daemon-reload"); err != nil {
				errs = append(errs, fmt.Errorf("systemd daemon-reload after rollback: %w", err))
			}
		}
		return errors.Join(errs...)
	}
	return undo, true, nil
}

// reconcileFailedUnitPublication restores only the exact bytes this operation
// published. A changed, inaccessible, or foreign unit is never overwritten or
// removed. The caller still receives failure even after successful repair.
func (p SystemdPersistence) reconcileFailedUnitPublication(ctx context.Context, systemctl, unitDir, path string, published, prior []byte, existed, wasEnabled bool) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("systemd unit publication uncertain: cannot inspect current unit: %w", err)
	}
	if !bytes.Equal(current, published) || !isOwnedSystemdUnit(current) {
		return fmt.Errorf("systemd unit publication uncertain: current file no longer matches the STL-owned published unit; refusing overwrite")
	}

	restore := p.restoreAfterFailure
	if restore == nil {
		restore = restoreSystemdFile
	}
	if err := restore(unitDir, path, prior, existed); err != nil {
		return fmt.Errorf("systemd unit publication compensation incomplete: %w", err)
	}
	// Successful filesystem calls alone are insufficient if the identity
	// changed during cleanup. Re-read the compensated unit before reloading
	// systemd and claiming restoration of the exact previous contents.
	if existed {
		recovered, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("systemd unit publication compensation incomplete: cannot inspect restored unit: %w", err)
		}
		if !bytes.Equal(recovered, prior) {
			return fmt.Errorf("systemd unit publication compensation incomplete: prior owned contents do not match")
		}
	} else {
		_, err := os.Lstat(path)
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("systemd unit publication compensation incomplete: newly created unit is not proven absent")
		}
	}

	// A canceled caller must not prevent refreshing systemd after restoring
	// the old file. Share one limited cleanup budget for reload and identity
	// verification; do not claim success when systemd cannot be reconciled.
	repairCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, err := p.Runner.Run(repairCtx, systemctl, "daemon-reload"); err != nil {
		return fmt.Errorf("systemd unit publication compensation incomplete: daemon-reload failed: %w", err)
	}
	enabled, err := p.isEnabled(repairCtx, systemctl, restoreSystemdUnitName)
	if err != nil {
		return fmt.Errorf("systemd unit publication compensation incomplete: cannot inspect enablement: %w", err)
	}
	if enabled != wasEnabled {
		return fmt.Errorf("systemd unit publication compensation incomplete: prior enablement was not preserved")
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
	content, err := os.ReadFile(filepath.Join(unitDir, restoreSystemdUnitName))
	if err == nil {
		if !isOwnedSystemdUnit(content) {
			return false, fmt.Errorf("unowned systemd restore unit identity")
		}
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect restore unit: %w", err)
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
	prior, err := os.ReadFile(path)
	systemctl := p.SystemctlBinary
	if systemctl == "" {
		systemctl = "systemctl"
	}
	if errors.Is(err, os.ErrNotExist) {
		// The unit file being absent alone does not prove its systemd
		// enablement links are absent. Never disable a foreign identity.
		enabled, inspectErr := p.isEnabled(ctx, systemctl, restoreSystemdUnitName)
		if inspectErr != nil {
			return fmt.Errorf("cannot verify absent STL restore unit identity: %w", inspectErr)
		}
		if enabled {
			return fmt.Errorf("refusing to claim complete cleanup: enabled systemd restore identity lacks an STL-owned unit")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read systemd unit: %w", err)
	}
	if !isOwnedSystemdUnit(prior) {
		return fmt.Errorf("refusing to remove non-STL systemd unit %q", restoreSystemdUnitName)
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
	if err := os.Remove(path); err != nil {
		if wasEnabled {
			_, _ = p.Runner.Run(context.WithoutCancel(ctx), systemctl, "enable", restoreSystemdUnitName)
		}
		return fmt.Errorf("remove STL systemd unit: %w", err)
	}
	if err := syncOwnedDir(unitDir); err != nil {
		restoreErr := writeAtomicFile(unitDir, path, prior, 0o644)
		if wasEnabled {
			_, _ = p.Runner.Run(context.WithoutCancel(ctx), systemctl, "enable", restoreSystemdUnitName)
		}
		return errors.Join(err, restoreErr)
	}
	if _, err := p.Runner.Run(ctx, systemctl, "daemon-reload"); err != nil {
		restoreErr := writeAtomicFile(unitDir, path, prior, 0o644)
		if wasEnabled {
			_, _ = p.Runner.Run(context.WithoutCancel(ctx), systemctl, "enable", restoreSystemdUnitName)
		}
		_, reloadErr := p.Runner.Run(context.WithoutCancel(ctx), systemctl, "daemon-reload")
		return errors.Join(fmt.Errorf("systemd daemon-reload after remove: %w", err), restoreErr, reloadErr)
	}
	return nil
}

func (p SystemdPersistence) isEnabled(ctx context.Context, systemctl, name string) (bool, error) {
	result, err := p.Runner.Run(ctx, systemctl, "is-enabled", name)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, fmt.Errorf("systemd enablement inspection canceled: %w", ctxErr)
	}
	state := strings.TrimSpace(string(result.Stdout))
	switch state {
	case "enabled":
		// Only permanent enablement proves execution after reboot. A failed
		// inspection cannot be promoted to success by its stdout alone.
		if err != nil {
			return false, fmt.Errorf("inspect durable systemd enablement: %w", err)
		}
		return true, nil
	case "disabled", "not-found":
		return false, nil
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

func restoreSystemdFile(dir, path string, prior []byte, existed bool) error {
	if existed {
		return writeAtomicFile(dir, path, prior, 0o644)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove STL systemd unit: %w", err)
	}
	return syncOwnedDir(dir)
}

func writeAtomicFile(dir, path string, content []byte, mode os.FileMode) error {
	return writeAtomicFileWithHook(dir, path, content, mode, nil)
}

// The optional hook runs only after successful rename; it is nil in
// production and permits deterministic, non-privileged durability failures.
func writeAtomicFileWithHook(dir, path string, content []byte, mode os.FileMode, afterPublish func() error) error {
	tmp, err := os.CreateTemp(dir, ".stl-unit-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary owned file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if afterPublish != nil {
		if err := afterPublish(); err != nil {
			return &unitPublicationError{cause: err}
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		return &unitPublicationError{cause: err}
	}
	if err := syncOwnedDir(dir); err != nil {
		return &unitPublicationError{cause: err}
	}
	return nil
}

func syncOwnedDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
