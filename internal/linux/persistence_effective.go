package linux

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// Only isolated root-ownership fixtures use VerifyUnitPath. Production always
// requires a bounded manager proof, including when a custom Runner is supplied.
// Dedicated fake-systemctl tests opt in through the private force flag.
func (p SystemdPersistence) skipEffectiveInspectionForTest() bool {
	return p.VerifyUnitPath != nil && !p.forceEffectiveInspectionForTest
}

// readSystemdEffectiveProperties reads the *manager-loaded* unit, including
// service-specific, prefix and type-wide drop-ins that a main-file-only check
// cannot see. The strict property inventory denies partial, duplicate,
// unexpected, stale or failed systemd inspection. No subprocess text is
// reflected into privileged diagnostics.
func (p SystemdPersistence) readSystemdEffectiveProperties(ctx context.Context, systemctl string, keys ...string) (map[string]string, error) {
	if p.Runner == nil {
		return nil, errors.New("systemd effective-unit inspector is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("systemd effective-unit inspection canceled")
	}
	args := []string{"show", restoreSystemdUnitName, "--no-pager", "--all"}
	expected := make(map[string]bool, len(keys))
	for _, key := range keys {
		if expected[key] {
			return nil, errors.New("duplicate requested systemd property")
		}
		expected[key] = true
		args = append(args, "-p", key)
	}
	const stdoutLimit = 4096
	const stderrLimit = 1024
	var result CommandResult
	var err error
	if bounded, ok := p.Runner.(BoundedRunner); ok {
		result, err = bounded.RunBounded(ctx, CaptureLimits{Stdout: stdoutLimit, Stderr: stderrLimit},
			systemctl, args...)
	} else if p.forceEffectiveInspectionForTest {
		// This test-only fallback remains post-hoc bounded; the real
		// ExecRunner is a BoundedRunner and limits capture during execution.
		result, err = p.Runner.Run(ctx, systemctl, args...)
	} else {
		return nil, errors.New("bounded systemd effective-unit inspector unavailable")
	}
	if ctx.Err() != nil || err != nil ||
		len(result.Stderr) != 0 || len(result.Stdout) > stdoutLimit || len(result.Stdout) == 0 {
		return nil, errors.New("cannot prove complete manager-loaded restore-unit identity")
	}
	props := make(map[string]string, len(keys))
	for _, line := range strings.Split(strings.TrimSuffix(string(result.Stdout), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !expected[key] {
			return nil, errors.New("manager-loaded restore unit returned unrequested or incomplete metadata")
		}
		if _, duplicate := props[key]; duplicate {
			return nil, errors.New("manager-loaded restore unit returned duplicate metadata")
		}
		props[key] = value
	}
	if len(props) != len(expected) {
		return nil, errors.New("manager-loaded restore unit returned incomplete metadata")
	}
	return props, nil
}

// verifyEffectiveRestoreUnit admits the complete canonical *loaded* service.
// The public STL marker, exact main-file bytes and trusted inode alone do
// not authorize disabling, replacing, adopting or deleting systemd resources.
func (p SystemdPersistence) verifyEffectiveRestoreUnit(ctx context.Context, systemctl, path string) error {
	if p.skipEffectiveInspectionForTest() {
		return nil
	}
	props, err := p.readSystemdEffectiveProperties(ctx, systemctl,
		"LoadState", "FragmentPath", "DropInPaths", "NeedDaemonReload", "ExecStart")
	if err != nil {
		return err
	}
	if props["LoadState"] != "loaded" ||
		props["FragmentPath"] != filepath.Clean(path) ||
		props["DropInPaths"] != "" ||
		props["NeedDaemonReload"] != "no" {
		return errors.New("systemd restore unit has a foreign fragment, drop-in or stale manager configuration")
	}
	// The manager's normalized ExecStart has dynamic last-run metadata.
	// Its single command, arguments and error handling must be canonical.
	const command = "/usr/local/bin/stl"
	want := "{ path=" + command + " ; argv[]=" + command + " link restore --all ; ignore_errors=no ; "
	effective := props["ExecStart"]
	if !strings.HasPrefix(effective, want) || !strings.HasSuffix(effective, " }") ||
		strings.Count(effective, "argv[]=") != 1 || strings.Count(effective, "{ path=") != 1 {
		return errors.New("systemd effective restore command is not the canonical STL command")
	}
	return nil
}

// verifyAbsentEffectiveRestoreUnit also refuses a leftover standalone
// drop-in/manager identity when no main STL unit file exists. A disabled or
// not-found enablement check alone cannot prove the entire unit is absent.
func (p SystemdPersistence) verifyAbsentEffectiveRestoreUnit(ctx context.Context, systemctl string) error {
	if p.skipEffectiveInspectionForTest() {
		return nil
	}
	props, err := p.readSystemdEffectiveProperties(ctx, systemctl,
		"LoadState", "FragmentPath", "DropInPaths", "NeedDaemonReload")
	if err != nil {
		return err
	}
	if props["LoadState"] != "not-found" || props["FragmentPath"] != "" ||
		props["DropInPaths"] != "" || props["NeedDaemonReload"] != "no" {
		return errors.New("systemd missing restore unit has a foreign drop-in, fragment or stale manager configuration")
	}
	return nil
}
