package linux

import "errors"

// RestoreFailureKind identifies which *trusted check* failed without exposing
// subprocess output, paths supplied by a caller, or possible credential text.
// It never asserts that a specific systemd/environment problem was proven
// from an arbitrary command failure.
type RestoreFailureKind string

const (
	RestoreExecutableUntrusted RestoreFailureKind = "restore_executable_untrusted"
	RestoreUnitPathUntrusted   RestoreFailureKind = "restore_unit_path_untrusted"
	RestoreUnitConflict        RestoreFailureKind = "restore_unit_identity_conflict"
	RestoreEnablementUnknown   RestoreFailureKind = "restore_enablement_unverified"
	RestoreDaemonReloadFailed  RestoreFailureKind = "restore_daemon_reload_failed"
	RestoreEnableFailed        RestoreFailureKind = "restore_enable_failed"
)

type RestoreFailure struct {
	Kind  RestoreFailureKind
	Cause error
}

func (e *RestoreFailure) Error() string { return string(e.Kind) }
func (e *RestoreFailure) Unwrap() error { return e.Cause }

func classifyRestoreFailure(kind RestoreFailureKind, cause error) error {
	return &RestoreFailure{Kind: kind, Cause: cause}
}

// RestoreFailureOf follows typed wrapping across Engine compensation layers.
// No prose, error string, command output or untrusted data is ever parsed.
func RestoreFailureOf(err error) (RestoreFailureKind, bool) {
	var classified *RestoreFailure
	if !errors.As(err, &classified) {
		return "", false
	}
	switch classified.Kind {
	case RestoreExecutableUntrusted, RestoreUnitPathUntrusted, RestoreUnitConflict,
		RestoreEnablementUnknown, RestoreDaemonReloadFailed, RestoreEnableFailed:
		return classified.Kind, true
	}
	return "", false
}
