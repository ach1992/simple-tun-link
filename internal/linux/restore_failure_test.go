package linux

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRestoreFailureTypeRetainsInternalCauseWithoutPrintingIt(t *testing.T) {
	sensitive := errors.New("UNTRUSTED_OS_DATA_MUST_NOT_LEAK")
	w := classifyRestoreFailure(RestoreExecutableUntrusted, sensitive)
	if !errors.Is(w, sensitive) {
		t.Fatal("typed error lost canonical wrapped cause")
	}
	kind, ok := RestoreFailureOf(w)
	if !ok || kind != RestoreExecutableUntrusted || strings.Contains(w.Error(), sensitive.Error()) {
		t.Fatalf("type classification is unsafe: %v %t %q", kind, ok, w.Error())
	}
	unknown := classifyRestoreFailure("unsupported_typename", sensitive)
	if _, ok := RestoreFailureOf(unknown); ok {
		t.Fatal("unrecognized stage was accepted as trustworthy")
	}
}

func TestSystemdRestorePathFailureClassificationWithoutHostMutation(t *testing.T) {
	runner := &recordingRunner{}
	p := SystemdPersistence{
		Runner:           runner,
		UnitDir:          t.TempDir(),
		VerifyExecutable: func(string) error { return errors.New("private path/details") },
		VerifyUnitPath:   func(string) error { return nil },
	}
	_, _, err := p.EnsureRestore(context.Background(), "/usr/local/bin/stl")
	if kind, ok := RestoreFailureOf(err); !ok || kind != RestoreExecutableUntrusted {
		t.Fatalf("incorrect verified failure site: %v (%v)", kind, err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("refused restore executor mutated systemd")
	}
}

// testRestoreCause inspects the private cause only from in-package tests.
// Production intentionally exposes a stable, credential-safe category, not
// the untrusted OS error.
func testRestoreCause(err error, expected RestoreFailureKind, originalContains string) bool {
	kind, found := RestoreFailureOf(err)
	if !found || kind != expected {
		return false
	}
	var typed *RestoreFailure
	return errors.As(err, &typed) && typed.Cause != nil &&
		strings.Contains(typed.Cause.Error(), originalContains)
}
