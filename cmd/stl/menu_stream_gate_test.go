//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
	"golang.org/x/sys/unix"
)

// Failure pages and menu error notices must share the session stdout
// capability, never make an independent choice solely from stderr.
func enableTTYColorsForBoundaryTest(t *testing.T) {
	t.Helper()
	t.Setenv("TERM", "xterm")
	t.Setenv("CLICOLOR", "1")
	previous, present := os.LookupEnv("NO_COLOR")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv("NO_COLOR", previous)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	})
}

func testSessionFailure(t *testing.T, stdout, stderr *os.File, jsonOutput bool) int {
	t.Helper()
	issue := &linux.RestoreFailure{
		Kind:  linux.RestoreUnitConflict,
		Cause: errors.New("PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE"),
	}
	evidence := &stlerr.OperationEvidence{
		Stage: "persistence", HostMutation: "attempted",
		DesiredState: "no_commit_attempted", Rollback: "completed_unverified",
	}
	return lifecycleFailureWithEvidence(stdout, stderr, jsonOutput,
		stlerr.CodeState, "link_import", nil, "Import not confirmed", evidence, issue)
}

func TestRedirectedStdoutWithInteractiveStderrCannotEmitANSI(t *testing.T) {
	enableTTYColorsForBoundaryTest(t)
	master, slave := openMenuPTY(t)
	outFile, err := os.CreateTemp(t.TempDir(), "redirected-stdout-")
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	if got := testSessionFailure(t, outFile, slave, false); got != 1 {
		t.Fatalf("failure exit code=%d", got)
	}
	message := readMenuPTYUntil(t, master, "Reason:", "Next:", "Evidence:")
	for _, want := range []string{
		"Import not confirmed", "rollback_completed_unverified",
		"restore_unit_identity_conflict", "persistence", "systemctl cat",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("stable plaintext error missing %q: %q", want, message)
		}
	}
	if strings.Contains(message, "\x1b[") ||
		strings.Contains(message, "PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE") ||
		strings.Contains(message, "OPERATION NOT COMPLETED") {
		t.Fatalf("non-TTY stdout unexpectedly enabled terminal rendering: %q", message)
	}
}

func TestBothRedirectedStreamsRetainPlainErrorContract(t *testing.T) {
	enableTTYColorsForBoundaryTest(t)
	var stdout, stderr bytes.Buffer
	issue := &linux.RestoreFailure{Kind: linux.RestoreUnitConflict,
		Cause: errors.New("PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE")}
	ev := &stlerr.OperationEvidence{Stage: "persistence", HostMutation: "attempted",
		DesiredState: "no_commit_attempted", Rollback: "completed_unverified"}
	if code := lifecycleFailureWithEvidence(&stdout, &stderr, false,
		stlerr.CodeState, "link_import", nil, "Import not confirmed", ev, issue); code != 1 {
		t.Fatalf("incorrect failure status: %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("plaintext error wrote stdout: %q", stdout.String())
	}
	for _, line := range []string{"Reason: rollback_completed_unverified",
		"Next:", "Evidence: stage=persistence host_mutation=attempted desired_state=no_commit_attempted rollback=completed_unverified"} {
		if !strings.Contains(stderr.String(), line) {
			t.Fatalf("plain output contract changed: %q", stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "\x1b[") ||
		strings.Contains(stderr.String(), "PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE") {
		t.Fatalf("redirected error contains terminal control or internal OS details: %q", stderr.String())
	}
}

func TestBothInteractiveTTYStreamsRetainHumanFailurePage(t *testing.T) {
	enableTTYColorsForBoundaryTest(t)
	_, stdout := openMenuPTY(t)
	master, stderr := openMenuPTY(t)
	if code := testSessionFailure(t, stdout, stderr, false); code != 1 {
		t.Fatalf("failure exit code=%d", code)
	}
	text := readMenuPTYUntil(t, master, "OPERATION NOT COMPLETED", "WHAT TO CHECK NEXT",
		"restore_unit_identity_conflict")
	if !strings.Contains(text, "\x1b[1;31m") ||
		!strings.Contains(text, "[FAILED]") ||
		strings.Contains(text, "\x1b[2J") ||
		strings.Contains(text, "PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE") {
		t.Fatalf("interactive human page/secret boundary is wrong: %q", text)
	}
}

func TestMachineJSONRemainsANSIAndStderrFree(t *testing.T) {
	enableTTYColorsForBoundaryTest(t)
	master, stderr := openMenuPTY(t)
	var stdout bytes.Buffer
	issue := &linux.RestoreFailure{Kind: linux.RestoreUnitConflict,
		Cause: errors.New("PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE")}
	ev := &stlerr.OperationEvidence{Stage: "persistence", HostMutation: "attempted",
		DesiredState: "no_commit_attempted", Rollback: "completed_unverified"}
	if code := lifecycleFailureWithEvidence(&stdout, stderr, true,
		stlerr.CodeState, "link_import", nil, "Import not confirmed", ev, issue); code != 1 {
		t.Fatalf("machine exit code=%d", code)
	}
	if strings.Contains(stdout.String(), "\x1b[") ||
		strings.Contains(stdout.String(), "PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE") {
		t.Fatalf("machine stream leaked escape or private value: %q", stdout.String())
	}
	var response lifecycleFailureResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil ||
		response.SchemaVersion != 1 || response.Outcome != "unconfirmed" ||
		!response.ReconciliationRequired || response.Error.Evidence.Stage != "persistence" {
		t.Fatalf("machine schema/output changed: %+v, %v", response, err)
	}
	if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	var unexpected [100]byte
	n, err := unix.Read(int(master.Fd()), unexpected[:])
	if n > 0 || (err != nil && !errors.Is(err, unix.EAGAIN)) {
		t.Fatalf("machine error unexpectedly rendered to TTY stderr: n=%d err=%v", n, err)
	}
}

func TestManageErrorNoticeHonorsRedirectedStdoutBoundary(t *testing.T) {
	enableTTYColorsForBoundaryTest(t)
	stateAsFile := filepath.Join(t.TempDir(), "invalid-state-root")
	if err := os.WriteFile(stateAsFile, []byte("NOT_A_DIRECTORY"), 0600); err != nil {
		t.Fatal(err)
	}
	master, stderr := openMenuPTY(t)
	var stdout bytes.Buffer
	input := strings.NewReader("")
	if code := menuManage(input, bufio.NewReader(input), &stdout, stderr,
		&runtimeOptions{stateRoot: stateAsFile}); code != 1 {
		t.Fatalf("expected state load error, exit=%d", code)
	}
	text := readMenuPTYUntil(t, master, "Cannot load saved tunnels")
	if !strings.Contains(text, "[FAILED]") || strings.Contains(text, "\x1b[") {
		t.Fatalf("Manage error ignored stdout nonTTY boundary: %q", text)
	}
}

// When only stdout is a TTY, an error redirected to a file remains a
// plain, stable stderr diagnostic, not a presentation surface.
func TestInteractiveStdoutWithRedirectedStderrRemainsPlain(t *testing.T) {
	enableTTYColorsForBoundaryTest(t)
	_, stdout := openMenuPTY(t)
	var stderr bytes.Buffer
	issue := &linux.RestoreFailure{Kind: linux.RestoreUnitConflict,
		Cause: errors.New("PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE")}
	if code := lifecycleFailureWithEvidence(stdout, &stderr, false,
		stlerr.CodeState, "link_import", nil, "Import not confirmed", nil, issue); code != 1 {
		t.Fatalf("incorrect exit code: %d", code)
	}
	if !strings.Contains(stderr.String(), "Reason:") || strings.Contains(stderr.String(), "\x1b[") ||
		strings.Contains(stderr.String(), "PRIVATE_UNIT_TEXT_MUST_NOT_ESCAPE") {
		t.Fatalf("redirected stderr unexpectedly styled or leaked private details: %q", stderr.String())
	}
}

// TERM=dumb must never opt into human ANSI error styling even when both
// underlying file descriptors happen to be actual PTYs.
func TestDumbTerminalUsesPlainFailureEvenWithTwoPTYs(t *testing.T) {
	t.Setenv("TERM", "dumb")
	_, stdout := openMenuPTY(t)
	master, stderr := openMenuPTY(t)
	if code := testSessionFailure(t, stdout, stderr, false); code != 1 {
		t.Fatalf("incorrect exit code: %d", code)
	}
	text := readMenuPTYUntil(t, master, "Reason:", "Next:", "Evidence:")
	if strings.Contains(text, "\x1b[") || strings.Contains(text, "OPERATION NOT COMPLETED") {
		t.Fatalf("TERM=dumb unexpectedly received interactive failure rendering: %q", text)
	}
}
