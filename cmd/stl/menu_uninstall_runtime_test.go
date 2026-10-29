package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestMenuCanonicalUninstallConsentPreflightAndStaleExit(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		preflightErr error
		installErr   error
		verify       bool
		wants        int
		expectCode   int
		contains     string
	}{
		{"cancel", "\n", nil, nil, true, 0, 0, "Uninstall cancelled"},
		{"success", "UNINSTALL\n", nil, nil, true, 1, menuUpdatedExecutable, "STL uninstalled"},
		{"owned orphan restore", "UNINSTALL\n", errOwnedRestoreUnitPresent, nil, true, 1, menuUpdatedExecutable, "verified STL-owned restore unit"},
		{"preflight", "UNINSTALL\n", errors.New("saved Links or pending operations remain"), nil, true, 0, 0, "saved_or_pending_links"},
		{"failed process", "UNINSTALL\n", nil, errors.New("private-key=DO_NOT_LEAK"), true, 1, menuUpdatedExecutable, "Uninstall was not confirmed"},
		{"failed verification", "UNINSTALL\n", nil, nil, false, 1, menuUpdatedExecutable, "installation remains"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "never-used")
			input := strings.NewReader(tc.answer)
			var out, errOut bytes.Buffer
			calls := 0
			ops := menuUninstallOps{
				canAct:    func(io.Reader, io.Writer) bool { return true },
				preflight: func(context.Context) error { return tc.preflightErr },
				install: func(_ context.Context, stdout, stderr io.Writer, args ...string) error {
					calls++
					wantArgs := "uninstall"
					if errors.Is(tc.preflightErr, errOwnedRestoreUnitPresent) {
						wantArgs += " --retire-owned-restore"
					}
					if strings.Join(args, " ") != wantArgs {
						t.Fatalf("wrong canonical installer invocation: got %q want %q", args, wantArgs)
					}
					_, _ = io.WriteString(stderr, "private-token=DO_NOT_LEAK\n")
					return tc.installErr
				},
				verify: func() bool { return tc.verify },
			}
			code := menuUninstallWithOps(input, bufio.NewReader(input), &out, &errOut,
				&runtimeOptions{stateRoot: root}, ops)
			rendered := out.String() + errOut.String()
			if code != tc.expectCode || calls != tc.wants ||
				!strings.Contains(rendered, tc.contains) ||
				strings.Contains(rendered, "DO_NOT_LEAK") ||
				strings.Contains(rendered, "private-key") {
				t.Fatalf("case=%s code=%d installs=%d output=%q", tc.name, code, calls, rendered)
			}
		})
	}
}

func TestUninstallPreflightReasonDoesNotRevealRawFailure(t *testing.T) {
	for _, tc := range []struct{ message, reason string }{
		{"existing Link state root has no committed state snapshot: secret", "state_root_unverified"},
		{"saved Links or pending operations remain", "saved_or_pending_links"},
		{"protected credential retirement remains unfinished or unverified", "credential_retirement_pending"},
		{"downgrade requires a canonical empty State without retained receipts", "downgrade_state_history_retained"},
		{"Engine restore unit is still installed", "restore_unit_present"},
		{"cannot prove restore-unit absence: secret", "restore_unit_unverified"},
		{"untrusted state root: secret", "state_integrity_unverified"},
		{"private-key=DO_NOT_LEAK", "uninstall_preflight_unverified"},
	} {
		reason, next := uninstallGateGuidance(errors.New(tc.message))
		if reason != tc.reason || next == "" || strings.Contains(next, "secret") ||
			strings.Contains(reason+next, "DO_NOT_LEAK") {
			t.Fatalf("unsafe mapping: reason=%q next=%q", reason, next)
		}
	}
}
