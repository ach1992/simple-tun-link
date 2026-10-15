package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/state"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestPersistenceFailureKeepsTypedRootCauseSeparateFromRollbackEvidence(t *testing.T) {
	cases := []struct {
		kind linux.RestoreFailureKind
		hint string
	}{
		{linux.RestoreExecutableUntrusted, "namei -l /usr/local/bin/stl"},
		{linux.RestoreUnitPathUntrusted, "namei -l /etc/systemd/system/simple-tun-link-restore.service"},
		{linux.RestoreUnitConflict, "systemctl cat simple-tun-link-restore.service"},
		{linux.RestoreEnablementUnknown, "ps -p 1 -o comm="},
		{linux.RestoreDaemonReloadFailed, "journalctl -b -u simple-tun-link-restore.service"},
		{linux.RestoreEnableFailed, "systemctl is-enabled simple-tun-link-restore.service"},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			const internalSecret = "INTERNAL_PRIVATE_OS_OUTPUT_DO_NOT_EXPOSE"
			wrapped := stlerr.Wrap(stlerr.CodeState, "ensure", "", "gre", "restore setup failed",
				&linux.RestoreFailure{Kind: tc.kind, Cause: errors.New(internalSecret)})
			ev := &stlerr.OperationEvidence{Stage: "persistence", HostMutation: "attempted",
				DesiredState: "no_commit_attempted", Rollback: "completed_unverified"}
			for _, machine := range []bool{false, true} {
				var out, errOut bytes.Buffer
				if code := lifecycleFailureWithEvidence(&out, &errOut, machine, stlerr.CodeState, "link_ensure",
					nil, "Link creation not confirmed", ev, wrapped); code != 1 {
					t.Fatalf("unexpected CLI exit status: %d", code)
				}
				output := out.String() + errOut.String()
				if strings.Contains(output, internalSecret) || !strings.Contains(output, string(tc.kind)) ||
					!strings.Contains(output, "rollback_completed_unverified") ||
					!strings.Contains(output, tc.hint) {
					t.Fatalf("diagnostic evidence missing or raw OS output exposed: %q", output)
				}
				if machine {
					var response lifecycleFailureResponse
					if err := json.Unmarshal(out.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					if response.SchemaVersion != 1 || response.Outcome != "unconfirmed" ||
						!response.ReconciliationRequired || response.Error.ReasonCode != "rollback_completed_unverified" ||
						response.Error.Evidence.Stage != "persistence" {
						t.Fatalf("machine failure/schema evidence changed: %+v", response)
					}
				}
			}
		})
	}
}

type injectedRestorePrecommitFailure struct{}

func (*injectedRestorePrecommitFailure) EnsureRestore(context.Context, string) (func(context.Context) error, bool, error) {
	return nil, false, &linux.RestoreFailure{
		Kind:  linux.RestoreEnablementUnknown,
		Cause: errors.New("PRIVATE_SYSTEMCTL_TRANSCRIPT_NEVER_EXPOSE"),
	}
}
func (*injectedRestorePrecommitFailure) RemoveRestore(context.Context) error { return nil }
func (*injectedRestorePrecommitFailure) IsRestoreInstalled(context.Context) (bool, error) {
	return false, nil
}

func TestRealEnginePersistenceRollbackCarriesVerifiedFailureCategory(t *testing.T) {
	root := t.TempDir()
	link, raw := makeLifecycleDesired(t, "b", "10.70.24.0/31")
	fake := newLifecycleFake()
	opts := &runtimeOptions{
		stateRoot: root, backends: []backend.Backend{fake},
		restorePersistence: &injectedRestorePrecommitFailure{}, executable: "/usr/local/bin/stl",
	}
	var out, errOut bytes.Buffer
	code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"},
		strings.NewReader(raw), &out, &errOut, opts)
	payload := assertCLIRecoveryFailure(t, code, out.String(), errOut.String(),
		"state_failed", "persistence", "attempted", "rollback_completed_unverified")
	if payload.Error.Evidence.DesiredState != "no_commit_attempted" ||
		!strings.Contains(payload.Error.NextStep, "restore_enablement_unverified") ||
		!strings.Contains(payload.Error.NextStep, "ps -p 1 -o comm=") ||
		fake.present[link.ID] {
		t.Fatalf("real Engine lost typed persistence root classification or failed rollback: %+v", payload)
	}
	snap, err := state.NewFileStore(root).Load(context.Background())
	if err != nil || len(snap.Links) != 0 {
		t.Fatalf("unconfirmed persistence wrote desired State: %+v / %v", snap, err)
	}
}

func TestInteractivePersistenceFailureRendersReadableSafeSections(t *testing.T) {
	_, stdoutTTY := openMenuPTY(t)
	master, stderrTTY := openMenuPTY(t)
	t.Setenv("TERM", "xterm")
	var output bytes.Buffer
	sensitive := &linux.RestoreFailure{
		Kind: linux.RestoreUnitConflict, Cause: errors.New("PRIVATE_OS_UNIT_TEXT")}
	ev := &stlerr.OperationEvidence{
		Stage: "persistence", HostMutation: "attempted",
		DesiredState: "no_commit_attempted", Rollback: "completed_unverified",
	}
	if got := lifecycleFailureWithEvidence(stdoutTTY, stderrTTY, false, stlerr.CodeState, "link_import",
		nil, "Import not confirmed", ev, sensitive); got != 1 {
		t.Fatalf("unsafe return status: %d", got)
	}
	if output.Len() != 0 {
		t.Fatal("human failure mistakenly wrote machine JSON")
	}
	// A PTY can split the final Reference into a later read. Do not assert
	// fields that have not been fully received on a faster CI runner.
	text := readMenuPTYUntil(t, master, "TUNNEL OPERATION / INCOMPLETE",
		"NEXT STEP / NO AUTOMATIC RETRY", "link_import / persistence / rollback_completed_unverified")
	for _, marker := range []string{
		"TUNNEL OPERATION / INCOMPLETE", "[FAILED]", "link_import", "persistence",
		"rollback_completed_unverified", "restore_unit_identity_conflict",
		"NEXT STEP / NO AUTOMATIC RETRY",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("human terminal omitted %q: %q", marker, text)
		}
	}
	if strings.Contains(text, "PRIVATE_OS_UNIT_TEXT") {
		t.Fatal("raw unit output was leaked to operator")
	}
}
