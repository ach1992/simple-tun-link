package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestOperatorTroubleshootingReasonAndNextStepAcrossCoreCLIs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new-state")
	id := "lnk_1234567890abcdef1234567890abcdef"
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"read missing Link", []string{"link", "status", id, "--json"}, 2},
		{"diagnose missing Link", []string{"link", "diagnose", id, "--json"}, 2},
		{"invalid ensure input", []string{"link", "ensure", "--stdin", "--json"}, 2},
		{"invalid remove confirmation", []string{"link", "remove", id, "--confirm", "bad", "--json"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			exit := runWithRuntimeInput(tc.args, strings.NewReader("PSK=NEVER_PRINT"),
				&stdout, &stderr, &runtimeOptions{stateRoot: root})
			if exit != tc.want || stderr.Len() != 0 || strings.Contains(stdout.String(), "NEVER_PRINT") {
				t.Fatalf("unsafe or unexpected CLI result: exit %d stdout %q stderr %q", exit, stdout.String(), stderr.String())
			}
			var report linkReadErrorResponse
			if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil ||
				report.SchemaVersion != 1 || report.Error == nil ||
				report.Error.ReasonCode != "invalid_request" || report.Error.NextStep == "" {
				t.Fatalf("error did not expose safe stable operator action: %+v", report)
			}
		})
	}
	var stdout, stderr strings.Builder
	exit := lifecycleFailure(&stdout, &stderr, true, stlerr.CodeRollback,
		"link_ensure", &app.Result{}, "rollback was incomplete")
	if exit != 1 || stderr.Len() != 0 || strings.Contains(stdout.String(), "NEVER_PRINT") {
		t.Fatalf("unexpected rollback failure: %d %q %q", exit, stdout.String(), stderr.String())
	}
	var resp lifecycleFailureResponse
	if err := json.Unmarshal([]byte(stdout.String()), &resp); err != nil || resp.SchemaVersion != 1 ||
		resp.Error.ReasonCode != "rollback_incomplete" || resp.Error.NextStep == "" ||
		!resp.ReconciliationRequired || resp.Outcome != "unconfirmed" {
		t.Fatalf("unsafe/incomplete lifecycle recovery contract: %+v", resp)
	}

	stdout.Reset()
	stderr.Reset()
	_ = readCommandPublicError(&stdout, &stderr, false,
		stlerr.New(stlerr.CodeConflict, "link_status", "", "", "resource ownership uncertain"))
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Reason: resource_conflict") ||
		!strings.Contains(stderr.String(), "Next: ") {
		t.Fatalf("human error path lacks safe guidance: %q", stderr.String())
	}

}
