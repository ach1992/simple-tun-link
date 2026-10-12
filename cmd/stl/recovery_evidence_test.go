package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func assertCLIRecoveryFailure(t *testing.T, exit int, output, stderr, code, stage, host, reason string) lifecycleFailureResponse {
	t.Helper()
	if exit != 1 && exit != 4 {
		t.Fatalf("mutation failure incorrectly succeeded or changed exit code: %d", exit)
	}
	if stderr != "" || strings.Contains(output, "VERY_SECRET_NOT_FOR_OUTPUT") ||
		strings.Contains(output, "DO_NOT_EXPOSE") || strings.Contains(output, "private_key") {
		t.Fatalf("JSON stdout/secret contract violated: stdout=%q stderr=%q", output, stderr)
	}
	var payload lifecycleFailureResponse
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("not one valid machine JSON record: %q %v", output, err)
	}
	if payload.SchemaVersion != 1 || payload.Outcome != "unconfirmed" || !payload.ReconciliationRequired ||
		payload.Error == nil || string(payload.Error.Code) != code ||
		payload.Error.ReasonCode != reason || payload.Error.NextStep == "" ||
		payload.Error.Evidence == nil || payload.Error.Evidence.Stage != stage ||
		payload.Error.Evidence.HostMutation != host {
		t.Fatalf("bad v1-compatible Engine stage/evidence or operator guidance: %+v", payload)
	}
	return payload
}

func TestLifecycleOperatorFailureRecoveryAcrossEngineStages(t *testing.T) {
	_, desired := makeLifecycleDesired(t, "a", "10.70.20.0/31")
	{
		root := t.TempDir()
		exit, out, stderr := runLifecycleTest(t, root, nil, []string{"link", "ensure", "--stdin", "--json"}, desired)
		payload := assertCLIRecoveryFailure(t, exit, out, stderr, "unsupported", "preflight",
			"not_attempted", "rejected_before_host_apply")
		if payload.Error.Evidence.Rollback != "not_required" || payload.Error.Evidence.DesiredState != "no_commit_attempted" {
			t.Fatalf("preflight incorrectly implies host mutation: %+v", payload.Error.Evidence)
		}
	}
	for _, mode := range []string{"apply", "verify"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			b := newLifecycleFake()
			if mode == "apply" {
				b.failApply = true
			} else {
				b.failVerify = true
			}
			exit, out, stderr := runLifecycleTest(t, root, b, []string{"link", "ensure", "--stdin", "--json"}, desired)
			stageReason := map[string]string{"apply": "apply_outcome_unverified", "verify": "rollback_completed_unverified"}[mode]
			payload := assertCLIRecoveryFailure(t, exit, out, stderr, map[string]string{"apply": "apply_failed", "verify": "verify_failed"}[mode],
				mode, "attempted", stageReason)
			if mode == "verify" && payload.Error.Evidence.Rollback != "completed_unverified" {
				t.Fatalf("successful rollback callback was not distinguished from verified host state: %+v", payload.Error.Evidence)
			}
		})
	}
}

type moduleInspectionBackend struct{ *lifecycleFakeBackend }

func (*moduleInspectionBackend) Inspect(context.Context, domain.Link) (backend.Observation, error) {
	return nil, backend.KernelModuleNotLoaded("fou")
}

func TestLifecycleOperatorMissingModuleIsSpecificBeforeHostApply(t *testing.T) {
	root := t.TempDir()
	_, desired := makeLifecycleDesired(t, "b", "10.70.21.0/31")
	var stdout, stderr bytes.Buffer
	code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"}, strings.NewReader(desired),
		&stdout, &stderr, &runtimeOptions{stateRoot: root, backends: []backend.Backend{&moduleInspectionBackend{newLifecycleFake()}}})
	payload := assertCLIRecoveryFailure(t, code, stdout.String(), stderr.String(),
		"inspect_failed", "inspect", "not_attempted", "kernel_module_not_loaded")
	if payload.Error.Evidence.DesiredState != "no_commit_attempted" || payload.Error.Evidence.Rollback != "not_required" {
		t.Fatalf("missing module altered/emptied inventory: %+v", payload)
	}
}

func TestLifecycleVerifiedSuccessAndIdempotenceKeepV1ResultShape(t *testing.T) {
	root := t.TempDir()
	b := newLifecycleFake()
	_, desired := makeLifecycleDesired(t, "c", "10.70.22.0/31")
	for i := 0; i < 2; i++ {
		code, out, stderr := runLifecycleTest(t, root, b, []string{"link", "ensure", "--stdin", "--json"}, desired)
		if code != 0 || stderr != "" {
			t.Fatalf("ensure failed: exit %d stdout %q stderr %q", code, out, stderr)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(out), &payload); err != nil {
			t.Fatal(err)
		}
		if payload["schema_version"] != float64(1) || payload["changed"] != (i == 0) ||
			payload["removed"] != false || payload["operation"] != "link_ensure" || payload["error"] != nil ||
			payload["evidence"] != nil {
			t.Fatalf("existing stable v1 success shape was altered: %+v", payload)
		}
	}
	if len(b.applies) != 1 {
		t.Fatalf("no-op caused extra backend writes: %d", len(b.applies))
	}
	_ = stlerr.CodeInspect // ensure optional error model remains independent of result
}

func TestLifecycleCredentialProvisionFailureCannotBePromotedToSafeNoop(t *testing.T) {
	proof := &stlerr.OperationEvidence{Stage: "credential_provision",
		HostMutation: "not_attempted", DesiredState: "no_commit_attempted",
		Rollback: "not_required", CredentialProvision: "attempted"}
	failure := stlerr.New(stlerr.CodeState, "ensure_imported",
		"lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "wireguard", "protected credential could not be provisioned")
	var stdout, stderr bytes.Buffer
	exit := lifecycleFailureWithEvidence(&stdout, &stderr, true, stlerr.CodeState, "link_import", nil,
		"Link import did not complete successfully", proof, failure)
	var payload lifecycleFailureResponse
	if exit != 1 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &payload) != nil ||
		payload.Error == nil || payload.Error.ReasonCode != "credential_provision_outcome_unverified" ||
		payload.Error.Evidence == nil || payload.Error.Evidence.CredentialProvision != "attempted" ||
		!strings.Contains(payload.Error.NextStep, "protected local key") {
		t.Fatalf("CLI hid potentially retained protected credential: exit=%d output=%s", exit, stdout.String())
	}
}
