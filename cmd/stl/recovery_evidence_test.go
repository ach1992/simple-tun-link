package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/app"
	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/state"
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

type interruptedLifecycleInspector struct {
	*lifecycleFakeBackend
	cause error
}

func (b *interruptedLifecycleInspector) Inspect(context.Context, domain.Link) (backend.Observation, error) {
	return nil, errors.Join(b.cause, errors.New("private_key=FORBIDDEN_RAW_ERROR"))
}

func TestLifecycleCLIPreApplyInterruptionsHaveTrustedReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cause  error
		reason string
	}{
		{"deadline", context.DeadlineExceeded, "operation_deadline_exceeded_before_apply"},
		{"canceled", context.Canceled, "operation_cancelled_before_apply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			link, raw := makeLifecycleDesired(t, "8", "10.70.28.0/31")
			fake := newLifecycleFake()
			inspector := &interruptedLifecycleInspector{fake, tc.cause}
			var stdout, stderr bytes.Buffer
			code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"},
				strings.NewReader(raw), &stdout, &stderr,
				&runtimeOptions{stateRoot: root, backends: []backend.Backend{inspector}})
			payload := assertCLIRecoveryFailure(t, code, stdout.String(), stderr.String(),
				"inspect_failed", "inspect", "not_attempted", tc.reason)
			if payload.Error.Evidence.DesiredState != "no_commit_attempted" ||
				payload.Error.Evidence.Rollback != "not_required" || len(fake.applies) != 0 {
				t.Fatalf("read-only interruption incorrectly mutated host: %+v", payload)
			}
			snapshot, err := state.NewFileStore(root).Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := snapshot.Find(link.ID); exists {
				t.Fatal("interrupted Ensure persisted desired state")
			}
			stdout.Reset()
			stderr.Reset()
			code = runWithRuntimeInput([]string{"link", "ensure", "--stdin"},
				strings.NewReader(raw), &stdout, &stderr,
				&runtimeOptions{stateRoot: root, backends: []backend.Backend{inspector}})
			if code != 1 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), "Reason: "+tc.reason) ||
				!strings.Contains(stderr.String(), "Next: ") ||
				strings.Contains(stderr.String(), "FORBIDDEN_RAW_ERROR") ||
				strings.Contains(stderr.String(), "private_key=") {
				t.Fatalf("human recovery did not preserve redacted interruption: exit=%d output=%q", code, stderr.String())
			}
		})
	}
}

// A real canceled Link-lock wait is covered by internal/app. Verify that
// the same typed cause is retained by the CLI projector, not parsed from prose.
func TestLifecycleCLIProjectsCanceledLockWaitWithoutLeakingCause(t *testing.T) {
	interruption := stlerr.WithEvidence(
		stlerr.Wrap(stlerr.CodeState, "ensure", "", "", "cannot lock Link",
			errors.Join(context.DeadlineExceeded, errors.New("PSK=HIDDEN"))),
		stlerr.OperationEvidence{Stage: "preflight", HostMutation: "not_attempted",
			DesiredState: "no_commit_attempted", Rollback: "not_required"})
	var out, stderr bytes.Buffer
	exit := lifecycleFailureWithEvidence(&out, &stderr, true, stlerr.CodeState, "link_ensure",
		nil, "Link operation did not complete successfully", stlerr.EvidenceOf(interruption), interruption)
	payload := assertCLIRecoveryFailure(t, exit, out.String(), stderr.String(),
		"state_failed", "preflight", "not_attempted", "operation_deadline_exceeded_before_apply")
	if payload.Error.Evidence.Rollback != "not_required" {
		t.Fatal("cancellation before Apply incorrectly required rollback")
	}
}

type failingFinalUnitPersistence struct {
	active  bool
	removes int
}

func (p *failingFinalUnitPersistence) EnsureRestore(context.Context, string) (func(context.Context) error, bool, error) {
	previous := p.active
	p.active = true
	return func(context.Context) error { p.active = previous; return nil }, !previous, nil
}

func (p *failingFinalUnitPersistence) RemoveRestore(context.Context) error {
	p.removes++
	return errors.New("private_key=UNTRUSTED_UNIT_FAILURE")
}

func (p *failingFinalUnitPersistence) IsRestoreInstalled(context.Context) (bool, error) {
	return p.active, nil
}

func TestLifecycleCLIFinalRemoveCleanupFailurePreservesV1JSONEvidence(t *testing.T) {
	for _, tc := range []struct {
		name         string
		id           string
		subnet       string
		backendNoop  bool
		wantRollback string
	}{
		{name: "backend_noop", id: "9", subnet: "10.70.29.0/31", backendNoop: true, wantRollback: "not_required"},
		{name: "backend_changed", id: "e", subnet: "10.70.30.0/31", wantRollback: "not_attempted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			link, raw := makeLifecycleDesired(t, tc.id, tc.subnet)
			b := newLifecycleFake()
			p := &failingFinalUnitPersistence{}
			opts := &runtimeOptions{stateRoot: root, backends: []backend.Backend{b},
				restorePersistence: p, executable: "/usr/local/bin/stl"}
			var stdout, stderr bytes.Buffer
			code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"},
				strings.NewReader(raw), &stdout, &stderr, opts)
			if code != 0 || stderr.Len() != 0 || !b.present[link.ID] {
				t.Fatalf("failed to seed CLI owned Link: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if tc.backendNoop {
				// Network state was already absent before canonical Remove.
				delete(b.present, link.ID)
			}
			beforeApply := len(b.applies)
			stdout.Reset()
			stderr.Reset()
			code = runWithRuntimeInput([]string{"link", "remove", string(link.ID),
				"--confirm", string(link.ID), "--json"}, nil, &stdout, &stderr, opts)
			payload := assertCLIRecoveryFailure(t, code, stdout.String(), stderr.String(),
				"state_failed", "persistence_cleanup", "attempted", "post_commit_cleanup_incomplete")
			wantChanged := !tc.backendNoop
			wantApplyCount := beforeApply
			if wantChanged {
				wantApplyCount++
			}
			if payload.Error.Evidence.DesiredState != "committed" ||
				payload.Error.Evidence.Rollback != tc.wantRollback || payload.PartialResult == nil ||
				payload.PartialResult.LinkID != link.ID || payload.PartialResult.Changed != wantChanged ||
				!payload.PartialResult.Removed || p.removes != 1 || !p.active ||
				len(b.applies) != wantApplyCount || b.present[link.ID] {
				t.Fatalf("failed cleanup misreported committed Remove or compensated host: %+v; applies=%d", payload, len(b.applies))
			}
			snapshot, err := state.NewFileStore(root).Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := snapshot.Find(link.ID); exists {
				t.Fatal("failed unit cleanup undid committed desired-state deletion")
			}
		})
	}
}

func TestLifecycleCLIReceiptFailureProjectsActualHostMutationWithSameV1Envelope(t *testing.T) {
	id := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	for _, mutation := range []string{"not_attempted", "attempted"} {
		t.Run(mutation, func(t *testing.T) {
			err := stlerr.WithEvidence(stlerr.Wrap(stlerr.CodeState, "remove", string(id), "wireguard",
				"receipt publication not confirmed", errors.New("PSK=UNTRUSTED_RECEIPT_CAUSE")),
				stlerr.OperationEvidence{Stage: "credential_retirement", HostMutation: mutation,
					DesiredState: "committed", Rollback: "not_attempted"})
			result := &app.Result{LinkID: id, Changed: mutation == "attempted", Removed: true}
			var stdout, stderr bytes.Buffer
			code := lifecycleFailureWithEvidence(&stdout, &stderr, true, stlerr.CodeState,
				"link_remove", result, "Link operation did not complete successfully",
				stlerr.EvidenceOf(err), err)
			payload := assertCLIRecoveryFailure(t, code, stdout.String(), stderr.String(),
				"state_failed", "credential_retirement", mutation, "post_commit_cleanup_incomplete")
			if payload.PartialResult == nil || !payload.PartialResult.Removed ||
				payload.Error.Evidence.Rollback != "not_attempted" ||
				payload.Error.Evidence.DesiredState != "committed" {
				t.Fatalf("receipt failure lost committed-state evidence: %+v", payload)
			}
		})
	}
}
