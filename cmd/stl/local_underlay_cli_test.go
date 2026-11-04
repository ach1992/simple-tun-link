package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Test the real versioned CLI error projection, not backend prose: a failed
// local address inventory must not be reported as a remote-peer outage.
type unverifiedLocalIPv4Backend struct{ *lifecycleFakeBackend }

func (*unverifiedLocalIPv4Backend) Plan(_ context.Context, req backend.Request, _ backend.Observation) (backend.Plan, error) {
	return nil, stlerr.LocalUnderlayUnverified("gre_plan", string(req.Link.ID), string(req.Link.Backend), errors.New("SECRET_PRIVATE_PATH_DO_NOT_ECHO"))
}

type greInventoryClassificationBackend struct {
	*lifecycleFakeBackend
	cause  error
	reason string
}

func (b *greInventoryClassificationBackend) Plan(_ context.Context, req backend.Request, _ backend.Observation) (backend.Plan, error) {
	cause := errors.Join(b.cause, errors.New("PRIVATE_KERNEL_DIAGNOSTIC_DO_NOT_ECHO"))
	if b.reason == "local_underlay_unverified" {
		return nil, stlerr.LocalUnderlayUnverified("gre_plan", string(req.Link.ID), string(req.Link.Backend), cause)
	}
	issue := stlerr.Wrap(stlerr.CodePlan, "gre_plan", string(req.Link.ID), string(req.Link.Backend),
		"the advisory route source differs", cause)
	issue.ReasonCode = b.reason
	issue.NextStep = "Inspect ip -4 route get PEER_IP"
	return nil, issue
}

// The CLI must not project an advisory source-mismatch hint over an actual
// deadline/cancellation, and must redact the underlying subprocess text.
func TestVersionedCLIGREInventoryInterruptionReasonsTakePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cause  error
		reason string
		want   string
	}{
		{"overflow", linux.ErrOutputLimit, "local_underlay_unverified", "local_underlay_capture_limited"},
		{"deadline", context.DeadlineExceeded, "gre_underlay_source_mismatch", "operation_deadline_exceeded_before_apply"},
		{"cancelled", context.Canceled, "gre_underlay_source_mismatch", "operation_cancelled_before_apply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			link, input := makeLifecycleDesired(t, "f", "10.70.44.0/31")
			b := &greInventoryClassificationBackend{lifecycleFakeBackend: newLifecycleFake(),
				cause: tc.cause, reason: tc.reason}
			var out, errOut bytes.Buffer
			code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"},
				strings.NewReader(input), &out, &errOut,
				&runtimeOptions{stateRoot: root, backends: []backend.Backend{b}})
			payload := assertCLIRecoveryFailure(t, code, out.String(), errOut.String(),
				"plan_failed", "plan", "not_attempted", tc.want)
			if payload.Error.ObjectID != string(link.ID) ||
				strings.Contains(out.String()+errOut.String(), "PRIVATE_KERNEL_DIAGNOSTIC_DO_NOT_ECHO") ||
				len(b.applies) != 0 {
				t.Fatalf("unsafe or misleading CLI error: %+v", payload)
			}
			if _, err := os.Stat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
				t.Fatalf("failed inventory committed Link State: %v", err)
			}
		})
	}
}

func TestVersionedCLICreateDeniesUnknownLocalIPBeforeHostEffects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "owner")
	link, input := makeLifecycleDesired(t, "f", "10.70.44.0/31")
	b := &unverifiedLocalIPv4Backend{newLifecycleFake()}
	var out, errOut bytes.Buffer
	code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"}, strings.NewReader(input), &out, &errOut,
		&runtimeOptions{stateRoot: root, backends: []backend.Backend{b}})
	result := assertCLIRecoveryFailure(t, code, out.String(), errOut.String(), "plan_failed", "plan", "not_attempted", "local_underlay_unverified")
	if result.Error.ObjectID != string(link.ID) || !strings.Contains(result.Error.NextStep, "ip -json address show") ||
		!strings.Contains(result.Error.NextStep, "does not require peer reachability") ||
		strings.Contains(out.String(), "SECRET_PRIVATE_PATH_DO_NOT_ECHO") || len(b.applies) != 0 {
		t.Fatalf("unsafe or misleading versioned local-error result: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("local inventory failure committed Link State: %v", err)
	}
}

// All native/managed backends share one conservative CLI/JSON recovery
// projection. Missing vs duplicate local assignment must not be replaced by
// an advisory route hint, unavailable inventory, interruption or a staged key.
func TestSharedImportUnderlayReasonsAcrossSupportedBackends(t *testing.T) {
	backends := []struct {
		kind  domain.Backend
		stage string
	}{
		{domain.BackendGRE, "plan"},
		{domain.BackendIPIP, "plan"},
		{domain.BackendL2TPv3, "plan"},
		{domain.BackendWireGuard, "plan"},
		{domain.BackendWireGuardWSS, "plan"},
		{domain.BackendWireGuardQUIC, "plan"},
		{domain.BackendIPsec, "validate"},
	}
	cases := []struct {
		name         string
		cause        error
		reason, step string
		credential   string
	}{
		{"wrong receiver", errors.Join(linux.ErrUnderlaySourceMismatch, linux.ErrUnderlayLocalNotAssigned),
			"local_underlay_not_assigned", "THIS host", ""},
		{"ambiguous receiver", linux.ErrUnderlayLocalAmbiguous,
			"local_underlay_ambiguous", "multiple local interfaces", ""},
		{"unverified inventory", linux.ErrOutputLimit,
			"local_underlay_capture_limited", "capture limit", ""},
		{"ipsec bounded capture", ipsecbackend.ErrBoundedOutput,
			"local_underlay_capture_limited", "capture limit", ""},
		{"interrupted", errors.Join(context.Canceled, linux.ErrUnderlayLocalNotAssigned),
			"operation_cancelled_before_apply", "canceled", ""},
		{"credential staged", linux.ErrUnderlayLocalNotAssigned,
			"local_underlay_unverified", "protected key write was also attempted", "attempted"},
	}
	for _, selected := range backends {
		for _, tc := range cases {
			t.Run(string(selected.kind)+"/"+tc.name, func(t *testing.T) {
				secret := errors.New("PRIVATE_UNDERLAY_ERROR_DO_NOT_PRINT")
				observed := stlerr.LocalUnderlayUnverified("test_plan", "lnk_11111111111111111111111111111111",
					string(selected.kind), errors.Join(tc.cause, secret))
				evidence := &stlerr.OperationEvidence{Stage: selected.stage, HostMutation: "not_attempted",
					DesiredState: "no_commit_attempted", Rollback: "not_required",
					CredentialProvision: tc.credential}
				var out, errOut bytes.Buffer
				exit := lifecycleFailureWithEvidence(&out, &errOut, true, stlerr.CodePlan, "link_import",
					nil, "Link import did not finish", evidence, observed)
				var result lifecycleFailureResponse
				if exit == 0 || json.Unmarshal(out.Bytes(), &result) != nil || result.Error == nil ||
					result.Error.ReasonCode != tc.reason || result.Error.Backend != string(selected.kind) ||
					!strings.Contains(result.Error.NextStep, tc.step) || errOut.Len() > 0 ||
					strings.Contains(out.String(), "PRIVATE_UNDERLAY_ERROR_DO_NOT_PRINT") ||
					result.Error.Evidence == nil || result.Error.Evidence.HostMutation != "not_attempted" {
					t.Fatalf("missing shared actionable redacted classification: backend=%s exit=%d out=%s err=%s",
						selected.kind, exit, out.String(), errOut.String())
				}
			})
		}
	}
}

// A real OperationalBackend.Apply can fail during createDevice's final
// inventory recheck after prepared XFRM/PSK journal publication. Its typed
// error must retain a precise versioned reason WITHOUT claiming Apply was
// never entered; the actual backend dispatch is tested in ipsec package.
func TestIPsecPostApplyXFRMRecheckPreservesRecoveryEvidenceAndReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cause  error
		reason string
	}{
		{"cancelled", context.Canceled, "ipsec_xfrm_underlay_cancelled"},
		{"timeout", context.DeadlineExceeded, "ipsec_xfrm_underlay_timed_out"},
		{"capture", ipsecbackend.ErrBoundedOutput, "ipsec_xfrm_underlay_capture_limited"},
		{"missing", linux.ErrUnderlayLocalNotAssigned, "ipsec_xfrm_underlay_not_assigned"},
		{"ambiguous", linux.ErrUnderlayLocalAmbiguous, "ipsec_xfrm_underlay_ambiguous"},
		{"invalid readback", errors.New("PRIVATE_IPSEC_UNVERIFIED_DETAIL"), "ipsec_xfrm_underlay_unverified"},
	} {
		for _, encap := range []domain.Encapsulation{domain.EncapESP, domain.EncapNATT} {
			t.Run(string(encap)+"/"+tc.name, func(t *testing.T) {
				id := "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				cause := fmt.Errorf("%w: %w", ipsecbackend.ErrCreateDeviceUnderlayRecheck, tc.cause)
				observed := stlerr.Wrap(stlerr.CodeApply, "ensure", id, string(domain.BackendIPsec),
					"backend apply failed; protected recovery may be required", cause)
				evidence := &stlerr.OperationEvidence{Stage: "apply", HostMutation: "attempted",
					DesiredState: "no_commit_attempted", Rollback: "unavailable"}
				var out, errOut bytes.Buffer
				rc := lifecycleFailureWithEvidence(&out, &errOut, true, stlerr.CodeApply, "link_import",
					nil, "IPsec activation failed or is uncertain; reconcile staged intent", evidence, observed)
				var response lifecycleFailureResponse
				if rc == 0 || errOut.Len() != 0 || json.Unmarshal(out.Bytes(), &response) != nil ||
					response.Error == nil || response.Error.ReasonCode != tc.reason ||
					response.Error.Evidence == nil || response.Error.Evidence.Stage != "apply" ||
					response.Error.Evidence.HostMutation != "attempted" ||
					response.Error.Evidence.Rollback != "unavailable" ||
					!strings.Contains(response.Error.NextStep, "IPsec Apply was entered") ||
					!strings.Contains(response.Error.NextStep, "XFRM/VICI journals") ||
					strings.Contains(out.String(), "PRIVATE_IPSEC_UNVERIFIED_DETAIL") ||
					strings.Contains(out.String(), "No backend Apply was attempted") {
					t.Fatalf("post-Apply IPsec diagnostic lost safety or typed cause: rc=%d out=%s err=%s", rc, out.String(), errOut.String())
				}
			})
		}
	}
	// Unsafe rollback cannot be masked by a more convenient address error.
	id := "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cause := fmt.Errorf("%w: %w", ipsecbackend.ErrCreateDeviceUnderlayRecheck, linux.ErrUnderlayLocalNotAssigned)
	observed := stlerr.Wrap(stlerr.CodeRollback, "ensure", id, "ipsec", "failed", cause)
	var out, errOut bytes.Buffer
	_ = lifecycleFailureWithEvidence(&out, &errOut, true, stlerr.CodeRollback, "link_import", nil,
		"operation remains uncertain", &stlerr.OperationEvidence{Stage: "apply", HostMutation: "attempted",
			DesiredState: "no_commit_attempted", Rollback: "incomplete"}, observed)
	var response lifecycleFailureResponse
	if json.Unmarshal(out.Bytes(), &response) != nil || response.Error == nil ||
		response.Error.ReasonCode != "rollback_incomplete" {
		t.Fatalf("unverified rollback masked by a local binding diagnosis: %s", out.String())
	}
}
