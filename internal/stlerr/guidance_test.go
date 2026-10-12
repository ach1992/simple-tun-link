package stlerr

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestGuidanceProvidesStableSecretSafeRecoveryAcrossFailureCategories(t *testing.T) {
	cases := map[Code]string{
		CodeInvalid: "invalid_request", CodeUnsupported: "capability_unavailable",
		CodeConflict: "resource_conflict", CodeInspect: "observation_unverified",
		CodePlan: "plan_unverified", CodeValidate: "validation_unverified",
		CodeApply: "apply_outcome_unverified", CodeVerify: "verification_unverified",
		CodeState: "state_unverified", CodeRollback: "rollback_incomplete",
		CodeInternal: "internal_error",
	}
	for code, want := range cases {
		t.Run(string(code), func(t *testing.T) {
			src := Wrap(code, "ensure", "", "", "operation uncertain", errors.New("PSK=NEVER_PRINT"))
			out := WithGuidance(src)
			if out.ReasonCode != want || out.NextStep == "" || out.Code != code || src.ReasonCode != "" ||
				!errors.Is(src, src.cause) || errors.Unwrap(out) != nil {
				t.Fatalf("unsafe/missing stable guidance %+v", out)
			}
			raw, err := json.Marshal(out)
			if err != nil || strings.Contains(string(raw), "NEVER_PRINT") {
				t.Fatalf("cause leaked through guidance: %v %s", err, raw)
			}
		})
	}
	custom := New(CodeUnsupported, "diagnose", "", "", "IPsec runtime is not available")
	custom.ReasonCode, custom.NextStep = "ipsec_runtime_not_registered", "Use an available backend"
	got := WithGuidance(custom)
	if got.ReasonCode != custom.ReasonCode || got.NextStep != custom.NextStep {
		t.Fatal("explicit domain-specific guidance overridden")
	}
	if WithGuidance(nil).ReasonCode != "internal_error" {
		t.Fatal("nil guidance not safe")
	}
}
