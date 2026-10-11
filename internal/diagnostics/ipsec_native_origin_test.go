package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
)

func TestNativeOriginDoctorNeverClaimsServiceOwnership(t *testing.T) {
	table := []struct {
		value          ipsec.NativeOriginAssessment
		status, reason string
	}{
		{ipsec.NativeOriginVerified, "observed", "native_config_origin_observed"},
		{ipsec.NativeOriginMissing, "blocked", "native_config_origin_not_provisioned"},
		{ipsec.NativeOriginConflict, "blocked", "native_config_origin_conflict"},
		{ipsec.NativeOriginUnverified, "unknown", "native_config_origin_unverified"},
		{ipsec.NativeOriginAssessment("PSK=NEVER_PRINT"), "unknown", "native_config_origin_unverified"},
	}
	for _, tt := range table {
		check := inspectNativeExclusiveConfigOrigin(func() ipsec.NativeOriginAssessment { return tt.value })
		if check.Name != "native_config_origin" || check.Status != tt.status || check.ReasonCode != tt.reason || check.NextStep == "" {
			t.Fatalf("unsafe origin classification: %+v", check)
		}
		data, err := json.Marshal(check)
		if err != nil || strings.Contains(string(data), "NEVER_PRINT") || strings.Contains(string(data), "/var/lib/") {
			t.Fatalf("untrusted diagnostic: %q, %v", data, err)
		}
		if tt.value == ipsec.NativeOriginVerified && !strings.Contains(check.Summary, "unverified") {
			t.Fatal("receipt claimed operational readiness")
		}
	}
	if got := inspectNativeExclusiveConfigOrigin(nil); got.Status != "unknown" {
		t.Fatalf("nil reader accepted: %+v", got)
	}
}
