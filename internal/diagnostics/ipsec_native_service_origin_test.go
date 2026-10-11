package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
)

func TestNativeServiceOriginDoctorDoesNotGrantOperationalOwnership(t *testing.T) {
	for _, tc := range []struct {
		result ipsec.NativeOriginAssessment
		status string
		reason string
	}{
		{ipsec.NativeOriginVerified, "observed", "native_service_unit_origin_observed"},
		{ipsec.NativeOriginMissing, "blocked", "native_service_unit_origin_not_provisioned"},
		{ipsec.NativeOriginConflict, "blocked", "native_service_unit_origin_conflict"},
		{ipsec.NativeOriginUnverified, "unknown", "native_service_unit_origin_unverified"},
		{ipsec.NativeOriginAssessment("PSK=NEVER_PRINT"), "unknown", "native_service_unit_origin_unverified"},
	} {
		check := inspectNativeExclusiveServiceUnitOrigin(func() ipsec.NativeOriginAssessment { return tc.result })
		if check.Name != "native_service_unit_origin" || check.Status != tc.status || check.ReasonCode != tc.reason || check.NextStep == "" {
			t.Fatalf("unsafe service origin classification: %+v", check)
		}
		data, err := json.Marshal(check)
		if err != nil || strings.Contains(string(data), "NEVER_PRINT") || strings.Contains(string(data), "/etc/systemd/system/") ||
			strings.Contains(string(data), "/var/lib/") {
			t.Fatalf("untrusted service origin JSON: %s %v", data, err)
		}
		if tc.result == ipsec.NativeOriginVerified && !strings.Contains(check.Summary, "unverified") {
			t.Fatal("receipt was promoted to effective systemd ownership")
		}
	}
	if inspectNativeExclusiveServiceUnitOrigin(nil).Status != "unknown" {
		t.Fatal("nil reader accepted")
	}
}
