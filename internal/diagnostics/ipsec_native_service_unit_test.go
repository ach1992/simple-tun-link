package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
)

func TestNativeServiceUnitDiagnosticReasonAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		read   func() ipsec.NativeServiceUnitAssessment
		status string
		reason string
	}{
		{"exact is not effective ownership", func() ipsec.NativeServiceUnitAssessment { return ipsec.NativeServiceUnitExact }, "observed", "native_service_unit_bytes_verified"},
		{"missing is blocked", func() ipsec.NativeServiceUnitAssessment { return ipsec.NativeServiceUnitMissing }, "blocked", "native_service_unit_not_provisioned"},
		{"foreign is blocked", func() ipsec.NativeServiceUnitAssessment { return ipsec.NativeServiceUnitConflict }, "blocked", "native_service_unit_untrusted"},
		{"unknown remains unknown", func() ipsec.NativeServiceUnitAssessment { return ipsec.NativeServiceUnitUnverified }, "unknown", "native_service_unit_unverified"},
		{"nil is unknown", nil, "unknown", "native_service_unit_unverified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := inspectNativeExclusiveServiceUnit(tc.read)
			if check.Name != "native_service_unit" || check.Status != tc.status ||
				check.ReasonCode != tc.reason || check.NextStep == "" {
				t.Fatalf("unsafe diagnosis: %+v", check)
			}
			if tc.status == "observed" && !strings.Contains(check.Summary, "unverified") {
				t.Fatal("file bytes were confused with loaded/effective service ownership")
			}
			jsonData, err := json.Marshal(check)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private_key", "PSK=", "DO_NOT_PRINT", "/etc/systemd/system/"} {
				if strings.Contains(string(jsonData), secret) {
					t.Fatalf("sensitive or untrusted data in doctor: %s", jsonData)
				}
			}
		})
	}
}
