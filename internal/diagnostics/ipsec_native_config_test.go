package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
)

func TestNativeConfigDoctorClassifiesOnlyVerifiedPrerequisites(t *testing.T) {
	tests := []struct {
		name       string
		assessment ipsec.NativeConfigAssessment
		wantStatus string
		wantReason string
	}{
		{"protected reviewed bytes", ipsec.NativeConfigExact, "observed", "native_config_bytes_verified"},
		{"not staged", ipsec.NativeConfigMissing, "blocked", "native_config_not_provisioned"},
		{"unsafe or changed", ipsec.NativeConfigConflict, "blocked", "native_config_untrusted"},
		{"permission or IO unknown", ipsec.NativeConfigUnverified, "unknown", "native_config_unverified"},
		{"unknown enum fails closed", ipsec.NativeConfigAssessment("PSK=DO_NOT_PRINT"), "unknown", "native_config_unverified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := inspectNativeExclusiveConfig(func() ipsec.NativeConfigAssessment { return tt.assessment })
			if check.Name != "native_config" || check.Status != tt.wantStatus ||
				check.ReasonCode != tt.wantReason || check.Summary == "" || check.NextStep == "" {
				t.Fatalf("unsafe native-config diagnostic: %+v", check)
			}
			raw, err := json.Marshal(check)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "DO_NOT_PRINT") ||
				strings.Contains(string(raw), "/var/lib/simple-tun-link") {
				t.Fatalf("diagnostic exposed untrusted content/path: %s", raw)
			}
			if tt.assessment == ipsec.NativeConfigExact && !strings.Contains(check.Summary, "unverified") {
				t.Fatal("byte match was misrepresented as operational attestation")
			}
		})
	}
	if got := inspectNativeExclusiveConfig(nil); got.Status != "unknown" ||
		got.ReasonCode != "native_config_unverified" {
		t.Fatalf("nil dependency was assumed vacant: %+v", got)
	}
}
