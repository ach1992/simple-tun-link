package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEndpointMTUPolicyValidationAndLegacyOmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy MTUPolicy
		valid  bool
	}{
		{"legacy_unmanaged", MTUPolicy{}, true},
		{"explicit_unmanaged", MTUPolicy{Mode: MTUUnmanagedExplicit}, true},
		{"auto", MTUPolicy{Mode: MTUAuto}, true},
		{"manual", MTUPolicy{Mode: MTUManual, Bytes: 1400}, true},
		{"unmanaged_bytes", MTUPolicy{Bytes: 1400}, false},
		{"auto_bytes", MTUPolicy{Mode: MTUAuto, Bytes: 1400}, false},
		{"manual_missing_bytes", MTUPolicy{Mode: MTUManual}, false},
		{"manual_out_of_range", MTUPolicy{Mode: MTUManual, Bytes: 65536}, false},
		{"unknown_mode", MTUPolicy{Mode: "remote_auto"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if (err == nil) != tc.valid {
				t.Fatalf("policy=%+v err=%v", tc.policy, err)
			}
		})
	}
	base := Link{MTU: MTUPolicy{}}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"mtu"`) {
		t.Fatal("legacy Link unexpectedly serialized managed policy")
	}
	managed := Link{MTU: MTUPolicy{Mode: MTUManual, Bytes: 1340}}
	raw, err = json.Marshal(managed)
	if err != nil {
		t.Fatal(err)
	}
	var again Link
	if err = json.Unmarshal(raw, &again); err != nil || again.MTU != managed.MTU {
		t.Fatalf("saved MTU policy not stable across JSON: %+v %v", again.MTU, err)
	}
}
