package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// A failure to inspect local owner resources must not send a Remove operator
// into Create-module preparation or route troubleshooting for an absent peer.
func TestRemoveGuidanceDoesNotRequireCreationOrRemoteConnectivity(t *testing.T) {
	id := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	proof := &stlerr.OperationEvidence{Stage: "inspect", HostMutation: "not_attempted", DesiredState: "no_commit_attempted", Rollback: "not_required"}
	for _, tc := range []struct{ name, reason string }{
		{"module unavailable", "kernel_module_not_loaded"},
		{"local owner unavailable", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := stlerr.New(stlerr.CodeInspect, "remove", string(id), "gre", "UNSAFE_DEBUG_PAYLOAD")
			observed.ReasonCode = tc.reason
			var stdout, stderr bytes.Buffer
			code := lifecycleFailureWithEvidence(&stdout, &stderr, true, stlerr.CodeInspect, "link_remove", nil,
				"Local owner inspection incomplete", proof, observed)
			var response lifecycleFailureResponse
			if code == 0 || json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error == nil || stderr.Len() != 0 {
				t.Fatalf("invalid JSON failure contract: %q", stdout.String())
			}
			step := response.Error.NextStep
			if step == "" || strings.Contains(step, "load it") || strings.Contains(step, "ip -4 route get") || strings.Contains(step, "UNSAFE_DEBUG_PAYLOAD") || !strings.Contains(step, "local") {
				t.Fatalf("Remove suggested Create-only recovery or leaked details: %s", step)
			}
			if response.Outcome != "unconfirmed" || !response.ReconciliationRequired || response.Error.Evidence.HostMutation != "not_attempted" {
				t.Fatal("unverified Remove reported success")
			}
		})
	}
}
