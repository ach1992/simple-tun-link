package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type greFailureAtPlan struct{ *lifecycleFakeBackend }

func (*greFailureAtPlan) Plan(_ context.Context, req backend.Request, _ backend.Observation) (backend.Plan, error) {
	issue := stlerr.Wrap(stlerr.CodePlan, "gre_plan", string(req.Link.ID), string(domain.BackendGRE),
		"selected local underlay does not match kernel route source",
		errors.New("private-key=VERY_SECRET_NOT_FOR_OUTPUT"))
	issue.ReasonCode = "gre_underlay_source_mismatch"
	issue.NextStep = "Inspect ip -4 route get PEER_IP on this receiver; correct local underlay before import."
	return nil, issue
}

func TestGREPlanRefusalMachineContractBeforeApply(t *testing.T) {
	root := filepath.Join(t.TempDir(), "never-committed")
	_, desired := makeLifecycleDesired(t, "f", "10.70.44.0/31")
	b := &greFailureAtPlan{newLifecycleFake()}
	var out, errOut bytes.Buffer
	code := runWithRuntimeInput([]string{"link", "ensure", "--stdin", "--json"},
		strings.NewReader(desired), &out, &errOut, &runtimeOptions{
			stateRoot: root, backends: []backend.Backend{b},
		})
	payload := assertCLIRecoveryFailure(t, code, out.String(), errOut.String(),
		"plan_failed", "plan", "not_attempted", "gre_underlay_source_mismatch")
	if !strings.Contains(payload.Error.NextStep, "ip -4 route get") ||
		len(b.applies) != 0 {
		t.Fatalf("GRE pre-Apply safety or guidance failed: %+v applies=%v", payload.Error, b.applies)
	}
	if _, err := os.Lstat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("failed GRE Plan committed State: %v", err)
	}
}
