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
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Test the real versioned CLI error projection, not backend prose: a failed
// local address inventory must not be reported as a remote-peer outage.
type unverifiedLocalIPv4Backend struct{ *lifecycleFakeBackend }

func (*unverifiedLocalIPv4Backend) Plan(_ context.Context, req backend.Request, _ backend.Observation) (backend.Plan, error) {
	return nil, stlerr.LocalUnderlayUnverified("gre_plan", string(req.Link.ID), string(req.Link.Backend), errors.New("SECRET_PRIVATE_PATH_DO_NOT_ECHO"))
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
