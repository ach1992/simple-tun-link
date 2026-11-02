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
		{"overflow", linux.ErrOutputLimit, "local_underlay_unverified", "local_underlay_unverified"},
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
