package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

func TestRestoreGuidanceTraversesOnlyPublicValidatedLinkErrors(t *testing.T) {
	id := domain.LinkID("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	nested := stlerr.WithEvidence(stlerr.Wrap(stlerr.CodeInspect, "restore", string(id),
		"gre", "safe error", errors.New("PSK=NEVER_PRINT")),
		stlerr.OperationEvidence{Stage: "inspect", HostMutation: "not_attempted",
			DesiredState: "no_commit_attempted", Rollback: "not_required"})
	root := stlerr.Wrap(stlerr.CodeState, "restore_all", "", "", "restore failed",
		errors.Join(nested, errors.New("secret=UNTRUSTED")))
	items := restoreFailureSummaries(root)
	if len(items) != 1 || items[0].LinkID != id || items[0].Reason != "observation_unverified" ||
		items[0].Evidence == nil || items[0].Evidence.Stage != "inspect" ||
		strings.Contains(items[0].NextStep, "NEVER_PRINT") {
		t.Fatalf("unsafe or incomplete restore issue summary: %+v", items)
	}
}

func TestRestoreCLIProvidesPerLinkRecoveryWithoutMaskingSuccessfulSibling(t *testing.T) {
	root := t.TempDir()
	a := restoreTestLink(t, "1", domain.BackendGRE, "10.80.202.0/31", "10.80.202.1/31")
	b := restoreTestLink(t, "2", domain.BackendIPIP, "10.80.203.0/31", "10.80.203.1/31")
	seedRestoreState(t, root, a, b)
	working := newLifecycleFake()
	var stdout, stderr bytes.Buffer
	code := restoreWithContext(context.Background(), runtimeOptions{stateRoot: root,
		backends: []backend.Backend{working}}, &stdout, &stderr)
	if code != 1 || len(working.applies) != 1 || working.applies[0] != a.ID ||
		!strings.Contains(stderr.String(), "restore failed after 1 link(s)") ||
		!strings.Contains(stderr.String(), string(b.ID)) ||
		!strings.Contains(stderr.String(), "host_mutation=not_attempted") ||
		!strings.Contains(stderr.String(), "reason=capability_unavailable") ||
		strings.Contains(stderr.String(), string(a.ID)) || strings.Contains(stderr.String(), "PSK=") {
		t.Fatalf("restore recovery failed to preserve sibling and redact: code=%d stdout=%q stderr=%q applies=%v",
			code, stdout.String(), stderr.String(), working.applies)
	}
}
