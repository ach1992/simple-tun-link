package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestInstallerUninstallAndDowngradeErrorsArePreciseAndRedacted(t *testing.T) {
	for _, tc := range []struct{ name, action, raw, reason, next string }{
		{"downgrade blocked", "update", "stl installer [FAILED]: STL State/Link compatibility check blocked requested downgrade", "downgrade_state_incompatible", "My tunnels"},
		{"orphan cleanup", "uninstall", "stl installer [FAILED]: STL-owned orphan State locks could not be safely retired", "uninstall_orphan_cleanup_unverified", "Preserve them"},
		{"uninstall preflight", "uninstall", "stl installer [FAILED]: canonical uninstall preflight failed", "uninstall_preflight_unverified", "My tunnels"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var capture menuInstallerOutput
			_, stderr := capture.streams()
			_, _ = io.WriteString(stderr, tc.raw+": private-secret=VERY_SECRET_NOT_FOR_OUTPUT\n")
			var out bytes.Buffer
			capture.failure(&out, tc.action, errors.New("secret="+operatorSensitiveSentinel), context.Background())
			rendered := out.String()
			if !strings.Contains(rendered, tc.reason) || !strings.Contains(rendered, tc.next) ||
				strings.Contains(rendered, "VERY_SECRET_NOT_FOR_OUTPUT") ||
				strings.Contains(rendered, operatorSensitiveSentinel) {
				t.Fatalf("unsafe installer reason: %q", rendered)
			}
		})
	}
}
