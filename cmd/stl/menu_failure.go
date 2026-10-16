package main

import (
	"io"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Only real terminals receive the human-oriented failure page. Existing
// redirected stdout/stderr and schema-versioned JSON remain byte compatible.
// The error values are already canonical, reviewed, secret-safe fields; this
// renderer never unwraps OS/subprocess errors or displays arbitrary payloads.
func renderTerminalLifecycleFailure(out io.Writer, issue *stlerr.Error, evidence *stlerr.OperationEvidence) {
	menuSection(out, "Tunnel operation / incomplete")
	if evidence != nil && evidence.HostMutation == "not_attempted" {
		menuHealthLine(out, "Host changes", "INFO", "No backend network Apply was attempted")
	} else {
		menuHealthLine(out, "Host changes", "WARNING", "Outcome not fully confirmed; inspect before retrying")
	}
	if issue.Backend != "" {
		menuField(out, "Type", issue.Backend)
	}
	if evidence != nil {
		switch evidence.Stage {
		case "inspect":
			menuHealthLine(out, "Where stopped", "WARNING", "Checking local state/prerequisites (before Apply)")
		case "persistence":
			menuHealthLine(out, "Where stopped", "WARNING", "Reboot restoration / systemd ownership")
		case "preflight":
			menuHealthLine(out, "Where stopped", "WARNING", "Preparing the tunnel; not activated")
		default:
			menuField(out, "Where stopped", evidence.Stage)
		}
		if evidence.Rollback == "completed_unverified" || evidence.Rollback == "incomplete" {
			menuHealthLine(out, "Rollback", "WARNING", evidence.Rollback+" (verify existing state)")
		}
	}
	kind := "WARNING"
	if evidence == nil || evidence.HostMutation != "not_attempted" {
		kind = "FAILED" // attempted/uncertain host operations get the red status
	}
	switch issue.ReasonCode {
	case "rejected_before_host_apply":
		menuNotice(out, kind, "Prerequisite/ownership inspection did not pass; the exact cause is not yet verified.")
	case "kernel_module_not_loaded":
		menuNotice(out, kind, "A required kernel module was not loaded; nothing should be enabled automatically.")
	default:
		menuNotice(out, kind, issue.Detail)
	}
	menuSection(out, "Next step / no automatic retry")
	// Human guidance follows the actual terminal width. Exact commands and
	// any secret-safe copyable tokens remain unwrapped.
	menuProse(out, issue.NextStep)
	if issue.ReasonCode != "" {
		reference := issue.ReasonCode
		if evidence != nil && evidence.Stage != "" {
			reference = evidence.Stage + " / " + reference
		}
		if issue.Operation != "" {
			reference = issue.Operation + " / " + reference
		}
		menuField(out, "Reference", reference)
	}
}

// Wrap authored guidance without changing words or shell metacharacters.
// Never fold opaque stl:// URLs or secret-bearing data through this helper.
func wrapTerminalGuidance(value string, width int) string {
	words := strings.Fields(value)
	var b strings.Builder
	column := 0
	for _, word := range words {
		if column > 0 && column+len(word)+1 > width {
			b.WriteByte('\n')
			column = 0
		}
		if column != 0 {
			b.WriteByte(' ')
			column++
		}
		b.WriteString(word)
		column += len(word)
	}
	return b.String()
}
