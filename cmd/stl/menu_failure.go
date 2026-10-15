package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

// Only real terminals receive the human-oriented failure page. Existing
// redirected stdout/stderr and schema-versioned JSON remain byte compatible.
// The error values are already canonical, reviewed, secret-safe fields; this
// renderer never unwraps OS/subprocess errors or displays arbitrary payloads.
func renderTerminalLifecycleFailure(out io.Writer, issue *stlerr.Error, evidence *stlerr.OperationEvidence) {
	menuSection(out, "Operation not completed")
	menuNotice(out, "FAILED", issue.Detail)
	if issue.Operation != "" {
		menuField(out, "Operation", issue.Operation)
	}
	if issue.Backend != "" {
		menuField(out, "Tunnel type", issue.Backend)
	}
	if issue.ReasonCode != "" {
		menuField(out, "Reason", issue.ReasonCode)
	}
	if evidence != nil {
		menuField(out, "Failed stage", evidence.Stage)
		status := evidence.Rollback
		if evidence.Rollback == "completed_unverified" || evidence.Rollback == "incomplete" {
			status += " (verify local state)"
		}
		menuField(out, "Rollback", status)
	}
	menuSection(out, "What to check next / read-only")
	fmt.Fprintln(out, wrapTerminalGuidance(issue.NextStep, 72))
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
