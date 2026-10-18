package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

// The canonical installer and APT produce environment-specific diagnostic
// output (including repository URLs and source fragments). None of it may be
// forwarded to the menu. These independent, bounded sinks only extract fixed
// reason/stage identifiers; raw lines are never logged or retained.
type menuInstallerOutput struct {
	mu     sync.Mutex
	stage  string
	reason string
}

type menuInstallerOutputStream struct {
	owner    *menuInstallerOutput
	line     []byte
	oversize bool
}

func (v *menuInstallerOutput) streams() (io.Writer, io.Writer) {
	return &menuInstallerOutputStream{owner: v}, &menuInstallerOutputStream{owner: v}
}

func (s *menuInstallerOutputStream) Write(p []byte) (int, error) {
	s.owner.mu.Lock()
	defer s.owner.mu.Unlock()
	for _, b := range p {
		if b == '\n' || b == '\r' {
			if !s.oversize {
				s.owner.observeLine(string(s.line))
			}
			s.line = s.line[:0]
			s.oversize = false
			continue
		}
		if len(s.line) < 1024 {
			s.line = append(s.line, b)
		} else {
			s.oversize = true
		}
	}
	return len(p), nil
}

func (v *menuInstallerOutput) observeLine(line string) {
	switch {
	case strings.HasPrefix(line, "stl installer [FAILED]: partial failure; inspect retained recovery directory:"):
		v.stage, v.reason = "binary_recovery", "retained_recovery_requires_inspection"
	case strings.HasPrefix(line, "stl installer [FAILED]: STL ownership record is missing or not regular"):
		v.stage, v.reason = "installation_ownership", "installer_ownership_unverified"
	case strings.HasPrefix(line, "stl installer [FAILED]: APT package transaction failed"):
		v.stage, v.reason = "apt_package_transaction", "apt_transaction_incomplete"
	case strings.HasPrefix(line, "stl installer [FAILED]: APT index refresh failed"),
		strings.HasPrefix(line, "stl installer [FAILED]: APT lists lock remained busy"):
		v.stage, v.reason = "apt_index_refresh", "apt_index_unverified"
	case strings.HasPrefix(line, "stl installer [FAILED]: APT cannot resolve the complete selected dependency plan"),
		strings.HasPrefix(line, "stl installer [FAILED]: APT dependency plan changed"):
		v.stage, v.reason = "apt_dependency_plan", "apt_dependency_plan_unverified"
	case strings.HasPrefix(line, "stl installer [INFO]: Another APT process holds the lists lock"):
		// A later failure may be unrelated; this remains a reported stage,
		// never a claim that the lists lock was the sole cause.
		if v.reason == "" {
			v.stage = "apt_index_refresh"
		}
	case strings.HasPrefix(line, "[INFO] Installing verified missing packages on"):
		if v.reason == "" {
			v.stage = "apt_package_transaction"
		}
	}
}

// Only authored values leave this boundary. The child exit status is derived
// from the process, not from untrusted child text; stage is explicitly
// reported, not trusted proof of exactly which side effects occurred.
func (v *menuInstallerOutput) failure(out io.Writer, action string, err error, ctx context.Context) {
	v.mu.Lock()
	stage, reason := v.stage, v.reason
	v.mu.Unlock()
	if stage == "" {
		stage = "unverified"
	}
	if reason == "" {
		reason = "installer_execution_unverified"
	}
	status := "unknown"
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		status = fmt.Sprintf("%d", exit.ExitCode())
	}
	if ctx != nil && ctx.Err() != nil {
		reason = "installer_interrupted"
	}
	menuField(out, "Reported stage", stage)
	menuField(out, "Child exit code", status)
	menuField(out, "Reason", reason)
	if action == "prepare" {
		menuField(out, "NEXT ACTION", "Inspect dpkg --audit and installed selected packages; APT or vendor services may have changed. Reconcile before a NEW PREPARE.")
	} else {
		menuField(out, "NEXT ACTION", "Inspect stl version --json, installation ownership record and retained private recovery journal; package or binary changes may persist. Do not retry blindly.")
	}
}
