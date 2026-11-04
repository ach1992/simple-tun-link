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

// Both the read-only package preview and the post-consent operator report
// use this single allowlist of canonical installer FAILED messages. In
// particular, APT output and pre-transaction INFO do not establish that an
// apt-get install occurred. Only authored diagnostic identifiers are retained.
func canonicalAPTOperatorFailure(line string) (stage, reason string) {
	message, ok := strings.CutPrefix(line, "stl installer [FAILED]: ")
	if !ok {
		return "", ""
	}
	switch {
	case strings.HasPrefix(message, "APT_PACKAGE_INSTALL failed;"),
		strings.HasPrefix(message, "APT package transaction failed"),
		strings.HasPrefix(message, "selected package remains unavailable:"):
		return "apt_package_transaction", "apt_transaction_incomplete"
	case strings.HasPrefix(message, "APT_INDEX_REFRESH failed;"),
		strings.HasPrefix(message, "APT index refresh failed"),
		strings.HasPrefix(message, "APT lists lock remained busy"):
		return "apt_index_refresh", "apt_index_unverified"
	case strings.HasPrefix(message, "APT_DEPENDENCY_PLAN failed;"),
		strings.HasPrefix(message, "APT cannot resolve the complete selected dependency plan"),
		strings.HasPrefix(message, "APT dependency plan changed"),
		strings.HasPrefix(message, "APT plan changed since confirmation"),
		strings.HasPrefix(message, "APT preferred candidate differs from the consented version"),
		strings.HasPrefix(message, "no APT package index mapping available"),
		strings.HasPrefix(message, "APT plan would remove packages"),
		strings.HasPrefix(message, "APT plan would upgrade an installed package"),
		strings.HasPrefix(message, "APT returned an unrecognized install identity"),
		strings.HasPrefix(message, "APT returned an unrecognized candidate version"),
		strings.HasPrefix(message, "APT plan includes duplicate package identity"),
		strings.HasPrefix(message, "APT plan omitted a required selected package"),
		strings.HasPrefix(message, "APT plan is empty or exceeds safe preview limits"),
		strings.HasPrefix(message, "approved APT install plan is empty"):
		return "apt_dependency_plan", "apt_dependency_plan_unverified"
	case strings.HasPrefix(message, "APT candidate InRelease"),
		strings.HasPrefix(message, "APT sources explicitly bypass signature verification"),
		strings.HasPrefix(message, "APT selected a dependency outside the distribution archive"),
		strings.HasPrefix(message, "APT candidate includes a non-distribution package source"),
		strings.HasPrefix(message, "APT candidate package version has no verified distribution index"),
		strings.HasPrefix(message, "APT index-to-release inventory could not be inspected"),
		strings.HasPrefix(message, "APT candidate source maps to ambiguous release identities"),
		strings.HasPrefix(message, "APT candidate-to-index policy could not be read"),
		strings.HasPrefix(message, "APT source inventory could not be read"),
		strings.HasPrefix(message, "APT source inventory could not be inspected"),
		strings.HasPrefix(message, "official distribution archive signing keyring unavailable"),
		strings.HasPrefix(message, "official archive keyring package ownership unverified"),
		strings.HasPrefix(message, "distribution archive keyring package not fully installed"),
		strings.HasPrefix(message, "cannot verify distribution archive signatures"),
		strings.HasPrefix(message, "official Ubuntu archive metadata does not match the host"),
		strings.HasPrefix(message, "official Debian archive metadata does not match the host"):
		return "apt_source_trust", "apt_source_trust_unverified"
	default:
		return "", ""
	}
}

func (v *menuInstallerOutput) observeLine(line string) {
	// Informational APT lock waits and "Installing verified missing
	// packages" precede final verification and cannot establish the
	// failed stage or whether apt-get install actually began.
	if stage, reason := canonicalAPTOperatorFailure(line); reason != "" {
		v.stage, v.reason = stage, reason
		return
	}
	switch {
	case strings.HasPrefix(line, "stl installer [FAILED]: partial failure; inspect retained recovery directory:"):
		v.stage, v.reason = "binary_recovery", "retained_recovery_requires_inspection"
	case strings.HasPrefix(line, "stl installer [FAILED]: STL State/Link compatibility check blocked requested downgrade"):
		v.stage, v.reason = "state_compatibility", "downgrade_state_incompatible"
	case strings.HasPrefix(line, "stl installer [FAILED]: STL-owned orphan State locks could not be safely retired"):
		v.stage, v.reason = "orphan_state_cleanup", "uninstall_orphan_cleanup_unverified"
	case strings.HasPrefix(line, "stl installer [FAILED]: canonical uninstall preflight failed"):
		v.stage, v.reason = "uninstall_preflight", "uninstall_preflight_unverified"
	case strings.HasPrefix(line, "stl installer [FAILED]: STL ownership record is missing or not regular"):
		v.stage, v.reason = "installation_ownership", "installer_ownership_unverified"
	case strings.HasPrefix(line, "stl local install [FAILED]: wrong file for"),
		strings.HasPrefix(line, "stl local install [FAILED]: unsupported CPU architecture"):
		v.stage, v.reason = "local_architecture", "local_architecture_incompatible"
	case strings.HasPrefix(line, "stl local install [FAILED]: selected optional"),
		strings.HasPrefix(line, "stl local install [FAILED]: WSS selected"),
		strings.HasPrefix(line, "stl local install [FAILED]: QUIC selected"):
		v.stage, v.reason = "local_companion", "local_companion_unverified"
	case strings.HasPrefix(line, "stl local install [FAILED]: embedded archive SHA256 mismatch"),
		strings.HasPrefix(line, "stl local install [FAILED]: embedded bundle version or source commit mismatch"):
		v.stage, v.reason = "local_bundle", "local_bundle_unverified"
	case strings.HasPrefix(line, "stl local install [FAILED]: transferred file"),
		strings.HasPrefix(line, "stl local install [FAILED]: untrusted /root/stl"),
		strings.HasPrefix(line, "stl local install [FAILED]: local installer has an invalid"):
		v.stage, v.reason = "local_source", "local_source_untrusted"

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
	switch {
	case action == "prepare":
		menuField(out, "NEXT ACTION", "Inspect dpkg --audit and installed selected packages; APT or vendor services may have changed. Reconcile before a NEW PREPARE.")
	case reason == "downgrade_state_incompatible":
		menuField(out, "NEXT ACTION", "The target release cannot safely read existing STL State. Open My tunnels to remove verified Links and use STL recovery for pending operations; retry Downgrade only after STL proves an empty compatible State.")
	case reason == "uninstall_orphan_cleanup_unverified":
		menuField(out, "NEXT ACTION", "STL found leftover State contents it cannot prove are its own locks. Preserve them and inspect State ownership; do not delete arbitrary files to force Uninstall.")
	case reason == "uninstall_preflight_unverified":
		menuField(out, "NEXT ACTION", "Use My tunnels to remove verified Links, then inspect STL restore unit and State ownership in STL before retrying Uninstall.")
	case reason == "local_architecture_incompatible":
		menuField(out, "NEXT ACTION", "Download the exact official local installer matching uname -m and independently verify its full SHA256. Check installed ownership before retrying.")
	case reason == "local_companion_unverified":
		menuField(out, "NEXT ACTION", "Check the selected helper's official architecture and pinned SHA256, and inspect installed core/companion identity before retrying; Core might already be updated.")
	case reason == "local_bundle_unverified" || reason == "local_source_untrusted":
		menuField(out, "NEXT ACTION", "Re-transfer a verified official file into protected /root/stl (root-owned, mode 0700) and independently check SHA256; inspect any partial installation/recovery before retrying.")
	default:
		menuField(out, "NEXT ACTION", "Inspect stl version --json, installation ownership record and retained private recovery journal; package or binary changes may persist. Do not retry blindly.")
	}
}
