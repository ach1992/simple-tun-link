package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/linux"
	"github.com/ach1992/simple-tun-link/internal/stlerr"
)

type ipsecCLIProbe struct {
	daemonPresent bool
	calls         []string
}

func (p *ipsecCLIProbe) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	p.calls = append(p.calls, key)
	switch {
	case key == "/usr/bin/pgrep -x charon" && p.daemonPresent:
		return linux.CommandResult{}, nil
	case strings.HasPrefix(key, "/usr/bin/pgrep -x "):
		return linux.CommandResult{}, &linux.CommandError{Command: "pgrep", ExitCode: 1}
	case key == "/usr/sbin/swanctl --help":
		return linux.CommandResult{}, errors.New("PSK=DO_NOT_PRINT")
	case key == "/sbin/ip -json -details link show type xfrm":
		return linux.CommandResult{}, nil
	default:
		t := "unanticipated read-only command " + name
		return linux.CommandResult{}, errors.New(t)
	}
}

func TestIPsecDoctorOperatorAndMachineDiagnostics(t *testing.T) {
	root := filepath.Join(t.TempDir(), "uncreated-state")
	probe := &ipsecCLIProbe{}
	opts := &runtimeOptions{stateRoot: root, probeRunner: probe}
	var stdout, stderr bytes.Buffer
	code := runWithRuntime([]string{"doctor", "ipsec", "--json"}, &stdout, &stderr, opts)
	if code != 4 || stderr.Len() != 0 {
		t.Fatalf("unexpected doctor exit: %d, stderr %q", code, stderr.String())
	}
	var report diagnostics.IPsecHostReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.ActivationAllowed || report.SchemaVersion != 1 || report.Backend != "ipsec" ||
		report.RuntimeMode != "native_exclusive" || len(report.Checks) != 7 {
		t.Fatalf("missing stable fail-closed diagnostic envelope: %+v", report)
	}
	if strings.Contains(stdout.String(), "DO_NOT_PRINT") || !strings.Contains(stdout.String(), "reason_code") {
		t.Fatalf("secret leak or missing stable reasons: %s", stdout.String())
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only doctor created a state directory: %v", err)
	}
	stdout.Reset()
	code = runWithRuntime([]string{"doctor", "ipsec"}, &stdout, &stderr, opts)
	if code != 4 || !strings.Contains(stdout.String(), "Next:") || !strings.Contains(stdout.String(), "NOT READY") {
		t.Fatalf("operator did not receive actionable failure: code %d output %q", code, stdout.String())
	}
	for _, call := range probe.calls {
		if strings.Contains(call, "load-") || strings.Contains(call, "systemctl") ||
			strings.Contains(call, "ip link add") || strings.Contains(call, "swanctl --load") {
			t.Fatalf("doctor used effectful command: %q", call)
		}
	}
}

func TestIPsecDoctorShowsExistingDaemonAndRejectsBadUsage(t *testing.T) {
	probe := &ipsecCLIProbe{daemonPresent: true}
	opts := &runtimeOptions{probeRunner: probe}
	var stdout, stderr bytes.Buffer
	if code := runWithRuntime([]string{"doctor", "ipsec", "--json"}, &stdout, &stderr, opts); code != 4 {
		t.Fatalf("existing daemon misreported success: %d", code)
	}
	var report diagnostics.IPsecHostReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) == 0 || report.Checks[0].ReasonCode != "charon_process_observed" ||
		report.Checks[0].Status != "blocked" || report.ActivationAllowed {
		t.Fatalf("existing daemon not protected: %+v", report)
	}
	stdout.Reset()
	if code := runWithRuntime([]string{"doctor", "wrong", "--json"}, &stdout, &stderr, opts); code != 2 {
		t.Fatalf("bad usage exit = %d", code)
	}
	var failure linkReadErrorResponse
	if err := json.Unmarshal(stdout.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.SchemaVersion != 1 || failure.Error == nil || failure.Error.Code != stlerr.CodeInvalid {
		t.Fatalf("unexpected error model: %+v", failure)
	}
}

// Existing stored IPsec intent must never be mistaken for an active Link.
// Both operator paths point to the same safe, non-mutating host doctor.
func TestIPsecLinkStatusAndDiagnoseGiveRecoveryPath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	link := fixtureReadLink("lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "10.80.90.0/31", "10.80.90.1/31", "ipsec")
	link.Encapsulation = "esp"
	storeReadLinks(t, root, link)
	for _, operation := range []string{"status", "diagnose"} {
		code, out, errOut := readCLI(t, root, nil, "link", operation, string(link.ID), "--json")
		if code != 4 || errOut != "" {
			t.Fatalf("unexpected unavailable IPsec command: %d %q %q", code, out, errOut)
		}
		var result linkReadErrorResponse
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.SchemaVersion != 1 || result.Error == nil ||
			result.Error.Code != stlerr.CodeUnsupported ||
			result.Error.Operation != "link_"+operation ||
			result.Error.Backend != "ipsec" || result.Error.ObjectID != string(link.ID) ||
			result.Error.ReasonCode != diagnostics.IPsecRuntimeNotRegisteredReason ||
			result.Error.NextStep != "stl doctor ipsec" ||
			!strings.Contains(result.Error.Detail, "stl doctor ipsec") {
			t.Fatalf("missing typed IPsec recovery contract: %+v", result)
		}
		for _, secret := range []string{"private_key=", "PSK=", "DO_NOT_EXPOSE_OR_LOG",
			"setup_link=", "swanctl --load", "raw_command"} {
			if strings.Contains(out, secret) {
				t.Fatalf("IPsec %s JSON leaked %q: %q", operation, secret, out)
			}
		}

		code, human, humanErr := readCLI(t, root, nil, "link", operation, string(link.ID))
		if code != 4 || human != "" || !strings.Contains(humanErr, "stl doctor ipsec") ||
			!strings.Contains(humanErr, "backend=ipsec") ||
			!strings.Contains(humanErr, string(link.ID)) ||
			strings.Contains(humanErr, "DO_NOT_EXPOSE_OR_LOG") {
			t.Fatalf("IPsec %s human guidance invalid: code=%d out=%q err=%q",
				operation, code, human, humanErr)
		}
	}

	// Existing generic error contracts must not grow empty recovery fields.
	code, other, otherErr := readCLI(t, root, nil, "link", "status", "lnk_invalid", "--json")
	if code != 2 || otherErr != "" || strings.Contains(other, "reason_code") ||
		strings.Contains(other, "next_step") {
		t.Fatalf("non-IPsec error changed schema semantics: code=%d out=%q err=%q", code, other, otherErr)
	}
}
