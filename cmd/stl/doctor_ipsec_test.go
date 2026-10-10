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
	case key == "pgrep -x charon" && p.daemonPresent:
		return linux.CommandResult{}, nil
	case strings.HasPrefix(key, "pgrep -x "):
		return linux.CommandResult{}, &linux.CommandError{Command: "pgrep", ExitCode: 1}
	case key == "swanctl --version":
		return linux.CommandResult{}, errors.New("PSK=DO_NOT_PRINT")
	case key == "ip -json -details link show type xfrm":
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
		report.RuntimeMode != "native_exclusive" || len(report.Checks) != 4 {
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
	for _, cmd := range [][]string{
		{"link", "status", string(link.ID), "--json"},
		{"link", "diagnose", string(link.ID), "--json"},
	} {
		code, out, errOut := readCLI(t, root, nil, cmd...)
		if code != 4 || errOut != "" {
			t.Fatalf("unexpected unavailable IPsec command: %d %q %q", code, out, errOut)
		}
		var result linkReadErrorResponse
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result.Error == nil || result.Error.Code != stlerr.CodeUnsupported ||
			!strings.Contains(result.Error.Detail, "stl doctor ipsec") ||
			strings.Contains(out, "private_key=") {
			t.Fatalf("missing safe IPsec operator guidance: %q", out)
		}
	}
}
