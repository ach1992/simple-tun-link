package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/ipsec"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Keep legacy doctor tests hermetic; current host UDP sockets are unrelated
// to their process/tool probes and must not affect unit-test outcomes.
func inspectIPsecDoctorFixture(ctx context.Context, runner linux.Runner) (IPsecHostReport, error) {
	files := map[string]string{
		"/proc/net/udp":  udpHeader + "0: 00000000:C350 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 0\n",
		"/proc/net/udp6": udp6Header + "0: 00000000000000000000000000000000:C350 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 0\n",
	}
	return inspectIPsecHostWithInputs(ctx, runner, ipsecInventoryReader(files, nil), func(string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}, func() ipsec.NativeConfigAssessment { return ipsec.NativeConfigMissing },
		func() ipsec.NativeOriginAssessment { return ipsec.NativeOriginMissing },
		func() ipsec.NativeServiceUnitAssessment { return ipsec.NativeServiceUnitMissing },
		func() ipsec.NativeOriginAssessment { return ipsec.NativeOriginMissing })
}

type ipsecDoctorRunner struct {
	overrides map[string]error
	calls     []string
}

func (r *ipsecDoctorRunner) Run(_ context.Context, name string, args ...string) (linux.CommandResult, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, key)
	if err, ok := r.overrides[key]; ok {
		return linux.CommandResult{Stdout: []byte("private_key=NEVER_SHOW"), Stderr: []byte("PSK=NEVER_SHOW")}, err
	}
	if name == "/usr/bin/pgrep" {
		return linux.CommandResult{}, &linux.CommandError{Command: name, ExitCode: 1}
	}
	return linux.CommandResult{}, nil
}

func checkByName(t *testing.T, report IPsecHostReport, name string) IPsecHostCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("missing check %s", name)
	return IPsecHostCheck{}
}

func TestIPsecDoctorReadOnlyAndNoFalseActivation(t *testing.T) {
	runner := &ipsecDoctorRunner{}
	report, err := inspectIPsecDoctorFixture(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Backend != "ipsec" || report.RuntimeMode != "native_exclusive" ||
		report.ActivationAllowed || len(report.Checks) != 10 {
		t.Fatalf("false operational claim: %+v", report)
	}
	if c := checkByName(t, report, "daemon_process"); c.ReasonCode != "charon_process_not_observed" ||
		c.Status != "observed" || !strings.Contains(c.Summary, "unverified") {
		t.Fatalf("missing ownership caution: %+v", c)
	}
	if c := checkByName(t, report, "strongswan_service"); c.Status != "observed" || c.ReasonCode != "strongswan_service_not_observed" {
		t.Fatalf("missing read-only service inventory: %+v", c)
	}
	if c := checkByName(t, report, "native_service_unit"); c.Status != "blocked" || c.ReasonCode != "native_service_unit_not_provisioned" {
		t.Fatalf("missing proposed native service unit prerequisite: %+v", c)
	}
	if c := checkByName(t, report, "native_service_unit_origin"); c.Status != "blocked" || c.ReasonCode != "native_service_unit_origin_not_provisioned" {
		t.Fatalf("missing unit-origin admission check: %+v", c)
	}
	if c := checkByName(t, report, "native_config"); c.Status != "blocked" || c.ReasonCode != "native_config_not_provisioned" {
		t.Fatalf("missing root-private config prerequisite: %+v", c)
	}
	if c := checkByName(t, report, "native_config_origin"); c.Status != "blocked" || c.ReasonCode != "native_config_origin_not_provisioned" {
		t.Fatalf("missing durable receipt prerequisite: %+v", c)
	}
	if c := checkByName(t, report, "operational_runtime"); c.ReasonCode != "ipsec_runtime_not_registered" ||
		c.Status != "blocked" || c.NextStep == "" {
		t.Fatalf("missing actionable blocked runtime: %+v", c)
	}
	wantCalls := []string{"/usr/bin/pgrep -x charon", "/usr/bin/pgrep -x charon-systemd",
		"/usr/sbin/swanctl --help", "/sbin/ip -json -details link show type xfrm"}
	if strings.Join(runner.calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("unexpected command calls (mutation risk): %q", runner.calls)
	}
}

func TestIPsecDoctorDetectsExistingDaemonWithoutTouchingIt(t *testing.T) {
	runner := &ipsecDoctorRunner{overrides: map[string]error{
		"/usr/bin/pgrep -x charon": nil,
	}}
	report, err := inspectIPsecDoctorFixture(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	c := checkByName(t, report, "daemon_process")
	if c.Status != "blocked" || c.ReasonCode != "charon_process_observed" ||
		report.ActivationAllowed || !strings.Contains(c.NextStep, "Do not stop") {
		t.Fatalf("foreign daemon not protected: %+v", report)
	}
}

func TestIPsecDoctorUnknownObservationsDoNotLeakOrBecomeVacant(t *testing.T) {
	runner := &ipsecDoctorRunner{overrides: map[string]error{
		"/usr/bin/pgrep -x charon":                    &linux.CommandError{Command: "pgrep", ExitCode: 2},
		"/usr/sbin/swanctl --help":                    errors.New("private_key=NEVER_SHOW"),
		"/sbin/ip -json -details link show type xfrm": errors.New("PSK=NEVER_SHOW"),
	}}
	report, err := inspectIPsecDoctorFixture(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"daemon_process", "strongswan_tool", "xfrm_inventory"} {
		if c := checkByName(t, report, name); c.Status != "unknown" || c.ReasonCode == "" || c.NextStep == "" {
			t.Fatalf("unsafe or unactionable unknown check: %+v", c)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "NEVER_SHOW") || strings.Contains(string(encoded), "private_key") ||
		report.ActivationAllowed {
		t.Fatalf("diagnostic leaked secrets or declared readiness: %s", encoded)
	}
}

func TestIPsecDoctorCanceledAndInvalidDependencies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspectIPsecDoctorFixture(ctx, &ipsecDoctorRunner{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation swallowed: %v", err)
	}
	if _, err := inspectIPsecDoctorFixture(context.Background(), nil); err == nil {
		t.Fatal("nil runner accepted")
	}
}
