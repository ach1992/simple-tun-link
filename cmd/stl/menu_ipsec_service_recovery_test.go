package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	ipsecbackend "github.com/ach1992/simple-tun-link/internal/backend/ipsec"
)

func TestIPsecExistingVerifiedServiceRequiresSeparateExactConsent(t *testing.T) {
	plan := ipsecbackend.VendorServiceStopPlan{Unit: "strongswan.service", Active: "active", Enabled: "enabled"}
	for _, tc := range []struct {
		name       string
		answer     string
		readiness  error
		stopError  error
		willStop   bool
		expectOK   bool
		packagesOK bool
	}{
		{"exact separate consent", "STOP strongswan.service\n", nil, nil, true, true, true},
		{"cancel", "\n", nil, nil, false, false, true},
		{"wrong service", "STOP ipsec.service\n", nil, nil, false, false, true},
		{"generic PREPARE not stop", "PREPARE\n", nil, nil, false, false, true},
		{"case sensitive", "stop strongswan.service\n", nil, nil, false, false, true},
		{"requires complete package inventory", "STOP strongswan.service\n", nil, nil, false, false, false},
		{"post-stop not admitted", "STOP strongswan.service\n", errors.New("other conflicting unit"), nil, true, false, true},
		{"stop failure, effects uncertain", "STOP strongswan.service\n", nil, errors.New("partial service transition"), true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.NewReader(tc.answer)
			var out bytes.Buffer
			calls := 0
			reads := 0
			ops := menuIPsecVendorOps{
				inspect: func(context.Context) (ipsecbackend.VendorServiceStopPlan, error) { return plan, nil },
				stop: func(_ context.Context, got ipsecbackend.VendorServiceStopPlan) error {
					calls++
					if got != plan {
						t.Fatalf("stale/different vendor unit: got=%+v want=%+v", got, plan)
					}
					return tc.stopError
				},
				readiness: func(context.Context) error { reads++; return tc.readiness },
			}
			ready := menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, tc.packagesOK, errors.New("vendor strongSwan service enabled or ambiguous"), ops)
			if ready != tc.expectOK || (calls == 1) != tc.willStop ||
				(reads == 1) != (tc.willStop && tc.stopError == nil) {
				t.Fatalf("unexpected owner action: ready=%t stops=%d reads=%d output=%s", ready, calls, reads, out.String())
			}
			if tc.willStop && (!strings.Contains(out.String(), "immediately disconnect") ||
				!strings.Contains(out.String(), "persists after reboot")) {
				t.Fatalf("service interruption and persistence warning lost: %s", out.String())
			}
		})
	}
}

func TestIPsecExistingServiceManualRecheckAndUnknownRemainReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inspectErr error
		answer     string
		readyErr   error
		wantOK     bool
		wantReads  int
	}{
		{"manual recheck succeeded", errors.New("foreign unit"), "RECHECK\n", nil, true, 1},
		{"manual recheck still fails", errors.New("foreign unit"), "RECHECK\n", errors.New("cannot prove ownership"), false, 1},
		{"unknown unit cannot be auto-stopped", errors.New("unknown unit"), "STOP strongswan.service\n", nil, false, 0},
		{"unknown unit cancellation", errors.New("unknown unit"), "\n", nil, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.NewReader(tc.answer)
			var out bytes.Buffer
			count := 0
			ops := menuIPsecVendorOps{
				inspect: func(context.Context) (ipsecbackend.VendorServiceStopPlan, error) {
					return ipsecbackend.VendorServiceStopPlan{}, tc.inspectErr
				},
				stop: func(context.Context, ipsecbackend.VendorServiceStopPlan) error {
					t.Fatal("foreign/unverified service was modified")
					return nil
				},
				readiness: func(context.Context) error { count++; return tc.readyErr },
			}
			ok := menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, true, errors.New("native systemd loaded identity unavailable or occupied"), ops)
			if ok != tc.wantOK || count != tc.wantReads ||
				!strings.Contains(out.String(), "manual") && tc.inspectErr != nil {
				t.Fatalf("unsafe or unhelpful manual path: ok=%t reads=%d out=%s", ok, count, out.String())
			}
		})
	}
}

func TestIPsecRecoveryRejectsMissingOperationSeam(t *testing.T) {
	in := strings.NewReader("STOP strongswan.service\n")
	var out bytes.Buffer
	if menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, true, errors.New("native systemd loaded identity unavailable or occupied"),
		menuIPsecVendorOps{inspect: func(context.Context) (ipsecbackend.VendorServiceStopPlan, error) {
			return ipsecbackend.VendorServiceStopPlan{}, nil
		}, stop: func(context.Context, ipsecbackend.VendorServiceStopPlan) error { return nil },
			readiness: nil}) {
		t.Fatal("missing safe post-action readiness should never grant admission")
	}
	var _ io.Reader = in
}

func TestIPsecAlreadyStoppedVendorDoesNotSuggestRepeatedStopOrHideActualBlocker(t *testing.T) {
	in := strings.NewReader("RECHECK\n")
	var out bytes.Buffer
	stopCalls, probes := 0, 0
	ops := menuIPsecVendorOps{
		inspect: func(context.Context) (ipsecbackend.VendorServiceStopPlan, error) {
			return ipsecbackend.VendorServiceStopPlan{}, errors.New("vendor service is already stopped and disabled")
		},
		stop: func(context.Context, ipsecbackend.VendorServiceStopPlan) error {
			stopCalls++
			return errors.New("service transition must not occur")
		},
		readiness: func(context.Context) error {
			probes++
			return errors.New("vendor strongSwan service enabled or ambiguous")
		},
	}
	ready := menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, true,
		errors.New("native systemd loaded identity unavailable or occupied"), ops)
	rendered := out.String()
	if ready || stopCalls != 0 || probes != 1 {
		t.Fatalf("stopped service was inappropriately adopted or not rechecked: ready=%t stops=%d probes=%d", ready, stopCalls, probes)
	}
	for _, term := range []string{
		"Already inactive and disabled; no STOP is needed",
		"ipsec_provisioning_private_unit_conflict",
		"ipsec_provisioning_vendor_enablement_unverified",
		"stl doctor ipsec --json",
		"no service was changed",
	} {
		if !strings.Contains(rendered, term) {
			t.Fatalf("missing actionable independent cause %q: %s", term, rendered)
		}
	}
	if strings.Contains(rendered, "stop/disable it manually") ||
		strings.Contains(rendered, "STOP/DISABLE affects this EXISTING") {
		t.Fatalf("healthy already-disabled service received disruptive STOP advice: %s", rendered)
	}
}

func TestIPsecUnknownReadinessErrorNeverLeaksSensitiveOutput(t *testing.T) {
	probe := ipsecReadinessCheck(errors.New("PSK=DO_NOT_EXPOSE localhost command transcript"))
	if probe.Status != "blocked" || probe.ReasonCode != "ipsec_provisioning_unverified" ||
		strings.Contains(probe.Summary+probe.NextStep, "DO_NOT_EXPOSE") {
		t.Fatalf("untrusted readiness error leaked or was promoted to ready: %+v", probe)
	}
	ready := ipsecReadinessCheck(nil)
	if ready.Status != "observed" || ready.ReasonCode != "ipsec_provisioning_prerequisites_verified" ||
		strings.Contains(ready.Summary, "activated") {
		t.Fatalf("preflight success claimed service activation: %+v", ready)
	}
}

func TestIPsecIncompleteInitialPackagePlanSkipsUnusableVendorSurvey(t *testing.T) {
	in := strings.NewReader("RECHECK\n")
	var out bytes.Buffer
	inspections, changes, reads := 0, 0, 0
	ops := menuIPsecVendorOps{
		inspect: func(context.Context) (ipsecbackend.VendorServiceStopPlan, error) {
			inspections++
			return ipsecbackend.VendorServiceStopPlan{Unit: "strongswan.service", Active: "active", Enabled: "enabled"}, nil
		},
		stop: func(context.Context, ipsecbackend.VendorServiceStopPlan) error {
			changes++
			return nil
		},
		readiness: func(context.Context) error {
			reads++
			return errors.New("root-owned strongSwan executable not verified")
		},
	}
	ok := menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, false,
		errors.New("root-owned strongSwan executable not verified"), ops)
	if ok || inspections != 0 || changes != 0 || reads != 1 ||
		!strings.Contains(out.String(), "Some packages were missing at the START") ||
		!strings.Contains(out.String(), "ipsec_provisioning_executable_unverified") {
		t.Fatalf("incomplete initial package plan conducted unusable vendor survey or hid cause: ok=%v inspect=%d stop=%d read=%d out=%s", ok, inspections, changes, reads, out.String())
	}
}

func TestIPsecDoctorPreflightClarifiesVendorFileVersusCurrentReadiness(t *testing.T) {
	cases := []struct{ reason, wantCode string }{
		{"vendor strongSwan service active or ambiguous", "ipsec_provisioning_vendor_activity_unverified"},
		{"vendor strongSwan service enabled or ambiguous", "ipsec_provisioning_vendor_enablement_unverified"},
		{"native systemd loaded identity unavailable or occupied", "ipsec_provisioning_private_unit_conflict"},
		{"private VICI socket already present or cannot be inspected", "ipsec_provisioning_vici_conflict"},
	}
	for _, tc := range cases {
		check := ipsecReadinessCheck(errors.New(tc.reason))
		if check.Name != "provisioning_readiness" || check.Status != "blocked" ||
			check.ReasonCode != tc.wantCode || check.NextStep == "" {
			t.Fatalf("preflight must publish a safe actionable stable reason: %+v", check)
		}
	}
}
