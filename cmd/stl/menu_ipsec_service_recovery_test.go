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
			ready := menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, tc.packagesOK, ops)
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
			ok := menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, true, ops)
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
	if menuResolveIPsecServiceConflictWithOps(in, bufio.NewReader(in), &out, true,
		menuIPsecVendorOps{inspect: func(context.Context) (ipsecbackend.VendorServiceStopPlan, error) {
			return ipsecbackend.VendorServiceStopPlan{}, nil
		}, stop: func(context.Context, ipsecbackend.VendorServiceStopPlan) error { return nil },
			readiness: nil}) {
		t.Fatal("missing safe post-action readiness should never grant admission")
	}
	var _ io.Reader = in
}
