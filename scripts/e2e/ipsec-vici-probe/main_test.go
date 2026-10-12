package main

import (
	"os"
	"strings"
	"testing"
)

func TestEffectfulLabProbeRefusesUnapprovedExecution(t *testing.T) {
	before := os.Args
	t.Cleanup(func() { os.Args = before })
	os.Args = []string{"stl-ipsec-probe", "load", "/run/stl-ipsec-proof/a.vici", "a", "esp", "a"}
	t.Setenv("STL_E2E_DISPOSABLE_HOST", "")
	t.Setenv("STL_IPSEC_ISOLATED", "approved")
	if err := run(); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("unapproved VICI writer must refuse without contacting daemon: %v", err)
	}
	t.Setenv("STL_E2E_DISPOSABLE_HOST", "approved")
	t.Setenv("STL_IPSEC_ISOLATED", "")
	if err := run(); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("missing isolated-fixture permission must refuse: %v", err)
	}
}

func TestEffectfulLabProbeRejectsArbitraryEndpoint(t *testing.T) {
	before := os.Args
	t.Cleanup(func() { os.Args = before })
	t.Setenv("STL_E2E_DISPOSABLE_HOST", "approved")
	t.Setenv("STL_IPSEC_ISOLATED", "approved")
	os.Args = []string{"stl-ipsec-probe", "load", "/run/charon.vici", "a", "esp", "a"}
	if err := run(); err == nil {
		t.Fatal("foreign VICI socket must never become a writable lab endpoint")
	}
}
