//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/diagnostics"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

func TestReviewerNoColorForbidsAllTerminalControl(t *testing.T) {
	t.Setenv("STL_NO_CLEAR", "0")
	t.Setenv("TERM", "xterm-256color")
	previous, had := os.LookupEnv("NO_COLOR")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("NO_COLOR", previous)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	})
	for _, tc := range []struct {
		name, term string
		color      bool
	}{
		{"NO_COLOR present even when empty", "xterm-256color", false},
		{"dumb terminal", "dumb", false},
		{"normal interactive", "xterm-256color", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			if tc.name == "NO_COLOR present even when empty" {
				t.Setenv("NO_COLOR", "")
			} else {
				_ = os.Unsetenv("NO_COLOR")
			}
			master, slave := openMenuPTY(t)
			menuScreen(slave, "Main")
			menuNotice(slave, "OK", "Screen rendered")
			got := readMenuPTYUntil(t, master, "MAIN", "Screen rendered")
			if strings.Contains(got, "\x1b") != tc.color {
				t.Fatalf("unexpected ANSI eligibility: %q", got)
			}
			if tc.color && !strings.Contains(got, "\x1b[2J\x1b[H") {
				t.Fatalf("normal TTY did not redraw visible screen: %q", got)
			}
		})
	}
	var redirected bytes.Buffer
	menuScreen(&redirected, "Main")
	if strings.Contains(redirected.String(), "\x1b") {
		t.Fatalf("redirected output included ANSI: %q", redirected.String())
	}
}

func TestReviewerNarrowCopyBlocksKeepCommandsIDsKeysAndURLs(t *testing.T) {
	id := "lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	link := fixtureReadLink(id, "10.20.30.0/31", "10.20.30.1/31", domain.BackendWireGuard)
	completeWireGuardFixture(t, &link, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32)))
	command := "stl link diagnose " + id
	url := "https://example.invalid/long/exact/operational/recovery/instructions"
	setup := "stl://receiver-test-payload-that-can-be-longer-than-any-terminal-width-should-never-be-hard-wrapped"
	for _, width := range []uint16{60, 80, 120} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			t.Setenv("NO_COLOR", "1")
			t.Setenv("TERM", "xterm-256color")
			master, slave := openMenuPTY(t)
			if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
				&unix.Winsize{Row: 30, Col: width}); err != nil {
				t.Fatal(err)
			}
			printManualConnectionDetails(slave, link)
			menuCopyLine(slave, "After peer import", command)
			menuCopyLine(slave, "Recovery link", url)
			menuCopyLine(slave, "Setup Link", setup)
			menuCopyLine(slave, "End", "COPY-END")
			got := readMenuPTYUntil(t, master, "COPY-END")
			for _, payload := range []string{string(link.ID), link.WireGuard.LocalPublicKey,
				link.WireGuard.PeerPublicKey, command, url, setup} {
				if !strings.Contains(got, "\r\n"+payload+"\r\n") {
					t.Fatalf("%d-column copy block transformed/split value %q: %q", width, payload, got)
				}
			}
			if strings.Contains(got, "\x1b") {
				t.Fatalf("%d-column NO_COLOR copied ANSI: %q", width, got)
			}
			if len(command) > int(width) || len(link.WireGuard.LocalPublicKey) > int(width) {
				t.Fatal("the command and WireGuard test key should fit the narrowest terminal")
			}
		})
	}
}

func TestReviewerDoctorGroupsStatusesAndOneAction(t *testing.T) {
	report := diagnostics.IPsecHostReport{SchemaVersion: 1, Backend: "ipsec", RuntimeMode: "native_exclusive",
		Checks: []diagnostics.IPsecHostCheck{
			{Name: "daemon_process", Status: "blocked", ReasonCode: "charon_process_observed"},
			{Name: "strongswan_service", Status: "blocked", ReasonCode: "strongswan_service_observed"},
			{Name: "opaque_probe", Status: "unknown", ReasonCode: "opaque_probe_unverified"},
			{Name: "operational_runtime", Status: "blocked", ReasonCode: diagnostics.IPsecRuntimeNotRegisteredReason},
			{Name: "xfrm_inventory", Status: "observed", ReasonCode: "xfrm_inventory_readable"},
		}}
	var out bytes.Buffer
	renderIPsecDoctorHuman(&out, report)
	body := out.String()
	for _, want := range []string{"NOT READY", "3 blocked / 1 unknown",
		"charon_process_observed", "opaque_probe_unverified",
		"Do not stop or adopt", "NEXT: ONE SAFE ACTION",
		"stl doctor ipsec --json"} {
		if !strings.Contains(body, want) {
			t.Fatalf("doctor missing useful status or action %q: %q", want, body)
		}
	}
	if strings.Count(body, "NEXT: ONE SAFE ACTION") != 1 ||
		strings.Contains(body, "No action for this observation") {
		t.Fatalf("doctor repeated per-check actions: %q", body)
	}
	report.Checks = []diagnostics.IPsecHostCheck{
		{Name: "daemon_process", Status: "unknown", ReasonCode: "charon_process_unverified"},
		{Name: "operational_runtime", Status: "blocked", ReasonCode: diagnostics.IPsecRuntimeNotRegisteredReason},
	}
	out.Reset()
	renderIPsecDoctorHuman(&out, report)
	if strings.Contains(out.String(), "Do not stop or adopt") ||
		!strings.Contains(out.String(), "Resolve incomplete read-only") {
		t.Fatalf("unknown wrongly reported as proven conflict: %q", out.String())
	}
	report.ActivationAllowed = true
	report.Checks = []diagnostics.IPsecHostCheck{{Name: "operational_runtime", Status: "observed"}}
	out.Reset()
	renderIPsecDoctorHuman(&out, report)
	if strings.Contains(out.String(), "NOT READY") ||
		!strings.Contains(out.String(), "VERIFIED") ||
		!strings.Contains(out.String(), "Link traffic still requires") {
		t.Fatalf("admitted runtime was overclaimed or hidden: %q", out.String())
	}
}

func TestReviewerDoctorAt60ColumnsIsReadableAndReadOnly(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	master, slave := openMenuPTY(t)
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 30, Col: 60}); err != nil {
		t.Fatal(err)
	}
	report := diagnostics.IPsecHostReport{Checks: []diagnostics.IPsecHostCheck{
		{Name: "daemon_process", Status: "blocked", ReasonCode: "charon_process_observed"},
		{Name: "operational_runtime", Status: "blocked", ReasonCode: diagnostics.IPsecRuntimeNotRegisteredReason},
		{Name: "native_config", Status: "unknown", ReasonCode: "native_config_origin_unverified"},
	}}
	renderIPsecDoctorHuman(slave, report)
	menuCopyLine(slave, "End", "DOCTOR-END")
	text := readMenuPTYUntil(t, master, "DOCTOR-END")
	if strings.Contains(text, "\x1b") || !strings.Contains(text, "NOT READY") ||
		!strings.Contains(text, "NEXT: ONE SAFE ACTION") {
		t.Fatalf("noncompact/nonplaintext doctor: %q", text)
	}
	for _, line := range strings.Split(text, "\r\n") {
		if len(line) > 60 {
			t.Fatalf("doctor line exceeds 60 columns (%d): %q", len(line), line)
		}
	}
}

func TestReviewerDoctorDoesNotMistakeInstalledDisabledVendorForLiveConflict(t *testing.T) {
	report := diagnostics.IPsecHostReport{SchemaVersion: 1, Backend: "ipsec", RuntimeMode: "native_exclusive",
		Checks: []diagnostics.IPsecHostCheck{
			{Name: "strongswan_service", Status: "blocked", ReasonCode: "strongswan_service_observed",
				Summary: "A known vendor unit file exists; activity is unverified."},
			{Name: "operational_runtime", Status: "blocked", ReasonCode: diagnostics.IPsecRuntimeNotRegisteredReason},
			{Name: "provisioning_readiness", Status: "blocked", ReasonCode: "ipsec_provisioning_vendor_enablement_unverified",
				NextStep: "Inspect exact unit enablement; do not stop an inactive/disabled service."},
		}}
	var out bytes.Buffer
	renderIPsecDoctorHuman(&out, report)
	got := out.String()
	for _, want := range []string{"Native preflight", "ipsec_provisioning_vendor_enablement_unverified",
		"Inspect exact unit enablement", "NOT READY"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Doctor did not explain exact preflight cause %q: %s", want, got)
		}
	}
	if strings.Contains(got, "A conflicting or unowned process, service or IKE port was observed") {
		t.Fatalf("a service file alone was promoted to an active conflict: %s", got)
	}

	report.Checks[2] = diagnostics.IPsecHostCheck{Name: "provisioning_readiness",
		Status: "observed", ReasonCode: "ipsec_provisioning_prerequisites_verified"}
	out.Reset()
	renderIPsecDoctorHuman(&out, report)
	if !strings.Contains(out.String(), "Private provisioning prerequisites pass right now") ||
		strings.Contains(out.String(), "IPsec / runtime VERIFIED") {
		t.Fatalf("read-only provisioning proof incorrectly claimed an active or missing service: %s", out.String())
	}
}
