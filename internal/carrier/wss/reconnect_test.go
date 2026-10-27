package wss

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func restartWSSLink(role string) domain.Link {
	link := wssTestLink()
	link.Backend = domain.BackendWireGuardWSS
	link.WSS = domain.WSSOptions{Role: role, TCPPort: 59443}
	if role == "dial" {
		link.WSS.ForwardUDPPort = 53001
	}
	return link
}

// Mirrors the exact systemctl show command shape on systemd 249 and 259.
// Runtime timestamps/status are not authority; argv and full flags are.
func wssRestartReadback(cmd Command, extended bool) string {
	policy := "ignore_errors=yes"
	if extended {
		policy = "flags=ignore-failure"
	}
	return fmt.Sprintf("{ path=%s ; argv[]=%s %s ; %s ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		cmd.Binary, cmd.Binary, strings.Join(cmd.Args, " "), policy)
}

func TestWSSRestartProbeIsDeadlineBoundedKernelWGTrafficNotLinkMutation(t *testing.T) {
	dial := restartWSSLink("dial")
	cmd, err := dialRestartProbe(dial)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-q", "-n", "-I", "stlwg0123456789", "-s", "8", "-c", "8", "-i", "0.25", "-W", "1", "-w", "3", "10.99.1.2"}
	if cmd.Binary != "/usr/bin/ping" || strings.Join(cmd.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected WSS managed warmup command: %s %q", cmd.Binary, cmd.Args)
	}
	canonical, err := wireguard.InterfaceName(dial.ID)
	if err != nil || canonical != cmd.Args[3] {
		t.Fatalf("restart interface diverges from managed WireGuard interface: got=%q want=%q, %v", cmd.Args[3], canonical, err)
	}
	property, err := (Host{}).restartProbeProperty(dial)
	if err != nil || property != "--property=ExecStartPost=-/usr/bin/ping "+strings.Join(want, " ") {
		t.Fatalf("wrong best-effort systemd startup property: %q, %v", property, err)
	}
	listener := restartWSSLink("listen")
	probe, err := (Host{}).restartProbeProperty(listener)
	if err != nil || probe != "" {
		t.Fatalf("listener must have no synthetic dial probe: %q, %v", probe, err)
	}
}

func TestWSSRestartProbeReadbackRejectsHiddenFlagsAndMalformedPairs(t *testing.T) {
	dial := restartWSSLink("dial")
	cmd, err := dialRestartProbe(dial)
	if err != nil {
		t.Fatal(err)
	}
	legacy := wssRestartReadback(cmd, false)
	extended := wssRestartReadback(cmd, true)
	if err := verifyWSSRestartProbe(legacy, extended, dial); err != nil {
		t.Fatal(err)
	}
	if err := verifyWSSRestartProbe("", "", dial); err != nil {
		t.Fatalf("verified legacy helper denied: %v", err)
	}
	cases := map[string][2]string{
		"wrong-peer":            {strings.Replace(legacy, "10.99.1.2", "10.99.1.3", 1), extended},
		"wrong-deadline":        {legacy, strings.Replace(extended, "-w 3", "-w 60", 1)},
		"wrong-interface":       {strings.Replace(legacy, "stlwg0123456789", "eth0", 1), extended},
		"missing-ignore":        {strings.Replace(legacy, "ignore_errors=yes", "ignore_errors=no", 1), extended},
		"missing-extended":      {legacy, ""},
		"missing-legacy":        {"", extended},
		"wrong-extended-flags":  {legacy, strings.Replace(extended, "flags=ignore-failure", "flags=", 1)},
		"fully-privileged":      {legacy, strings.Replace(extended, "flags=ignore-failure", "flags=ignore-failure fully-privileged", 1)},
		"no-env-expand":         {legacy, strings.Replace(extended, "flags=ignore-failure", "flags=ignore-failure no-env-expand", 1)},
		"no-setuid":             {legacy, strings.Replace(extended, "flags=ignore-failure", "flags=ignore-failure no-setuid", 1)},
		"via-shell":             {legacy, strings.Replace(extended, "flags=ignore-failure", "flags=ignore-failure via-shell", 1)},
		"duplicate-flag":        {legacy, strings.Replace(extended, "flags=ignore-failure", "flags=ignore-failure ignore-failure", 1)},
		"extra-unknown-flag":    {legacy, strings.Replace(extended, "flags=ignore-failure", "flags=ignore-failure argv0", 1)},
		"missing-flags-field":   {legacy, strings.Replace(extended, "flags=ignore-failure ; ", "", 1)},
		"duplicate-flags-field": {legacy, strings.Replace(extended, "flags=ignore-failure ;", "flags=ignore-failure ; flags=ignore-failure ;", 1)},
		"second-command":        {legacy, extended + " " + extended},
		"truncated-extended":    {legacy, strings.TrimSuffix(extended, " }")},
		"status-omitted":        {legacy, strings.Replace(extended, " ; status=0/0", "", 1)},
		"unknown-extra-field":   {legacy, strings.Replace(extended, " ; status=0/0", " ; unsupported=1 ; status=0/0", 1)},
		"foreign-post":          {"{ path=/bin/sh ; argv[]=/bin/sh -c true ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }", extended},
	}
	for label, input := range cases {
		t.Run(label, func(t *testing.T) {
			if err := verifyWSSRestartProbe(input[0], input[1], dial); err == nil {
				t.Fatal("accepted incomplete, contradictory or untrusted post-start execution")
			}
		})
	}
	if err := verifyWSSRestartProbe(legacy, extended, restartWSSLink("listen")); err == nil {
		t.Fatal("listener adopted a dial-only startup action")
	}
}
