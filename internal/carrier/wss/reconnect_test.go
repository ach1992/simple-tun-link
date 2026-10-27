package wss

import (
	"strings"
	"testing"

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

func TestWSSRestartProbeIsBoundedKernelWGTrafficNotLinkMutation(t *testing.T) {
	dial := restartWSSLink("dial")
	cmd, err := dialRestartProbe(dial)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-q", "-n", "-I", "stlwg0123456789", "-s", "8", "-c", "8", "-i", "0.25", "-W", "1", "10.99.1.2"}
	if cmd.Binary != "/usr/bin/ping" || strings.Join(cmd.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected WSS managed warmup command: %s %q", cmd.Binary, cmd.Args)
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

func TestWSSRestartProbeReadbackRejectsForeignExecutionAndAdmitsExactLegacy(t *testing.T) {
	dial := restartWSSLink("dial")
	cmd, err := dialRestartProbe(dial)
	if err != nil {
		t.Fatal(err)
	}
	correct := "{ path=" + cmd.Binary + " ; argv[]=" + cmd.Binary + " " + strings.Join(cmd.Args, " ") + " ; ignore_errors=yes ; start_time=[n/a] ; }"
	if err := verifyWSSRestartProbe(correct, dial); err != nil {
		t.Fatal(err)
	}
	if err := verifyWSSRestartProbe("", dial); err != nil {
		t.Fatalf("verified legacy helper denied: %v", err)
	}
	for label, input := range map[string]string{
		"different-peer": strings.Replace(correct, "10.99.1.2", "10.99.1.3", 1),
		"changed-count":  strings.Replace(correct, "-c 8", "-c 100", 1),
		"changed-device": strings.Replace(correct, "stlwg0123456789", "eth0", 1),
		"missing-ignore": strings.Replace(correct, "ignore_errors=yes", "ignore_errors=no", 1),
		"second-command": correct + correct,
		"foreign":        "{ path=/bin/sh ; argv[]=/bin/sh -c true ; ignore_errors=yes ; }",
	} {
		t.Run(label, func(t *testing.T) {
			if err := verifyWSSRestartProbe(input, dial); err == nil {
				t.Fatal("accepted untrusted post-start execution")
			}
		})
	}
	if err := verifyWSSRestartProbe(correct, restartWSSLink("listen")); err == nil {
		t.Fatal("listener adopted a dial-only startup action")
	}
}
