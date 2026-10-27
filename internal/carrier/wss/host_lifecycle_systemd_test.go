package wss

import (
	"os"
	"strings"
	"testing"
)

// The CI-only fixture is actual `systemctl show --property=...` output from
// a disposable GitHub-hosted transient service, not a reconstructed stub.
// Never use this test to inspect or alter a managed physical WSS Link.
func TestWSSDisposableSystemdUnitReadback(t *testing.T) {
	path := os.Getenv("STL_WSS_DISPOSABLE_UNIT_READBACK")
	if path == "" {
		t.Skip("requires an explicitly supplied disposable systemd fixture")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	values, err := parseWSSUnitReadback(raw)
	if err != nil {
		t.Fatalf("real systemd output rejected by production parser: %v", err)
	}
	if values["LoadState"] != "loaded" || values["ActiveState"] != "active" || values["Transient"] != "yes" {
		t.Fatalf("disposable service does not have the expected loaded state")
	}
	main := Command{Binary: "/usr/bin/sleep", Args: []string{"90"}}
	if !matchesExactWSSExecStart(values["ExecStart"], main) ||
		!matchesExactWSSCommandReadback(values["ExecStartEx"], main, "flags", "") {
		t.Fatal("production parser rejected authentic disposable main-command properties")
	}
	link := restartWSSLink("dial")
	if err := verifyWSSRestartProbe(values["ExecStartPost"], values["ExecStartPostEx"], link); err != nil {
		t.Fatalf("production post-start verifier rejected authentic systemd properties: %v", err)
	}
	if err := verifyWSSUnitSecurityProperties(values); err != nil {
		t.Fatalf("production security verifier rejected authentic disposable unit: %v", err)
	}
	if err := verifyWSSNoForeignExecHooks(values); err != nil {
		t.Fatalf("production lifecycle verifier rejected authentic no-extra-hook unit: %v", err)
	}
	// Corrupt the same real-systemd readback one hook at a time. This
	// exercises the production parser and gate on real field formatting.
	for _, property := range strings.Split(wssForbiddenUnitExecHooks, ",") {
		t.Run(property, func(t *testing.T) {
			modified := make(map[string]string, len(values)+1)
			for k, v := range values {
				modified[k] = v
			}
			modified[property] = "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; flags= ; }"
			if err := verifyWSSNoForeignExecHooks(modified); err == nil {
				t.Fatalf("accepted injected foreign lifecycle hook %s", property)
			}
		})
	}
}
