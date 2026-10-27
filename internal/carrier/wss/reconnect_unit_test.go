package wss

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Loaded-unit readback is the destructive-authority gate for Stop/Restart.
// Testing the helper function alone does not exercise this admission path.
func TestWSSLoadedDialUnitRejectsForeignPoststartAndAllowsExactLegacy(t *testing.T) {
	link := restartWSSLink("dial")
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, dialer, err := GeneratePair(link.ID, link.Underlay.Peer.String())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Clear()
	defer dialer.Clear()
	if err := Stage(root, link, dialer); err != nil {
		t.Fatal(err)
	}
	host := Host{StateRoot: root}
	main, err := host.command(link)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(main.ServerRestrictions)
	probe, err := dialRestartProbe(link)
	if err != nil {
		t.Fatal(err)
	}
	post := "{ path=" + probe.Binary + " ; argv[]=" + probe.Binary + " " + strings.Join(probe.Args, " ") + " ; ignore_errors=yes ; }"
	unit := fmt.Sprintf("LoadState=loaded\nActiveState=active\nTransient=yes\nDescription=%s\nExecStart={ path=%s ; argv[]=%s %s ; }\nExecStartPost=%s\nEnvironment=%s\nType=exec\nRestart=on-failure\nRestartUSec=2s\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nCollectMode=inactive-or-failed\n",
		host.unitDescription(context.Background(), link), main.Binary, main.Binary, strings.Join(main.Args, " "), post, strings.Join(main.Env, " "))
	for label, tc := range map[string]struct {
		readback string
		success  bool
	}{
		"poststart-correct": {unit, true},
		"legacy-empty":      {strings.Replace(unit, "ExecStartPost="+post, "ExecStartPost=", 1), true},
		"foreign-post":      {strings.Replace(unit, "ExecStartPost="+post, "ExecStartPost={ path=/bin/sh ; argv[]=/bin/sh -c true ; ignore_errors=yes ; }", 1), false},
		// Real systemd 249 and 259 omit the unset property entirely.
		"legacy-missing-post":    {strings.Replace(unit, "ExecStartPost="+post+"\n", "", 1), true},
		"wrong-ignore":           {strings.Replace(unit, "ignore_errors=yes", "ignore_errors=no", 1), false},
		"different-private-peer": {strings.Replace(unit, "-W 1 10.99.1.2", "-W 1 10.99.1.3", 1), false},
	} {
		t.Run(label, func(t *testing.T) {
			h := host
			h.Runner = wssUnitAbsentStub{result: tc.readback}
			actual, err := h.inspectUnit(context.Background(), link)
			if tc.success && (err != nil || !actual.loaded || !actual.active) {
				t.Fatalf("trusted active unit rejected: %v", err)
			}
			if !tc.success && err == nil {
				t.Fatal("untrusted unit adopted")
			}
		})
	}
	// Private source stays private; no test file is written into the repository.
	if _, err := os.Stat(filepath.Join(root, "credentials", "wss", string(link.ID))); err != nil {
		t.Fatal(err)
	}
}
