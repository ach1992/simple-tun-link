package wss

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

// Loaded-unit readback is the destructive-authority gate for Stop/Restart.
// Testing the pure helper function alone does not cover this admission path.
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
	oldPost := wssRestartReadback(probe, false)
	newPost := wssRestartReadback(probe, true)
	mainEx := strings.Replace(wssRestartReadback(main, true), "flags=ignore-failure", "flags=", 1)
	unit := fmt.Sprintf("LoadState=loaded\nActiveState=active\nTransient=yes\nDescription=%s\nExecStart={ path=%s ; argv[]=%s %s ; }\nExecStartEx=%s\nExecStartPost=%s\nExecStartPostEx=%s\nEnvironment=%s\nType=exec\nRestart=on-failure\nRestartUSec=2s\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nCollectMode=inactive-or-failed\n",
		host.unitDescription(context.Background(), link), main.Binary, main.Binary, strings.Join(main.Args, " "), mainEx, oldPost, newPost, strings.Join(main.Env, " "))
	for label, tc := range map[string]struct {
		readback string
		success  bool
	}{
		"poststart-exact-both-properties": {unit, true},
		"legacy-both-empty":               {strings.Replace(strings.Replace(unit, "ExecStartPost="+oldPost, "ExecStartPost=", 1), "ExecStartPostEx="+newPost, "ExecStartPostEx=", 1), true},
		"legacy-both-missing":             {strings.Replace(strings.Replace(unit, "ExecStartPost="+oldPost+"\n", "", 1), "ExecStartPostEx="+newPost+"\n", "", 1), true},
		"legacy-one-empty-one-missing":    {strings.Replace(strings.Replace(unit, "ExecStartPost="+oldPost, "ExecStartPost=", 1), "ExecStartPostEx="+newPost+"\n", "", 1), true},
		"foreign-post":                    {strings.Replace(unit, "ExecStartPost="+oldPost, "ExecStartPost={ path=/bin/sh ; argv[]=/bin/sh -c true ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }", 1), false},
		"main-extended-missing":           {strings.Replace(unit, "ExecStartEx="+mainEx+"\n", "", 1), false},
		"main-fully-privileged":           {strings.Replace(unit, "ExecStartEx="+mainEx, "ExecStartEx="+strings.Replace(mainEx, "flags=", "flags=fully-privileged", 1), 1), false},
		"main-no-env-expand":              {strings.Replace(unit, "ExecStartEx="+mainEx, "ExecStartEx="+strings.Replace(mainEx, "flags=", "flags=no-env-expand", 1), 1), false},
		"missing-extended-command":        {strings.Replace(unit, "ExecStartPostEx="+newPost+"\n", "", 1), false},
		"missing-legacy-command":          {strings.Replace(unit, "ExecStartPost="+oldPost+"\n", "", 1), false},
		"privileged-extended-command":     {strings.Replace(unit, "flags=ignore-failure", "flags=ignore-failure fully-privileged", 1), false},
		"no-env-expand":                   {strings.Replace(unit, "flags=ignore-failure", "flags=ignore-failure no-env-expand", 1), false},
		"wrong-ignore":                    {strings.Replace(unit, "ignore_errors=yes", "ignore_errors=no", 1), false},
		"different-private-peer":          {strings.Replace(unit, "-w 3 10.99.1.2", "-w 3 10.99.1.3", 1), false},
		"wrong-overall-deadline":          {strings.Replace(unit, "-w 3", "-w 30", 1), false},
		"truncated-extended":              {strings.Replace(unit, " ; status=0/0 }", " }", 1), false},
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
	// Inspecting the readback is mandatory even when the service is active;
	// foreign execution flags cannot authorize systemctl stop on that unit.
	counter := &wssStopDispatchCounter{observation: strings.Replace(unit, "flags=ignore-failure", "flags=ignore-failure fully-privileged", 1)}
	host.Runner = counter
	if _, err := host.StopHelper(context.Background(), link); err == nil || counter.mutations != 0 {
		t.Fatalf("foreign flags must block Stop before mutation, err=%v mutating calls=%d", err, counter.mutations)
	}
	// Private source stays private; no test file is written into the repository.
	if _, err := os.Stat(filepath.Join(root, "credentials", "wss", string(link.ID))); err != nil {
		t.Fatal(err)
	}
}

type wssStopDispatchCounter struct {
	observation string
	mutations   int
}

func (r *wssStopDispatchCounter) Run(context.Context, string, ...string) (linux.CommandResult, error) {
	r.mutations++
	return linux.CommandResult{}, fmt.Errorf("destructive command must never be dispatched")
}
func (r *wssStopDispatchCounter) RunBounded(_ context.Context, _ linux.CaptureLimits, name string, args ...string) (linux.CommandResult, error) {
	if name != "systemctl" || len(args) < 3 || args[0] != "show" {
		return linux.CommandResult{}, fmt.Errorf("unexpected unit inspection")
	}
	return linux.CommandResult{Stdout: []byte(r.observation)}, nil
}
