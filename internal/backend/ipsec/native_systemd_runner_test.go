package ipsec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNativeSystemdRunnerDeniesUntrustedTransportAndExecutable(t *testing.T) {
	r := nativeSystemdRunner{Timeout: time.Second}
	for _, c := range []struct {
		binary string
		args   []string
	}{
		{"/usr/bin/env", nil},
		{nativeBusctl, []string{"--system", "get-property"}},
		{nativeBusctl, []string{"--address=unix:path=/run/stl-decoy", "call"}},
		{nativeBusctl, []string{"--system", "status", "org.freedesktop.systemd1", "--address=unix:path=/run/stl-decoy"}},
		{nativeBusctl, []string{"--system", "get-property", "--address=unix:path=/run/stl-decoy", "a", "b", "c"}},
		{nativeSystemctlBinary, []string{"--user", "status"}},
		{nativeSystemctlBinary, []string{"--system", "--host=remote", "status"}},
		{nativeSystemctlBinary, []string{"--system", "--machine=foreign", "status"}},
	} {
		if _, err := r.RunBounded(context.Background(),
			CaptureLimits{Stdout: 4096, Stderr: 1024}, c.binary, c.args...); err == nil {
			t.Fatalf("trusted systemd runner accepted untrusted command transport: %s", c.binary)
		}
	}
}

func TestNativeSystemdProductionCommandEnvironmentIsIsolated(t *testing.T) {
	// Use the SAME concrete bounded executor and fixed environment selected
	// by nativeSystemdRunner. A harmless /usr/bin/env makes the actual child
	// environment observable without contacting or changing any systemd host.
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/stl-decoy")
	t.Setenv("SYSTEMCTL_FORCE_BUS", "1")
	t.Setenv("LD_PRELOAD", "/run/stl-do-not-load.so")
	t.Setenv("LD_LIBRARY_PATH", "/run/stl-foreign-lib")
	t.Setenv("GCONV_PATH", "/run/stl-gconv")
	t.Setenv("SYSTEMD_PAGER", "/run/stl-pager")
	t.Setenv("PATH", "/run/stl-hostile-path")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := BoundedExecRunner{Timeout: 2 * time.Second, env: nativeSystemdFixedEnvironment()}
	out, err := r.RunBounded(ctx, CaptureLimits{Stdout: 4096, Stderr: 1024}, "/usr/bin/env")
	if err != nil {
		t.Fatalf("production environment-bound process could not run: %v", err)
	}
	defer clear(out.Stdout)
	defer clear(out.Stderr)
	if len(out.Stderr) != 0 {
		t.Fatal("trusted helper emitted unexpected diagnostic output")
	}
	want := nativeSystemdFixedEnvironment()
	got := strings.Split(strings.TrimSuffix(string(out.Stdout), "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("inherited variables reached trusted child, entries=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal("trusted child environment differed from fixed allowlist")
		}
	}
	// Invoke the ACTUAL nativeSystemdRunner (not only its low-level executor)
	// with an inert local systemctl command. Inherited loader controls must
	// not cause errors or alter child diagnostics on systemd 249+ hosts.
	probe, err := (nativeSystemdRunner{Timeout: 3 * time.Second}).RunBounded(ctx,
		CaptureLimits{Stdout: 4096, Stderr: 1024},
		nativeSystemctlBinary, "--system", "--version")
	if err != nil || len(probe.Stderr) != 0 || !strings.Contains(string(probe.Stdout), "systemd") {
		t.Fatal("trusted local systemctl failed under hostile inherited environment")
	}
	clear(probe.Stdout)
	clear(probe.Stderr)
}

func TestNativeSystemdInspectorPinsPrivateManagerTransport(t *testing.T) {
	// Fake records the exact args issued through the production admission
	// path. A --system or environment-selected bus is never a trust oracle.
	fake := &fakeServiceBus{overrides: map[string]string{"Manager.Environment": "as 0"}}
	a := NativeRuntimeAdmission{Runner: fake}
	if err := a.attestManagerEnvironment(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.commands) != 2 || fake.commands[0] !=
		"--system status org.freedesktop.systemd1" ||
		!strings.HasPrefix(fake.commands[1],
			"--system get-property org.freedesktop.systemd1 ") {
		t.Fatal("pre-start trust oracle did not verify PID1 before reading manager environment")
	}
}
