package ipsec

import (
	"context"
	"strings"
	"testing"
)

func TestDecodeNativeManagerStringArrayStrict(t *testing.T) {
	for _, tc := range []struct {
		frame string
		want  []string
	}{
		{"as 0", nil},
		{`as 1 "LANG=C"`, []string{"LANG=C"}},
		{`as 2 "LANG=en_US.UTF-8" "PATH=/usr/bin:/bin"`,
			[]string{"LANG=en_US.UTF-8", "PATH=/usr/bin:/bin"}},
		{`as 2 "LANG=hello world" "OTHER=plain"`,
			[]string{"LANG=hello world", "OTHER=plain"}},
	} {
		got, err := decodeNativeManagerStringArray(tc.frame)
		if err != nil || strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Fatalf("valid frame refused: %q, result=%v err=%v", tc.frame, got, err)
		}
	}
	for _, frame := range []string{
		"", "as", "as 00", "as -1", "as 257", "as 01 \"X=1\"",
		`as 1`, `as 1 "X=1" extra`, `as 2 "X=1"`,
		`as 1 X=1`, `as 1 "X=1" "Y=2"`,
		`as 1 "X=1`, `as 1 "X=1\q"`,
		`as 1 "X=1\n"`, `as 1 "X=1\x00"`,
		`as 1 "X=1"\nextra`,
		"as 1 \"X=" + strings.Repeat("a", 8192) + "\"",
	} {
		if _, err := decodeNativeManagerStringArray(frame); err == nil {
			t.Fatalf("untrusted manager frame accepted: %q", frame[:min(len(frame), 80)])
		}
	}
}

func TestNativePreStartManagerEnvironmentFailClosed(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want bool
	}{
		{"empty manager", "as 0", true},
		{"ordinary manager", `as 2 "LANG=C.UTF-8" "TZ=UTC"`, true},
		{"matching config selector", `as 1 "STRONGSWAN_CONF=/var/lib/simple-tun-link/ipsec/strongswan.conf"`, true},
		{"loader override", `as 1 "LD_PRELOAD=/run/foreign.so"`, false},
		{"library search override", `as 1 "LD_LIBRARY_PATH=/tmp"`, false},
		{"foreign strongswan override", `as 1 "STRONGSWAN_CONF=/etc/strongswan.conf"`, false},
		{"additional strongswan variable", `as 1 "STRONGSWAN_PLUGINS=foreign"`, false},
		{"duplicate manager assignment", `as 2 "LANG=C" "LANG=other"`, false},
		{"missing equals", `as 1 "FOREIGN"`, false},
		{"invalid name", `as 1 "1LD_PRELOAD=/tmp/a"`, false},
		{"malformed reply", `as 1 "LANG=C" garbage`, false},
		{"misleading array type", `s "LANG=C"`, false},
		{"oversized frame", "as 1 \"LONG=" + strings.Repeat("A", 8192) + "\"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeServiceBus{overrides: map[string]string{
				"Manager.Environment": tc.env,
				"Unit.ActiveState":    `s "inactive"`,
				"Service.MainPID":     "u 0",
			}}
			err := (NativeRuntimeAdmission{Runner: fake}).attestLoadedPreStartUnit(context.Background())
			if (err == nil) != tc.want {
				t.Fatalf("unsafe manager environment accepted=%v want=%v err=%v", err == nil, tc.want, err)
			}
			checkedManager := false
			for _, cmd := range fake.commands {
				if strings.Contains(cmd, "org.freedesktop.systemd1.Manager Environment") {
					checkedManager = true
				}
				if strings.Contains(cmd, " StartUnit ") || strings.Contains(cmd, " SetEnvironment ") ||
					strings.Contains(cmd, " UnsetEnvironment ") {
					t.Fatalf("pre-start environment gate mutated systemd: %s", cmd)
				}
			}
			if !checkedManager {
				t.Fatal("pre-start admission did not inspect manager environment")
			}
			if err != nil && strings.Contains(err.Error(), "/run/foreign.so") {
				t.Fatal("attestation failure exposed manager environment value")
			}
		})
	}
}

type nativeManagerEnvironmentDriftBus struct {
	fakeServiceBus
	reads int
}

func (f *nativeManagerEnvironmentDriftBus) RunBounded(ctx context.Context, limits CaptureLimits,
	binary string, args ...string) (CommandResult, error) {
	if len(args) == 6 && args[1] == "get-property" &&
		args[4] == "org.freedesktop.systemd1.Manager" && args[5] == "Environment" {
		f.reads++
		if f.reads == 2 {
			return CommandResult{Stdout: []byte("as 1 \"LD_PRELOAD=/run/foreign.so\"\n")}, nil
		}
	}
	return f.fakeServiceBus.RunBounded(ctx, limits, binary, args...)
}

func TestNativeManagerEnvironmentRecheckRejectsLateOverride(t *testing.T) {
	fake := &nativeManagerEnvironmentDriftBus{fakeServiceBus: fakeServiceBus{
		overrides: map[string]string{"Manager.Environment": "as 0"},
	}}
	admission := NativeRuntimeAdmission{Runner: fake}
	if err := admission.attestManagerEnvironment(context.Background()); err != nil {
		t.Fatalf("clean first manager env refused: %v", err)
	}
	if err := admission.attestManagerEnvironment(context.Background()); err == nil {
		t.Fatal("late manager-wide LD_PRELOAD accepted")
	}
	if fake.reads != 2 {
		t.Fatalf("manager environment not rechecked, reads=%d", fake.reads)
	}
}
