package ipsec

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type fakeServiceBus struct {
	overrides map[string]string
	commands  []string
}

func (f *fakeServiceBus) RunBounded(ctx context.Context, limits CaptureLimits, binary string, args ...string) (CommandResult, error) {
	if ctx == nil || ctx.Err() != nil || limits.Stdout < 16 || binary != nativeBusctl ||
		len(args) < 2 || args[0] != "--system" {
		return CommandResult{}, fmt.Errorf("unexpected bounded service probe")
	}
	f.commands = append(f.commands, strings.Join(args, " "))
	if args[1] == "call" {
		return CommandResult{Stdout: []byte("o \"/org/freedesktop/systemd1/unit/simple_2dtun_2dlink_2dipsec_2eservice\"\n")}, nil
	}
	if args[1] != "get-property" || len(args) != 6 {
		return CommandResult{}, fmt.Errorf("only observational properties allowed")
	}
	prop := strings.TrimPrefix(args[4], "org.freedesktop.systemd1.") + "." + args[5]
	if value, ok := f.overrides[prop]; ok {
		return CommandResult{Stdout: []byte(value + "\n")}, nil
	}
	fixed := map[string]string{
		"Unit.LoadState":        "s \"loaded\"",
		"Unit.ActiveState":      "s \"active\"",
		"Unit.FragmentPath":     "s \"/etc/systemd/system/simple-tun-link-ipsec.service\"",
		"Unit.SourcePath":       "s \"\"",
		"Unit.UnitFileState":    "s \"static\"",
		"Service.Type":          "s \"notify\"",
		"Service.User":          "s \"\"",
		"Service.Group":         "s \"\"",
		"Service.RootDirectory": "s \"\"",
		"Unit.DropInPaths":      "as 0",
		"Unit.NeedDaemonReload": "b false",
		"Service.UMask":         "u 63",
		"Service.Environment":   "as 1 \"STRONGSWAN_CONF=/var/lib/simple-tun-link/ipsec/strongswan.conf\"",
		"Service.MainPID":       "u 9876",
		"Service.Restart":       "s \"no\"",
		"Service.ExecCondition": "a(sasbttttuii) 0",
		"Service.ExecStartPre":  "a(sasbttttuii) 0",
		"Service.ExecStartPost": "a(sasbttttuii) 0",
		"Service.ExecReload":    "a(sasbttttuii) 0",
		"Service.ExecStop":      "a(sasbttttuii) 0",
		"Service.ExecStopPost":  "a(sasbttttuii) 0",
		"Service.ExecStart":     "a(sasbttttuii) 1 \"/usr/sbin/charon-systemd\" 1 \"/usr/sbin/charon-systemd\" false 0 0 0 0 0 0 0",
	}
	value, ok := fixed[prop]
	if !ok {
		return CommandResult{}, fmt.Errorf("unrecognized systemd property")
	}
	return CommandResult{Stdout: []byte(value + "\n")}, nil
}

func TestNativeServiceAdmissionStrictEffectiveProperties(t *testing.T) {
	cases := []struct {
		name     string
		override map[string]string
		want     bool
	}{
		{"exact", nil, true},
		{"generator", map[string]string{"Unit.FragmentPath": "s \"/run/systemd/generator/simple-tun-link-ipsec.service\""}, false},
		{"foreign unit", map[string]string{"Unit.UnitFileState": "s \"enabled\""}, false},
		{"drop-in", map[string]string{"Unit.DropInPaths": "as 1 \"/etc/systemd/system/simple-tun-link-ipsec.service.d/override.conf\""}, false},
		{"daemon-reload-needed", map[string]string{"Unit.NeedDaemonReload": "b true"}, false},
		{"unsafe-config-selection", map[string]string{"Service.Environment": "as 1 \"STRONGSWAN_CONF=/tmp/foreign.conf\""}, false},
		{"missing-private-environment", map[string]string{"Service.Environment": "as 0"}, false},
		{"wrong-main-pid", map[string]string{"Service.MainPID": "u 0"}, false},
		{"extra-env-line", map[string]string{"Service.Environment": "as 2 \"STRONGSWAN_CONF=/var/lib/simple-tun-link/ipsec/strongswan.conf\" \"EXTRA=1\""}, false},
		{"wrong-umask", map[string]string{"Service.UMask": "u 18"}, false},
		{"invalid-property-frame", map[string]string{"Unit.LoadState": "s \"loaded\"\ns \"foreign\""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeServiceBus{overrides: c.override}
			pid, err := (NativeRuntimeAdmission{Runner: fake}).servicePID(context.Background())
			if (err == nil) != c.want {
				t.Fatalf("service admission mismatch, pid=%d err=%v", pid, err)
			}
			if c.want && pid != 9876 {
				t.Fatalf("unexpected accepted PID %d", pid)
			}
			for _, cmd := range fake.commands {
				if strings.Contains(cmd, " StartUnit ") || strings.Contains(cmd, " StopUnit ") ||
					strings.Contains(cmd, " Reload ") || strings.Contains(cmd, " daemon-reload ") {
					t.Fatalf("read-only admission performed effectful systemd command: %s", cmd)
				}
			}
		})
	}
}

func TestDBusDecoderRejectsUntrustedProperties(t *testing.T) {
	for _, frame := range []string{
		"s notquoted", "s \"value\" trailing", "u 2", "s \"one\\ninjected\"", "s \"a\\x00b\"",
	} {
		if _, err := decodeDBusString(frame, "s"); err == nil {
			t.Fatalf("invalid D-Bus string was trusted: %q", frame)
		}
	}
}

func TestEnabledNativeServiceRequiresExactBootEdgeProof(t *testing.T) {
	cases := []struct {
		state    string
		bootEdge bool
		expected bool
	}{
		{`s "static"`, false, true},
		{`s "static"`, true, true},
		{`s "enabled"`, false, false},
		{`s "enabled"`, true, true},
		{`s "enabled-runtime"`, true, false},
		{`s "linked"`, true, false},
		{`s "masked"`, true, false},
		{`s "enabled" trailing`, true, false},
		{`s "enabled"\ns "foreign"`, true, false},
	}
	for _, tc := range cases {
		if got := nativeUnitFileStateVerified(tc.state, tc.bootEdge); got != tc.expected {
			t.Errorf("state=%q bootEdge=%v got=%v want=%v", tc.state, tc.bootEdge, got, tc.expected)
		}
	}
}
