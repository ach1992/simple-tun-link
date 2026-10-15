package ipsec

import (
	"context"
	"strings"
	"testing"
)

func TestNativeFirstStartAttestsExactEffectiveUnitBeforeAnyServiceExecution(t *testing.T) {
	const exactExe = "a(sasbttttuii) 1 \"/usr/sbin/charon-systemd\" 1 \"/usr/sbin/charon-systemd\" false 0 0 0 0 0 0 0"
	cases := []struct {
		name   string
		change map[string]string
		allow  bool
	}{
		{"clean private unit", nil, true},
		{"foreign dormant drop-in", map[string]string{
			"Unit.DropInPaths": "as 1 \"/etc/systemd/system/simple-tun-link-ipsec.service.d/override.conf\""}, false},
		{"foreign generator", map[string]string{
			"Unit.FragmentPath": "s \"/run/systemd/generator/simple-tun-link-ipsec.service\""}, false},
		{"foreign source", map[string]string{"Unit.SourcePath": "s \"/etc/init.d/foreign\""}, false},
		{"unexpected ExecStartPre root hook", map[string]string{
			"Service.ExecStartPre": "a(sasbttttuii) 1 \"/bin/sh\" 3 \"/bin/sh\" \"-c\" \"touch /tmp/FOREIGN\" false 0 0 0 0 0 0 0"}, false},
		{"unexpected ExecCondition", map[string]string{"Service.ExecCondition": "a(sasbttttuii) 1 \"/bin/true\" 1 \"/bin/true\" false 0 0 0 0 0 0 0"}, false},
		{"modified ExecStart", map[string]string{"Service.ExecStart": "a(sasbttttuii) 1 \"/bin/sh\" 1 \"/bin/sh\" false 0 0 0 0 0 0 0"}, false},
		{"extra ExecStart", map[string]string{"Service.ExecStart": exactExe + " unexpected"}, false},
		{"premature boot enablement", map[string]string{"Unit.UnitFileState": "s \"enabled\""}, false},
		{"service already active", map[string]string{"Unit.ActiveState": "s \"active\""}, false},
		{"existing PID", map[string]string{"Service.MainPID": "u 555"}, false},
		{"restart policy changed", map[string]string{"Service.Restart": "s \"always\""}, false},
		{"environment redirected", map[string]string{"Service.Environment": "as 1 \"STRONGSWAN_CONF=/tmp/foreign.conf\""}, false},
		{"foreign EnvironmentFile", map[string]string{"Service.EnvironmentFiles": "a(sb) 1 \"/tmp/foreign.env\" false"}, false},
		{"foreign PassEnvironment", map[string]string{"Service.PassEnvironment": "as 1 \"LD_PRELOAD\""}, false},
		{"foreign UnsetEnvironment", map[string]string{"Service.UnsetEnvironment": "as 1 \"PATH\""}, false},
		{"foreign PAMName", map[string]string{"Service.PAMName": "s \"external-pam\""}, false},
		{"daemon reload unresolved", map[string]string{"Unit.NeedDaemonReload": "b true"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overrides := map[string]string{
				"Unit.ActiveState": "s \"inactive\"",
				"Service.MainPID":  "u 0",
			}
			for k, v := range tc.change {
				overrides[k] = v
			}
			bus := &fakeServiceBus{overrides: overrides}
			err := (NativeRuntimeAdmission{Runner: bus}).attestLoadedPreStartUnit(context.Background())
			if (err == nil) != tc.allow {
				t.Fatalf("pre-start effective unit accepted=%v wanted=%v err=%v", err == nil, tc.allow, err)
			}
			loadedMetadata := false
			for _, call := range bus.commands {
				if strings.Contains(call, " LoadUnit ") {
					loadedMetadata = true
				}
				if strings.Contains(call, " StartUnit ") || strings.Contains(call, " StopUnit ") {
					t.Fatalf("pre-start attestation activated a unit: %q", call)
				}
			}
			if !loadedMetadata {
				t.Fatal("pre-start inspection did not load effective unit metadata")
			}
		})
	}
}

// A dormant, not-yet-started systemd unit may be garbage-collected after an
// observational busctl invocation. The effective metadata source is refreshed
// using LoadUnit, never accepted on a failed or changed second identity.
type nativeSecondLoadDriftBus struct {
	fakeServiceBus
	loads int
}

func (b *nativeSecondLoadDriftBus) RunBounded(ctx context.Context, limits CaptureLimits,
	binary string, args ...string) (CommandResult, error) {
	if len(args) > 1 && args[1] == "call" {
		b.loads++
		if b.loads == 2 {
			return CommandResult{Stdout: []byte("o \"/org/freedesktop/systemd1/unit/foreign_2eservice\"\n")}, nil
		}
	}
	return b.fakeServiceBus.RunBounded(ctx, limits, binary, args...)
}

func TestNativePreStartRefreshRefusesChangedSystemdObjectIdentity(t *testing.T) {
	bus := &nativeSecondLoadDriftBus{fakeServiceBus: fakeServiceBus{
		overrides: map[string]string{
			"Unit.ActiveState": "s \"inactive\"",
			"Service.MainPID":  "u 0",
		},
	}}
	if err := (NativeRuntimeAdmission{Runner: bus}).attestLoadedPreStartUnit(context.Background()); err == nil {
		t.Fatal("changed second LoadUnit identity was admitted")
	}
	if bus.loads != 2 {
		t.Fatalf("second effective unit was not independently checked, loads=%d", bus.loads)
	}
}
