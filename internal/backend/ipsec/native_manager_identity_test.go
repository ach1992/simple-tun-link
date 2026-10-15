package ipsec

import (
	"context"
	"testing"
)

func TestNativeManagerBusOwnerStrictPID1Identity(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		allow          bool
	}{
		{"expected PID1", "PID=1\nUID=0\nComm=systemd\n", true},
		{"expected PID1 detailed", "PID=1\nUID=0\nComm=systemd\nCGroup=/init.scope\n", true},
		{"foreign PID", "PID=501\nUID=0\nComm=systemd\n", false},
		{"foreign UID", "PID=1\nUID=1000\nComm=systemd\n", false},
		{"different process", "PID=1\nUID=0\nComm=fake\n", false},
		{"missing pid", "UID=0\nComm=systemd\n", false},
		{"duplicate pid", "PID=1\nPID=1\nUID=0\nComm=systemd\n", false},
		{"malformed pid", "PID=1 extra\nUID=0\nComm=systemd\n", false},
		{"missing newline", "PID=1\nUID=0\nComm=systemd", false},
		{"binary injection", "PID=1\x00\nUID=0\nComm=systemd\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bus := &fakeServiceBus{overrides: map[string]string{"Manager.Status": tc.response}}
			err := (NativeRuntimeAdmission{Runner: bus}).attestSystemdManagerIdentity(context.Background())
			if (err == nil) != tc.allow {
				t.Fatalf("bus owner accepted=%v expected=%v err=%v", err == nil, tc.allow, err)
			}
		})
	}
}

func TestNativeManagerEnvironmentRejectsFakeBusOwnerBeforeProperty(t *testing.T) {
	bus := &fakeServiceBus{overrides: map[string]string{
		"Manager.Status":      "PID=890\nUID=0\nComm=systemd\n",
		"Manager.Environment": "as 0",
	}}
	err := (NativeRuntimeAdmission{Runner: bus}).attestManagerEnvironment(context.Background())
	if err == nil || len(bus.commands) != 1 ||
		bus.commands[0] != "--system status org.freedesktop.systemd1" {
		t.Fatalf("manager property was read before bus owner trust proof: %v commands=%v", err, bus.commands)
	}
}
