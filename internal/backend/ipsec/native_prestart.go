package ipsec

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// This pre-effect D-Bus gate inspects the effective systemd unit BEFORE
// ANY first service start. A canonical on-disk file or a post-start runtime
// authorization cannot rule out dormant foreign overrides or generators.
// LoadUnit loads metadata into systemd, but does not activate the service.
var nativeFreshExecStart = regexp.MustCompile(
	"^a\\(sasbttttuii\\) 1 \"/usr/sbin/charon-systemd\" 1 \"/usr/sbin/charon-systemd\" false( 0){7}$")

func (a NativeRuntimeAdmission) attestLoadedPreStartUnit(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || a.Runner == nil {
		return errors.New("native pre-start systemd admission unavailable")
	}
	reply, err := a.readBus(ctx, "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
		"org.freedesktop.systemd1.Manager", "LoadUnit", "s", nativeServiceName)
	if err != nil {
		return errors.New("cannot load native service metadata without starting it")
	}
	path, err := decodeDBusString(reply, "o")
	if err != nil || !nativeUnitObject.MatchString(path) {
		return errors.New("native pre-start unit identity not verified")
	}
	for _, prop := range []struct{ category, key, value string }{
		{"Unit", "LoadState", "loaded"},
		{"Unit", "ActiveState", "inactive"},
		{"Unit", "FragmentPath", NativeExclusiveServiceUnitPath},
		{"Unit", "SourcePath", ""},
		{"Service", "Type", "notify"},
		{"Service", "User", ""},
		{"Service", "Group", ""},
		{"Service", "RootDirectory", ""},
		{"Service", "Restart", "no"},
	} {
		if a.require(ctx, path, prop.category, prop.key, prop.value) != nil {
			return fmt.Errorf("native pre-start property %s.%s does not match the fixed profile", prop.category, prop.key)
		}
	}
	for _, prop := range []struct{ category, key, value string }{
		{"Unit", "DropInPaths", "as 0"},
		{"Unit", "NeedDaemonReload", "b false"},
		{"Unit", "UnitFileState", "s \"static\""},
		{"Service", "MainPID", "u 0"},
		{"Service", "UMask", "u 63"},
		{"Service", "Environment", "as 1 \"STRONGSWAN_CONF=/var/lib/simple-tun-link/ipsec/strongswan.conf\""},
	} {
		got, err := a.property(ctx, path, prop.category, prop.key)
		if err != nil || got != prop.value {
			return fmt.Errorf("native pre-start property %s.%s unavailable or changed", prop.category, prop.key)
		}
	}
	// Explicitly exclude unit-level execution overrides. A drop-in or
	// generator could otherwise prepend a root ExecStartPre marker.
	for _, key := range []string{"ExecCondition", "ExecStartPre", "ExecStartPost",
		"ExecReload", "ExecStop", "ExecStopPost"} {
		got, err := a.property(ctx, path, "Service", key)
		if err != nil || got != "a(sasbttttuii) 0" {
			return fmt.Errorf("native pre-start Service.%s has foreign execution directives or unsupported property", key)
		}
	}
	got, err := a.property(ctx, path, "Service", "ExecStart")
	if err != nil || !nativeFreshExecStart.MatchString(got) {
		return errors.New("native pre-start ExecStart differs from exact reviewed service")
	}
	// systemd can garbage-collect a loaded but still inactive, unreferenced
	// unit between separate busctl invocations. GetUnit is a cached-unit
	// query, not evidence of an effective source change. Re-load the same
	// unit metadata without starting it; never waive any pre-start profile.
	again, err := a.readBus(ctx, "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
		"org.freedesktop.systemd1.Manager", "LoadUnit", "s", nativeServiceName)
	if err != nil {
		return errors.New("native effective unit could not be refreshed before first start")
	}
	loaded, err := decodeDBusString(again, "o")
	if err != nil || loaded != path || !nativeUnitObject.MatchString(loaded) {
		return errors.New("native unit source changed before first start")
	}
	// Refresh the critical execution identity after the final metadata load.
	// These values must still match while systemd holds the returned object.
	for _, prop := range []struct{ category, key, value string }{
		{"Unit", "LoadState", "s \"loaded\""},
		{"Unit", "ActiveState", "s \"inactive\""},
		{"Unit", "FragmentPath", "s \"" + NativeExclusiveServiceUnitPath + "\""},
		{"Unit", "SourcePath", "s \"\""},
		{"Unit", "DropInPaths", "as 0"},
		{"Unit", "NeedDaemonReload", "b false"},
		{"Service", "ExecStartPre", "a(sasbttttuii) 0"},
		{"Service", "Environment", "as 1 \"STRONGSWAN_CONF=/var/lib/simple-tun-link/ipsec/strongswan.conf\""},
	} {
		value, err := a.property(ctx, loaded, prop.category, prop.key)
		if err != nil || value != prop.value {
			return fmt.Errorf("native refreshed pre-start property %s.%s unavailable or changed", prop.category, prop.key)
		}
	}
	start, err := a.property(ctx, loaded, "Service", "ExecStart")
	if err != nil || !nativeFreshExecStart.MatchString(start) {
		return errors.New("native refreshed pre-start ExecStart differs from fixed service")
	}
	return nil
}

// The full production boundary adds a fresh independent process and socket
// inventory immediately before the only permitted privileged service start.
func (a NativeRuntimeAdmission) attestPreStartUnit(ctx context.Context) error {
	if err := a.attestLoadedPreStartUnit(ctx); err != nil {
		return err
	}
	if err := verifyNoForeignStrongSwanProcess(0); err != nil {
		return errors.New("foreign strongSwan process appeared before first start")
	}
	if err := nativeIKEPortsVacant(); err != nil {
		return errors.New("foreign IKE socket appeared before first start")
	}
	return nil
}
