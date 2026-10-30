package quichelper

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"golang.org/x/sys/unix"
)

// Managed units have a durable canonical ExecStart and a distinct ownership
// marker. The source-only first-start service is never promoted by matching
// its name, receipt or current process shape.
func buildManagedUnitSpec(plan quic.Plan, nonce, binary, root string) (unitSpec, error) {
	s, err := buildUnitSpec(plan, nonce, binary, root)
	if err != nil {
		return s, err
	}
	s.Description = "STL-QUIC-MANAGED-" + string(plan.LinkID) + ":origin:" + nonce
	s.Args = []string{"--disable-update-check", "--log-level", "info", "--log-format", "json", "-c", s.ConfigPath, s.Args[len(s.Args)-1]}
	return s, nil
}

func managedSecurityProperties(s unitSpec) map[string]string {
	p := specSecurityProperties(s)
	p["Restart"], p["RestartUSec"] = "on-failure", "2s"
	p["StandardOutput"], p["StandardError"] = "journal", "journal"
	return p
}

func managedPropertyNames() string {
	return unitPropertyNames() + ",RestartUSec,Result,ExecMainCode,ExecMainStatus"
}

func queryManagedUnit(ctx context.Context, name string) (map[string]string, error) {
	raw, err := managerCommand(ctx, "systemctl", "--system", "show", name, "--property="+managedPropertyNames(), "--no-pager", "--all")
	if err != nil {
		return nil, err
	}
	return parseProperties(raw)
}

func verifyManagedUnitProperties(v map[string]string, s unitSpec, requireActive bool) error {
	if err := noForeignHooks(v); err != nil {
		return err
	}
	for key, want := range map[string]string{"Id": s.Name, "Names": s.Name, "LoadState": "loaded", "Transient": "yes",
		"Description": s.Description, "FragmentPath": "/run/systemd/transient/" + s.Name, "UnitFileState": "transient", "NeedDaemonReload": "no"} {
		if got, ok := v[key]; !ok || got != want {
			return fmt.Errorf("managed QUIC unit identity differs: %s", key)
		}
	}
	validState := false
	switch v["ActiveState"] + "/" + v["SubState"] {
	case "active/running", "inactive/dead", "failed/failed", "activating/auto-restart", "activating/start", "deactivating/stop-sigterm", "deactivating/stop-sigkill", "deactivating/stop-post", "deactivating/final-sigterm", "deactivating/final-sigkill":
		validState = true
	}
	if !validState || requireActive && (v["ActiveState"] != "active" || v["SubState"] != "running") {
		return fmt.Errorf("managed QUIC unit is not in an admitted runtime state")
	}
	for key, want := range managedSecurityProperties(s) {
		got, ok := v[key]
		if key == "EnvironmentFiles" && !ok {
			continue
		}
		if !ok || got != want {
			return fmt.Errorf("managed QUIC unit security differs: %s", key)
		}
	}
	if !matchesCommand(v["ExecStart"], s, false) || !matchesCommand(v["ExecStartEx"], s, true) {
		return fmt.Errorf("managed QUIC unit executable or argv differs")
	}
	if _, err := canonicalUint(v["NRestarts"]); err != nil {
		return fmt.Errorf("managed QUIC restart observation is incomplete")
	}
	if v["ActiveState"] == "active" {
		pid, err := strconv.Atoi(v["MainPID"])
		if err != nil || pid <= 1 || strconv.Itoa(pid) != v["MainPID"] || v["ExecMainPID"] != v["MainPID"] ||
			!canonicalHex(v["InvocationID"], 32) || strings.Trim(v["InvocationID"], "0") == "" || v["ControlGroup"] != "/system.slice/"+s.Name {
			return fmt.Errorf("managed QUIC unit process identity is incomplete")
		}
		started, err := canonicalUint(v["ExecMainStartTimestampMonotonic"])
		if err != nil || started == 0 {
			return fmt.Errorf("managed QUIC start timestamp is invalid")
		}
	}
	return nil
}

func canonicalUint(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return 0, fmt.Errorf("invalid numeric systemd observation")
	}
	return n, nil
}

func trustedTransientFragment(path, name string) error {
	var st unix.Stat_t
	if path != "/run/systemd/transient" || unix.Lstat(filepath.Join(path, name), &st) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0o022 != 0 || st.Nlink != 1 {
		return fmt.Errorf("managed QUIC transient fragment is untrusted")
	}
	return nil
}

// managerFailure carries useful classification without rendering command
// argv, stderr, configuration or an untrusted child error in public output.
type managerFailure struct {
	Kind     string
	ExitCode int
	cause    error
}

func (e *managerFailure) Error() string {
	if e.Kind == "command_exit" {
		return fmt.Sprintf("local systemd command exited (%d)", e.ExitCode)
	}
	return "local systemd command: " + e.Kind
}
func (e *managerFailure) Unwrap() error { return e.cause }

type managedUnitObservation struct {
	Loaded, Active bool
	Host           hostIdentity
	Values         map[string]string
	Process        *processPin
}

func inspectManagedUnit(ctx context.Context, s unitSpec) (managedUnitObservation, error) {
	var result managedUnitObservation
	if ctx == nil {
		return result, fmt.Errorf("managed QUIC context unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	host, err := currentHostIdentity()
	if err != nil {
		return result, err
	}
	result.Host = host
	raw, err := managerCommand(ctx, "systemctl", "--system", "show", "--property=UnitPath,Environment", "--no-pager", "--all")
	if err != nil {
		return result, err
	}
	manager, err := parseProperties(raw)
	if err != nil {
		return result, err
	}
	if env, ok := manager["Environment"]; !ok || !safeManagerEnvironment(env) {
		return result, fmt.Errorf("QUIC manager has an unapproved inherited environment")
	}
	values, err := queryManagedUnit(ctx, s.Name)
	if err != nil {
		return result, err
	}
	result.Values = values
	result.Loaded = values["LoadState"] == "loaded"
	if err := checkUnitSearchPathsPolicy(ctx, manager["UnitPath"], s.Name, result.Loaded); err != nil {
		return result, err
	}
	if result.Loaded {
		if err := verifyManagedUnitProperties(values, s, false); err != nil {
			return result, err
		}
	} else if err := verifyUnitVacant(values, s); err != nil {
		return result, err
	}
	if err := verifyManagedDependencies(ctx, s, values, !result.Loaded); err != nil {
		return result, err
	}
	result.Active = result.Loaded && values["ActiveState"] == "active" && values["SubState"] == "running"
	if result.Active {
		result.Process, err = observeManagedProcess(ctx, s, values)
		if err != nil {
			return result, err
		}
	}
	again, err := currentHostIdentity()
	if err != nil || again != host {
		if result.Process != nil {
			_ = result.Process.Close()
			result.Process = nil
		}
		return result, fmt.Errorf("system manager identity changed during managed QUIC inspection")
	}
	return result, nil
}

func verifyManagedDependencies(ctx context.Context, s unitSpec, v map[string]string, vacant bool) error {
	fallback, err := unitDependencyFallbackRequired(v)
	if err != nil || !fallback {
		return err
	}
	raw, err := managerCommand(ctx, "systemctl", "--system", "show", "--property=Version", "--no-pager", "--all")
	if err != nil {
		return err
	}
	version, err := legacyDependencyVersion(raw)
	if err != nil {
		return err
	}
	snapshot, err := readLegacyUnitGraph(ctx, s.Name, version)
	if err != nil {
		return err
	}
	return verifyLegacyUnitGraphState(snapshot, s, vacant, v["ActiveState"])
}

func observeManagedProcess(ctx context.Context, s unitSpec, v map[string]string) (_ *processPin, result error) {
	if err := verifyManagedUnitProperties(v, s, true); err != nil {
		return nil, err
	}
	pid, _ := strconv.Atoi(v["MainPID"])
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("managed QUIC process cannot be retained")
	}
	pin := &processPin{fd: fd}
	defer func() {
		if result != nil {
			_ = pin.Close()
		}
	}()
	if err := pin.alive(); err != nil {
		return nil, err
	}
	first, err := observeProcessEnvironment(pid, s, v, true)
	if err != nil {
		return nil, err
	}
	again, err := queryManagedUnit(ctx, s.Name)
	if err != nil {
		return nil, err
	}
	if err := verifyManagedUnitProperties(again, s, true); err != nil {
		return nil, err
	}
	if again["MainPID"] != v["MainPID"] || again["InvocationID"] != v["InvocationID"] || again["ExecMainStartTimestampMonotonic"] != v["ExecMainStartTimestampMonotonic"] {
		return nil, fmt.Errorf("managed QUIC invocation changed during inspection")
	}
	second, err := observeProcessEnvironment(pid, s, again, true)
	if err != nil || first != second || pin.alive() != nil {
		return nil, fmt.Errorf("managed QUIC process changed during inspection")
	}
	pin.Observation = first
	return pin, nil
}

func startManagedUnit(ctx context.Context, s unitSpec) error {
	args := []string{"--system", "--unit=" + s.Name, "--description=" + s.Description, "--service-type=exec", "--quiet"}
	props := managedSecurityProperties(s)
	keys := make([]string, 0, len(props))
	for key := range props {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if key == "Type" || key == "EnvironmentFiles" {
			continue
		}
		// systemd-run takes the unit-file directive; the readback property is
		// RestartUSec. Both systemd249 and newer accept RestartSec= here.
		property := key
		if key == "RestartUSec" {
			property = "RestartSec"
		}
		args = append(args, "--property="+property+"="+props[key])
	}
	args = append(args, "--", s.Binary)
	args = append(args, s.Args...)
	_, err := managerCommand(ctx, "systemd-run", args...)
	return err
}
