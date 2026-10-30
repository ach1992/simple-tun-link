// Package quichelper implements only the original first start of an already
// admitted QUIC helper. It cannot recover, restart, stop or retire a service.
package quichelper

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
)

type unitSpec struct {
	Name, Description, Binary, ConfigPath string
	Args                                  []string
	PrivilegedPort                        bool
}

func buildUnitSpec(plan quic.Plan, nonce, binary, root string) (unitSpec, error) {
	if plan.LinkID.Validate() != nil || !canonicalHex(nonce, 32) ||
		!safeArgument(binary) || !safeArgument(root) || !filepath.IsAbs(binary) ||
		!filepath.IsAbs(root) || filepath.Clean(binary) != binary || filepath.Clean(root) != root || root == "/" {
		return unitSpec{}, fmt.Errorf("invalid original QUIC helper identity")
	}
	role := ""
	switch plan.Role {
	case quic.Dial:
		role = "client"
	case quic.Listen:
		role = "server"
	default:
		return unitSpec{}, fmt.Errorf("invalid original QUIC helper role")
	}
	config := filepath.Join(root, "credentials", "quic", string(plan.LinkID), "helper.json")
	return unitSpec{Name: "stl-quic-" + string(plan.LinkID)[4:] + ".service", Description: "STL-QUIC-" + string(plan.LinkID) + ":tx:" + nonce,
		Binary: binary, ConfigPath: config, PrivilegedPort: plan.Role == quic.Listen && plan.Underlay.Port() < 1024 || plan.Role == quic.Dial && plan.LocalForwardUDPPort < 1024, Args: []string{"--disable-update-check", "--log-level", "info", "-c", config, role}}, nil
}

// Paths and argv use a deliberately unambiguous subset of systemd's command
// syntax. In particular '$', '%', quoting and escapes must never be expanded
// differently by systemd 249 and newer managers.
func safeArgument(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_.:@+-", c)) {
			return false
		}
	}
	return true
}

func canonicalHex(s string, n int) bool {
	return len(s) == n && strings.Trim(s, "0123456789abcdef") == ""
}

// This immutable list removes known manager context at systemd's final
// environment assembly boundary. Manager keys are admitted only when a fixed
// Environment value overrides them or this list requires their removal.
const helperUnsetEnvironment = "HOME LOGNAME USER SHELL MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE SYSTEMD_EXEC_PID SGX_AESM_ADDR"

var securityProperties = map[string]string{
	"Type": "exec", "Restart": "no", "NoNewPrivileges": "yes", "PrivateTmp": "yes",
	"ProtectSystem": "strict", "ProtectHome": "yes", "PrivateDevices": "yes",
	"ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes",
	"RestrictSUIDSGID": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "yes",
	"CapabilityBoundingSet": "", "AmbientCapabilities": "", "User": "root", "Group": "root",
	"UMask": "0077", "StandardInput": "null", "StandardOutput": "null", "StandardError": "null",
	"WorkingDirectory": "/", "KillMode": "control-group", "CollectMode": "inactive", "RemainAfterExit": "no", "StopWhenUnneeded": "no",
	"DynamicUser": "no", "PrivateNetwork": "no", "NotifyAccess": "none", "DefaultDependencies": "no",
	"Environment": "PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C LC_CTYPE=C", "PassEnvironment": "",
	"UnsetEnvironment": helperUnsetEnvironment, "EnvironmentFiles": "", "RootDirectory": "", "RootImage": "",
	"NetworkNamespacePath": "",
}

const forbiddenHooks = "ExecCondition,ExecConditionEx,ExecStartPre,ExecStartPreEx,ExecStartPost,ExecStartPostEx,ExecReload,ExecReloadEx,ExecReloadPost,ExecReloadPostEx,ExecStop,ExecStopEx,ExecStopPost,ExecStopPostEx"

func unitPropertyNames() string {
	names := []string{"Id", "Names", "LoadState", "ActiveState", "SubState", "Transient", "Description", "FragmentPath", "SourcePath", "DropInPaths", "UnitFileState", "ExecStart", "ExecStartEx", "MainPID", "ExecMainPID", "InvocationID", "ControlGroup", "NRestarts", "ExecMainStartTimestampMonotonic", "OnFailure", "OnSuccess", "NeedDaemonReload", "Upholds", "UpheldBy", "TriggeredBy", "Sockets"}
	for key := range securityProperties {
		names = append(names, key)
	}
	names = append(names, strings.Split(forbiddenHooks, ",")...)
	slices.Sort(names)
	return strings.Join(slices.Compact(names), ",")
}

func parseProperties(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' {
		return nil, fmt.Errorf("incomplete QUIC systemd readback")
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid QUIC systemd readback")
		}
		if _, dup := values[k]; dup {
			return nil, fmt.Errorf("ambiguous QUIC systemd readback")
		}
		values[k] = v
	}
	return values, nil
}

func noForeignHooks(values map[string]string) error {
	for _, key := range strings.Split(forbiddenHooks, ",") {
		if values[key] != "" {
			return fmt.Errorf("foreign QUIC service lifecycle command: %s", key)
		}
	}
	for _, key := range []string{"DropInPaths", "SourcePath", "OnFailure", "OnSuccess"} {
		if values[key] != "" {
			return fmt.Errorf("foreign QUIC service directive: %s", key)
		}
	}
	// Restart=no does not prevent a foreign unit from activating or
	// continuously upholding this service. Missing Upholds/UpheldBy on
	// systemd 249/250 requires the separate trusted manager-dump gate.
	for _, key := range []string{"Upholds", "UpheldBy", "TriggeredBy", "Sockets"} {
		if values[key] != "" {
			return fmt.Errorf("foreign QUIC service dependency: %s", key)
		}
	}
	if value, present := values["TriggeredBy"]; !present || value != "" {
		return fmt.Errorf("QUIC service activation relationship is unverified")
	}
	// Sockets is not exported as a service D-Bus property on supported
	// managers. TriggeredBy is the effective relationship also used by
	// systemd's service_collect_fds; never infer socket absence from a
	// missing Sockets key or relax the required TriggeredBy receipt.
	// https://github.com/systemd/systemd/blob/v249/src/core/service.c
	// https://github.com/systemd/systemd/blob/v249/src/core/dbus-unit.c
	return nil
}

func verifyUnitVacant(v map[string]string, s unitSpec) error {
	if err := noForeignHooks(v); err != nil {
		return err
	}
	for key, want := range map[string]string{"Id": s.Name, "Names": s.Name, "LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "Transient": "no", "Description": s.Name, "FragmentPath": "", "Environment": "", "CollectMode": "inactive", "MainPID": "0", "ExecMainPID": "0", "Restart": "no", "NeedDaemonReload": "no"} {
		got, ok := v[key]
		if !ok || got != want {
			return fmt.Errorf("QUIC helper unit is present or vacancy is unverified")
		}
	}
	if v["ExecStart"] != "" || v["ExecStartEx"] != "" || v["InvocationID"] != "" || v["ControlGroup"] != "" {
		return fmt.Errorf("contradictory QUIC helper unit vacancy")
	}
	return nil
}

func matchesCommand(value string, s unitSpec, extended bool) bool {
	if !safeArgument(s.Binary) || len(s.Args) == 0 {
		return false
	}
	for _, a := range s.Args {
		if !safeArgument(a) {
			return false
		}
	}
	flags := "ignore_errors=no"
	if extended {
		flags = "flags="
	}
	prefix := "{ path=" + s.Binary + " ; argv[]=" + strings.Join(append([]string{s.Binary}, s.Args...), " ") + " ; " + flags + " ; "
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, " }") || strings.Count(value, "{") != 1 || strings.Count(value, "}") != 1 || strings.Count(value, "argv[]=") != 1 {
		return false
	}
	// Only the fixed runtime observation fields may follow argv/flags.
	rest := strings.TrimSuffix(strings.TrimPrefix(value, prefix), " }")
	fields := strings.Split(rest, " ; ")
	if len(fields) != 5 {
		return false
	}
	for i, key := range []string{"start_time=", "stop_time=", "pid=", "code=", "status="} {
		if !strings.HasPrefix(fields[i], key) {
			return false
		}
	}
	return true
}

func verifyUnitProperties(v map[string]string, s unitSpec) error {
	if err := noForeignHooks(v); err != nil {
		return err
	}
	for key, want := range map[string]string{"Id": s.Name, "Names": s.Name, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "Transient": "yes", "Description": s.Description, "FragmentPath": "/run/systemd/transient/" + s.Name, "UnitFileState": "transient", "NRestarts": "0", "NeedDaemonReload": "no"} {
		got, ok := v[key]
		if !ok || got != want {
			return fmt.Errorf("original QUIC unit identity differs: %s", key)
		}
	}
	for key, want := range specSecurityProperties(s) {
		got, ok := v[key]
		// systemctl 249's EnvironmentFiles a(sb) printer emits one line per
		// file and none for an empty array, even with --all. This exception is
		// specific to that typed property; all other security fields still
		// require explicit readback. Any observed file is forbidden.
		// https://github.com/systemd/systemd/blob/v249/src/systemctl/systemctl-show.c
		if key == "EnvironmentFiles" && !ok {
			continue
		}
		if !ok || got != want {
			return fmt.Errorf("original QUIC unit security differs: %s", key)
		}
	}
	if !matchesCommand(v["ExecStart"], s, false) || !matchesCommand(v["ExecStartEx"], s, true) {
		return fmt.Errorf("original QUIC unit executable or argv differs")
	}
	pid, err := strconv.Atoi(v["MainPID"])
	if err != nil || pid <= 1 || strconv.Itoa(pid) != v["MainPID"] || v["ExecMainPID"] != v["MainPID"] || (!canonicalHex(v["InvocationID"], 32) || strings.Trim(v["InvocationID"], "0") == "") || v["ControlGroup"] != "/system.slice/"+s.Name {
		return fmt.Errorf("original QUIC unit process identity is incomplete")
	}
	started, e := strconv.ParseUint(v["ExecMainStartTimestampMonotonic"], 10, 64)
	if e != nil || started == 0 || strconv.FormatUint(started, 10) != v["ExecMainStartTimestampMonotonic"] {
		return fmt.Errorf("original QUIC helper start timestamp is invalid")
	}
	return nil
}

func specSecurityProperties(s unitSpec) map[string]string {
	properties := make(map[string]string, len(securityProperties))
	for k, v := range securityProperties {
		properties[k] = v
	}
	if s.PrivilegedPort {
		properties["CapabilityBoundingSet"] = "cap_net_bind_service"
	}
	return properties
}
