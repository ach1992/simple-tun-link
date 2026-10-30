package quichelper

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
)

func testUnitSpec(t *testing.T) unitSpec {
	t.Helper()
	s, e := buildUnitSpec(quic.Plan{LinkID: fixtureID, Role: quic.Listen, Underlay: netip.MustParseAddrPort("198.51.100.60:443"), TLSName: "198.51.100.60", LocalWGUDPPort: 51820}, fixtureNonce, "/usr/local/libexec/stl/hysteria", "/var/lib/stl")
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func runningProperties(s unitSpec) map[string]string {
	v := specSecurityProperties(s)
	for k, value := range map[string]string{"Id": s.Name, "Names": s.Name, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "Transient": "yes", "Description": s.Description, "FragmentPath": "/run/systemd/transient/" + s.Name, "UnitFileState": "transient", "NRestarts": "0", "MainPID": "1234", "ExecMainPID": "1234", "InvocationID": strings.Repeat("a", 32), "ControlGroup": "/system.slice/" + s.Name, "ExecMainStartTimestampMonotonic": "123456", "NeedDaemonReload": "no", "Upholds": "", "UpheldBy": "", "TriggeredBy": ""} {
		v[k] = value
	}
	prefix := "{ path=" + s.Binary + " ; argv[]=" + strings.Join(append([]string{s.Binary}, s.Args...), " ") + " ; "
	suffix := " ; start_time=[Fri 2026-10-30 05:00:00 UTC] ; stop_time=[n/a] ; pid=1234 ; code=(null) ; status=0/0 }"
	v["ExecStart"] = prefix + "ignore_errors=no" + suffix
	v["ExecStartEx"] = prefix + "flags=" + suffix
	return v
}

func TestUnitReadbackRejectsForeignExecutionIdentityAndSecurity(t *testing.T) {
	s := testUnitSpec(t)
	if err := verifyUnitProperties(runningProperties(s), s); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, key, value string }{
		{"alias", "Names", s.Name + " other.service"}, {"generation", "Description", s.Description + "x"}, {"extra-start", "ExecStart", runningProperties(s)["ExecStart"] + " " + runningProperties(s)["ExecStart"]},
		{"privileged-flags", "ExecStartEx", strings.Replace(runningProperties(s)["ExecStartEx"], "flags=", "flags=privileged", 1)},
		{"pre-hook", "ExecStartPre", runningProperties(s)["ExecStart"]}, {"post-hook", "ExecStartPost", runningProperties(s)["ExecStart"]}, {"stop-hook", "ExecStopEx", runningProperties(s)["ExecStartEx"]},
		{"whitespace-hook", "ExecCondition", " "}, {"dropin", "DropInPaths", "/etc/systemd/system/service.d/foreign.conf"}, {"failure-trigger", "OnFailure", "foreign.service"},
		{"restart", "Restart", "on-failure"}, {"inherit-env", "PassEnvironment", "TOKEN"}, {"environment", "Environment", "SECRET=value"}, {"weak-sandbox", "NoNewPrivileges", "no"},
		{"incoming-upholder", "UpheldBy", "foreign.service"}, {"outgoing-upholder", "Upholds", "foreign.service"}, {"activation-trigger", "TriggeredBy", "foreign.socket"}, {"foreign-sockets", "Sockets", "foreign.socket"}, {"pending-reload", "NeedDaemonReload", "yes"}, {"automatic-stop", "StopWhenUnneeded", "yes"},
		{"pid", "MainPID", "01234"}, {"invocation", "InvocationID", strings.Repeat("0", 32)}, {"cgroup", "ControlGroup", "/system.slice/foreign.service"}, {"restarted", "NRestarts", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := runningProperties(s)
			v[tc.key] = tc.value
			if err := verifyUnitProperties(v, s); err == nil {
				t.Fatal("accepted foreign helper observation")
			}
		})
	}
	for _, key := range []string{"ExecStartEx", "Environment", "RootDirectory", "NoNewPrivileges", "InvocationID", "TriggeredBy", "NeedDaemonReload", "StopWhenUnneeded"} {
		t.Run("missing_"+key, func(t *testing.T) {
			v := runningProperties(s)
			delete(v, key)
			if err := verifyUnitProperties(v, s); err == nil {
				t.Fatal("accepted incomplete helper observation")
			}
		})
	}
}

func TestUnitSyntaxRejectsInterpolationAndPinsOnlyRequiredCapability(t *testing.T) {
	s := testUnitSpec(t)
	if !s.PrivilegedPort || specSecurityProperties(s)["CapabilityBoundingSet"] != "cap_net_bind_service" {
		t.Fatal("requested privileged listener capability missing")
	}
	p := quic.Plan{LinkID: fixtureID, Role: quic.Dial, Underlay: netip.MustParseAddrPort("198.51.100.60:443"), TLSName: "198.51.100.60", LocalForwardUDPPort: 52211, PeerWGUDPPort: 51820}
	noCap, e := buildUnitSpec(p, fixtureNonce, "/usr/local/libexec/stl/hysteria", "/var/lib/stl")
	if e != nil || noCap.PrivilegedPort || specSecurityProperties(noCap)["CapabilityBoundingSet"] != "" {
		t.Fatal("remote physical low port incorrectly granted local capability")
	}
	for _, bad := range []string{"/var/lib/$STATE", "/var/lib/%i", "/var/lib/with space", "/var/lib/quote\"", "/var/lib/slash\\"} {
		if _, e := buildUnitSpec(p, fixtureNonce, s.Binary, bad); e == nil {
			t.Fatalf("accepted expanding path %q", bad)
		}
	}
}

func TestManagerEnvironmentPolicyAndBoundedPropertyParser(t *testing.T) {
	for _, good := range []string{"", "LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C LC_ALL=C PATH=/usr/bin"} {
		if !safeManagerEnvironment(good) {
			t.Fatalf("rejected safe manager defaults: %q", good)
		}
	}
	for _, bad := range []string{"LD_PRELOAD=/tmp/foreign", "PATH=/usr/bin LANG=C GODEBUG=foreign", "LANG=C LANG=en_US", "PATH=\"/usr/bin with spaces\"", "HYSTERIA_PASSWORD=secret"} {
		if safeManagerEnvironment(bad) {
			t.Fatal("accepted ambiguous or behavior-changing manager environment")
		}
	}
	for _, bad := range []string{"", "A=1", "A=1\nA=2\n", "broken\n", strings.Repeat("a", (64<<10)+1)} {
		if _, e := parseProperties([]byte(bad)); e == nil {
			t.Fatal("accepted incomplete/ambiguous property stream")
		}
	}
}

func TestProcStatParserHandlesSpacesAndRejectsDeadOrMissingIdentity(t *testing.T) {
	fields := []string{"S", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "12345", "20"}
	raw := "1234 (name with ) parentheses) " + strings.Join(fields, " ") + "\n"
	got, err := parseStartTime([]byte(raw), 1234)
	if err != nil || got != 12345 {
		t.Fatalf("valid proc stat failed: %d %v", got, err)
	}
	for _, bad := range []string{strings.Replace(raw, " S ", " Z ", 1), strings.Replace(raw, "12345", "0", 1), "1234 (x) S 1 2\n", strings.Replace(raw, "1234 (", "4321 (", 1)} {
		if _, e := parseStartTime([]byte(bad), 1234); e == nil {
			t.Fatal("accepted dead or wrong process stat")
		}
	}
}

func TestUnitSearchTrustAcceptsRootControlledUsrMergeAliases(t *testing.T) {
	checked := false
	for _, path := range []string{"/bin", "/sbin", "/lib"} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if err := trustedDirectoryChain(path); err != nil {
			t.Fatalf("trusted usrmerge alias rejected: %v", err)
		}
		checked = true
	}
	if !checked {
		t.Skip("host has no usrmerge alias fixture")
	}
	if err := trustedDirectoryChain("/tmp"); err == nil {
		t.Fatal("accepted writable unit search ancestor")
	}
}

func TestManagerSGXContextRequiresPreExecRemovalAndCannotReachChild(t *testing.T) {
	// Synthetic value only: do not inspect or report a runner's actual SGX
	// environment value. The contract binds the variable name and its removal.
	const syntheticValue = "test-only-manager-context"
	if !safeManagerEnvironment("LANG=C PATH=/usr/bin SGX_AESM_ADDR=" + syntheticValue) {
		t.Fatal("explicitly removed manager context rejected")
	}
	spec := testUnitSpec(t)
	values := runningProperties(spec)
	if err := verifyUnitProperties(values, spec); err != nil {
		t.Fatal(err)
	}
	values["UnsetEnvironment"] = strings.Replace(values["UnsetEnvironment"], " SGX_AESM_ADDR", "", 1)
	if err := verifyUnitProperties(values, spec); err == nil {
		t.Fatal("SGX manager context admitted without mandatory pre-exec removal")
	}
	prefix := t.TempDir()
	invocation := strings.Repeat("a", 32)
	clean := []byte("PATH=/usr/sbin:/usr/bin:/sbin:/bin\x00LANG=C\x00LC_ALL=C\x00LC_CTYPE=C\x00INVOCATION_ID=" + invocation + "\x00")
	path := filepath.Join(prefix, "environ")
	if err := os.WriteFile(path, clean, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyProcessEnvironment(prefix, invocation); err != nil {
		t.Fatal(err)
	}
	contaminated := append(append([]byte(nil), clean...), []byte("SGX_AESM_ADDR="+syntheticValue+"\x00")...)
	if err := os.WriteFile(path, contaminated, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyProcessEnvironment(prefix, invocation); err == nil || strings.Contains(err.Error(), syntheticValue) {
		t.Fatalf("removed manager value survived process verification or leaked: %v", err)
	}
}

func TestEnvironmentFilesEmptyArrayOmissionOnly(t *testing.T) {
	spec := testUnitSpec(t)
	values := runningProperties(spec)
	delete(values, "EnvironmentFiles")
	if err := verifyUnitProperties(values, spec); err != nil {
		t.Fatalf("systemctl empty tuple-array omission rejected: %v", err)
	}
	for _, foreign := range []string{"/run/foreign.env (ignore_errors=no)", "/run/foreign.env (ignore_errors=yes)", " "} {
		values["EnvironmentFiles"] = foreign
		if err := verifyUnitProperties(values, spec); err == nil {
			t.Fatal("observed foreign EnvironmentFile accepted")
		}
	}
	delete(values, "EnvironmentFiles")
	delete(values, "RootDirectory")
	if err := verifyUnitProperties(values, spec); err == nil {
		t.Fatal("EnvironmentFiles exception weakened unrelated mandatory empty property")
	}
}
