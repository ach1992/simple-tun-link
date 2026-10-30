package quichelper

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func managedTestSpec(t *testing.T) unitSpec {
	t.Helper()
	f := newOriginFixture(t)
	s, err := buildManagedUnitSpec(f.plan, fixtureNonce, "/usr/local/libexec/stl/hysteria", f.root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func managedRunningProperties(s unitSpec) map[string]string {
	v := runningProperties(s)
	for key, value := range managedSecurityProperties(s) {
		v[key] = value
	}
	v["Result"], v["ExecMainCode"], v["ExecMainStatus"] = "success", "0", "0"
	return v
}

func TestManagedUnitAllowsOwnedRestartPolicyWithoutPromotingSourceOnly(t *testing.T) {
	s := managedTestSpec(t)
	if strings.Contains(s.Binary, "/proc/") || !strings.Contains(strings.Join(s.Args, " "), "--log-format json") {
		t.Fatal("managed launch does not survive launcher exit with fixed JSON output")
	}
	v := managedRunningProperties(s)
	v["NRestarts"] = "4"
	if err := verifyManagedUnitProperties(v, s, true); err != nil {
		t.Fatal(err)
	}
	if err := verifyUnitProperties(v, s); err == nil {
		t.Fatal("managed restart policy entered original source-only contract")
	}
	original := testUnitSpec(t)
	if err := verifyManagedUnitProperties(runningProperties(original), s, false); err == nil {
		t.Fatal("source-only unit was promoted into managed generation")
	}
	v["ActiveState"], v["SubState"], v["MainPID"] = "failed", "failed", "0"
	v["Result"], v["ExecMainCode"], v["ExecMainStatus"] = "exit-code", "1", "1"
	if err := verifyManagedUnitProperties(v, s, false); err != nil {
		t.Fatal("owned failed unit could not be diagnosed/stopped:", err)
	}
	if err := verifyManagedUnitProperties(v, s, true); err == nil {
		t.Fatal("failed unit counted as running")
	}
}

func TestManagedUnitRejectsForeignRestartAuthorityHooksAndIncompleteIdentity(t *testing.T) {
	s := managedTestSpec(t)
	for _, change := range []struct{ key, value string }{
		{"Description", s.Description + "x"}, {"ExecStartPre", "foreign command"}, {"ExecStopPostEx", "foreign command"},
		{"Restart", "always"}, {"RestartUSec", "1s"}, {"UpheldBy", "foreign.service"}, {"Upholds", "foreign.service"},
		{"TriggeredBy", "foreign.socket"}, {"NeedDaemonReload", "yes"}, {"StandardError", "null"}, {"EnvironmentFiles", "/tmp/foreign"},
		{"UnsetEnvironment", ""}, {"PassEnvironment", "SECRET"}, {"ControlGroup", "/foreign"}, {"NRestarts", "-1"},
	} {
		t.Run(change.key, func(t *testing.T) {
			v := managedRunningProperties(s)
			v[change.key] = change.value
			if verifyManagedUnitProperties(v, s, true) == nil {
				t.Fatal("foreign property admitted")
			}
		})
	}
	for _, key := range []string{"RestartUSec", "TriggeredBy", "Environment", "InvocationID", "ExecStartEx", "StandardError"} {
		v := managedRunningProperties(s)
		delete(v, key)
		if verifyManagedUnitProperties(v, s, true) == nil {
			t.Fatal("missing managed property admitted:", key)
		}
	}
	v := managedRunningProperties(s)
	delete(v, "EnvironmentFiles")
	if err := verifyManagedUnitProperties(v, s, true); err != nil {
		t.Fatal("known249 empty tuple omission rejected:", err)
	}
}

func TestManagedJournalEnvironmentBindsRealInheritedSocketAndRejectsSecrets(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	var st unix.Stat_t
	if unix.Fstat(pair[0], &st) != nil {
		t.Fatal("socket stat failed")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/fd/"+strconv.Itoa(pair[0]), filepath.Join(root, "fd", "2")); err != nil {
		t.Fatal(err)
	}
	invocation := strings.Repeat("a", 32)
	stream := strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10)
	base := "PATH=/usr/sbin:/usr/bin:/sbin:/bin\x00LANG=C\x00LC_ALL=C\x00LC_CTYPE=C\x00INVOCATION_ID=" + invocation + "\x00"
	for _, tc := range []struct {
		name, env string
		good      bool
	}{
		{"exact", base + "JOURNAL_STREAM=" + stream + "\x00", true},
		{"missing", base, false}, {"wrong-stream", base + "JOURNAL_STREAM=1:2\x00", false},
		{"secret", base + "JOURNAL_STREAM=" + stream + "\x00HYSTERIA_PASSWORD=secret\x00", false},
		{"duplicate", base + "JOURNAL_STREAM=" + stream + "\x00JOURNAL_STREAM=" + stream + "\x00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(root, "environ"), []byte(tc.env), 0o600); err != nil {
				t.Fatal(err)
			}
			err := verifyProcessEnvironmentPolicy(root, invocation, true)
			if (err == nil) != tc.good {
				t.Fatalf("environment decision differs: %v", err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(root, "environ"), []byte(base+"JOURNAL_STREAM="+stream+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if verifyProcessEnvironment(root, invocation) == nil {
		t.Fatal("source-only null-stream policy silently weakened")
	}
}

func TestManagedLoadedFragmentAllowanceDoesNotAllowReverseEdgesOrAliases(t *testing.T) {
	root := t.TempDir()
	name := "stl-quic-owned.service"
	if err := os.WriteFile(filepath.Join(root, name), []byte("exact transient fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func() error {
		f, err := os.Open(root)
		if err != nil {
			return err
		}
		defer f.Close()
		return inspectUnitReferenceDirectoryPolicy(context.Background(), f, name, true, uint32(os.Geteuid()), true)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "foreign.upholds"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../"+name, filepath.Join(root, "foreign.upholds", name)); err != nil {
		t.Fatal(err)
	}
	if check() == nil {
		t.Fatal("owned fragment allowance hid reverse upholder")
	}
	if err := os.Remove(filepath.Join(root, "foreign.upholds", name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(name, filepath.Join(root, "alias.service")); err != nil {
		t.Fatal(err)
	}
	if check() == nil {
		t.Fatal("owned fragment allowance hid foreign alias")
	}
}
