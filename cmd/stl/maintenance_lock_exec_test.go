package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalShellInstallerLockSurvivesGoChildExec(t *testing.T) {
	if os.Getenv("STL_TEST_LOCK_CHILD") == "1" {
		path := os.Getenv("STL_TEST_LOCK_PATH")
		if err := installerLockInherited(9, path); err != nil {
			t.Fatalf("canonical Bash exclusive lock did not survive exec: %v", err)
		}
		return
	}
	lock := filepath.Join(t.TempDir(), "install.lock")
	cmd := exec.Command("/bin/bash", "-c",
		`exec 9>>"$1"; flock -x -w 2 9; "$2" -test.run='^TestCanonicalShellInstallerLockSurvivesGoChildExec$'`,
		"stl-bash", lock, os.Args[0])
	cmd.Env = append(os.Environ(), "STL_TEST_LOCK_CHILD=1", "STL_TEST_LOCK_PATH="+lock)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS:") && !strings.Contains(string(out), "PASS") {
		t.Fatalf("Bash child canonical FD9 inheritance unverified: err=%v output=%q", err, string(out))
	}
}
