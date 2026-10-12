package ipsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeExecutableTrustRejectsNonRootOwnedMode0755(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged unit test; positive root-owned admission exercised in isolated PID1 systemd E2E")
	}
	dir := t.TempDir()
	executable := filepath.Join(dir, "charon-systemd")
	if err := os.WriteFile(executable, []byte("fixture"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatal("test precondition: 0755 mode missing")
	}
	if rootControlledExecutableMetadata(info, false) {
		t.Fatal("non-root-owned executable accepted")
	}
	if err := verifyTrustedNativeExecutable(executable, executable); err == nil {
		t.Fatal("non-root process file admitted as privileged strongSwan executable")
	}
}

func TestNativeExecutableTrustRejectsWritableParentsAndInvalidTypes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rootControlledExecutableMetadata(info, true) {
		t.Fatal("world-writable executable ancestor trusted")
	}
	f := filepath.Join(dir, "program")
	if err := os.WriteFile(f, []byte("test"), 0755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(f)
	if err != nil {
		t.Fatal(err)
	}
	if rootControlledExecutableMetadata(fi, true) {
		t.Fatal("regular file trusted as directory")
	}
	err = verifyTrustedNativeExecutable(f, f)
	if err == nil || (!strings.Contains(err.Error(), "ancestry") && !strings.Contains(err.Error(), "origin")) {
		t.Fatalf("unsafe ancestry accepted: %v", err)
	}
}
