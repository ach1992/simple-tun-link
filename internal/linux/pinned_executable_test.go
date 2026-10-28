package linux

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedExecutableRejectsUnsafeFilesAndProvesIdentity(t *testing.T) {
	folder := t.TempDir()
	path := filepath.Join(folder, "helper")
	raw := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(path, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	got, err := InspectPinnedExecutable(path, hash)
	if err != nil || got.SHA256 != hash || got.Inode == 0 {
		t.Fatalf("pinned identity not verified: %+v %v", got, err)
	}
	deny := func(name, p, pin string) {
		t.Helper()
		if _, err := InspectPinnedExecutable(p, pin); err == nil {
			t.Fatalf("%s admitted unsafe or unpinned executable", name)
		}
	}
	deny("untrusted-hash", path, strings.Repeat("0", 64))
	deny("relative", "helper", hash)
	deny("noncanonical", filepath.Join(folder, "..", filepath.Base(folder), "helper")+"//", hash)
	deny("nonhex-hash", path, strings.Repeat("G", 64))
	link := filepath.Join(folder, "helper-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	deny("symlink", link, hash)
	hard := filepath.Join(folder, "helper-hard")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	deny("hardlink", path, hash)
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	deny("writable-executable", path, hash)
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(folder, 0o777); err != nil {
		t.Fatal(err)
	}
	deny("writable-parent", path, hash)
	if err := os.Chmod(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '#'), 0o700); err != nil {
		t.Fatal(err)
	}
	deny("mutated-content", path, hash)
}
