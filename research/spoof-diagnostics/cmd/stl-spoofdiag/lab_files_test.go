package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOversizedInputsAndSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "sources.json")
	// A previously bounded decoder accepted a valid short object followed by
	// >4 MiB of padding; file size must be checked before parsing.
	data := `{"schema_version":1,"mode":"private_lab","candidates":[{"ip":"10.2.3.4","direction":"A_TO_B","sender":"A","receiver":"B"}]}`
	data += strings.Repeat(" ", 4<<20)
	if err := os.WriteFile(source, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCandidates(source); err == nil {
		t.Fatal("oversized candidate inventory accepted")
	}
	reportFile := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(reportFile, append([]byte(`{"schema_version":1,"observations":[]}`), []byte(strings.Repeat(" ", 8<<20))...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := report(reportFile); err == nil {
		t.Fatal("oversized evidence accepted")
	}
	good := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(good, []byte(`{"schema_version":1,"mode":"private_lab","candidates":[{"ip":"10.2.3.4","direction":"A_TO_B","sender":"A","receiver":"B"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCandidates(link); err == nil {
		t.Fatal("symlinked source list accepted")
	}
}

func TestPrivateKeyPermissionRefusal(t *testing.T) {
	dir, _ := testLabCredentials(t)
	key := filepath.Join(dir, "A.key")
	cert := filepath.Join(dir, "A.crt")
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLabCredential(cert, key); err == nil {
		t.Fatal("world-readable signing key accepted")
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLabCredential(cert, key); err != nil {
		t.Fatal(err)
	}
}
