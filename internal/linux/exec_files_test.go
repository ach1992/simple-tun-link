package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This uses synthetic fixture data only: inherited file descriptors must
// reach the child without putting their bytes into argv or generic errors.
func TestExecRunnerPassesVerifiedFileDescriptorWithoutSecretArgv(t *testing.T) {
	folder := t.TempDir()
	name := filepath.Join(folder, "private-fixture")
	const value = "synthetic-private-input-not-a-real-key"
	if err := os.WriteFile(name, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	result, err := (ExecRunner{}).RunWithFiles(context.Background(), "cat", []*os.File{fd}, "/proc/self/fd/3")
	if err != nil {
		t.Fatalf("cannot inherit read-only FD: %v", err)
	}
	if string(result.Stdout) != value || len(result.Stderr) != 0 {
		t.Fatal("child did not receive only verified FD content")
	}
	if _, err := (ExecRunner{}).RunWithFiles(context.Background(), "false", []*os.File{fd}); err == nil || strings.Contains(err.Error(), value) {
		t.Fatal("failed subprocess error leaked inherited secret contents")
	}
}
