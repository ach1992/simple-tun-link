package linux

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeInstallInfo struct {
	path string
	mode fs.FileMode
	uid  uint32
}

func (i fakeInstallInfo) Name() string       { return filepath.Base(i.path) }
func (i fakeInstallInfo) Size() int64        { return 1 }
func (i fakeInstallInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInstallInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInstallInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInstallInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func trustedInstallTree() map[string]fakeInstallInfo {
	return map[string]fakeInstallInfo{
		"/":                  {path: "/", mode: fs.ModeDir | 0o755},
		"/usr":               {path: "/usr", mode: fs.ModeDir | 0o755},
		"/usr/local":         {path: "/usr/local", mode: fs.ModeDir | 0o755},
		"/usr/local/bin":     {path: "/usr/local/bin", mode: fs.ModeDir | 0o755},
		"/usr/local/bin/stl": {path: "/usr/local/bin/stl", mode: 0o755},
	}
}

func TestTrustedInstalledExecutablePathValidation(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]fakeInstallInfo)
		path   string
		pass   bool
	}{
		{"trusted canonical", nil, "/usr/local/bin/stl", true},
		{"other basename", nil, "/usr/local/bin/stlink", false},
		{"relative executable", nil, "stl", false},
		{"noncanonical path", nil, "/usr/local/bin/../bin/stl", false},
		{"unprivileged executable", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local/bin/stl"]
			f.uid = 1000
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
		{"group writable executable", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local/bin/stl"]
			f.mode = 0o775
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
		{"world writable parent", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local/bin"]
			f.mode = fs.ModeDir | 0o777
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
		{"unprivileged parent owner", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local"]
			f.uid = 1000
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
		{"symlink canonical", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local/bin/stl"]
			f.mode = fs.ModeSymlink | 0o777
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
		{"symlink parent", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local/bin"]
			f.mode = fs.ModeSymlink | 0o777
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
		{"not executable", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local/bin/stl"]
			f.mode = 0o644
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
		{"not regular", func(m map[string]fakeInstallInfo) {
			f := m["/usr/local/bin/stl"]
			f.mode = fs.ModeDir | 0o755
			m[f.path] = f
		}, "/usr/local/bin/stl", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := trustedInstallTree()
			if tc.change != nil {
				tc.change(tree)
			}
			inspect := func(path string) (fs.FileInfo, error) {
				info, ok := tree[path]
				if !ok {
					return nil, os.ErrNotExist
				}
				return info, nil
			}
			err := verifyTrustedSTLExecutable(tc.path, inspect)
			if (err == nil) != tc.pass {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.pass, err)
			}
		})
	}
}

func TestUntrustedExecutableRejectedBeforeAnyUnitSideEffect(t *testing.T) {
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "stl")
	if err := os.WriteFile(bin, []byte("not a root-owned installation"), 0o755); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(t.TempDir(), "units")
	runner := &recordingRunner{}
	manager := SystemdPersistence{Runner: runner, UnitDir: unitDir}
	_, _, err := manager.EnsureRestore(t.Context(), bin)
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("untrusted executable was accepted: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("systemctl was invoked for untrusted executable: %v", runner.commands)
	}
	if _, err := os.Stat(unitDir); !os.IsNotExist(err) {
		t.Fatalf("unit directory mutated: %v", err)
	}
}
