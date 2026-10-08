package linux

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func trustedSystemdTree() map[string]fakeInstallInfo {
	return map[string]fakeInstallInfo{
		"/":                   {path: "/", mode: fs.ModeDir | 0o755},
		"/etc":                {path: "/etc", mode: fs.ModeDir | 0o755},
		"/etc/systemd":        {path: "/etc/systemd", mode: fs.ModeDir | 0o755},
		"/etc/systemd/system": {path: "/etc/systemd/system", mode: fs.ModeDir | 0o755},
		"/etc/systemd/system/" + restoreSystemdUnitName: {
			path: "/etc/systemd/system/" + restoreSystemdUnitName,
			mode: 0o644,
		},
	}
}

func TestRootOwnedUnitAndDirectoryChainTrustMatrix(t *testing.T) {
	unit := "/etc/systemd/system/" + restoreSystemdUnitName
	cases := []struct {
		name   string
		alter  func(map[string]fakeInstallInfo)
		path   string
		accept bool
	}{
		{name: "root owned regular protected", path: unit, accept: true},
		{name: "new unit in protected directory", path: unit, alter: func(m map[string]fakeInstallInfo) { delete(m, unit) }, accept: true},
		{name: "non-root owned matching contents", path: unit, alter: func(m map[string]fakeInstallInfo) { f := m[unit]; f.uid = 1001; m[unit] = f }},
		{name: "group writable unit", path: unit, alter: func(m map[string]fakeInstallInfo) { f := m[unit]; f.mode = 0o664; m[unit] = f }},
		{name: "world writable unit", path: unit, alter: func(m map[string]fakeInstallInfo) { f := m[unit]; f.mode = 0o646; m[unit] = f }},
		{name: "non-root owned unit directory", path: unit, alter: func(m map[string]fakeInstallInfo) { f := m["/etc/systemd/system"]; f.uid = 1001; m[f.path] = f }},
		{name: "group writable unit directory", path: unit, alter: func(m map[string]fakeInstallInfo) {
			f := m["/etc/systemd/system"]
			f.mode = fs.ModeDir | 0o775
			m[f.path] = f
		}},
		{name: "world writable parent", path: unit, alter: func(m map[string]fakeInstallInfo) { f := m["/etc"]; f.mode = fs.ModeDir | 0o777; m[f.path] = f }},
		{name: "symlinked parent", path: unit, alter: func(m map[string]fakeInstallInfo) {
			f := m["/etc/systemd"]
			f.mode = fs.ModeSymlink | 0o777
			m[f.path] = f
		}},
		{name: "symlinked leaf", path: unit, alter: func(m map[string]fakeInstallInfo) { f := m[unit]; f.mode = fs.ModeSymlink | 0o777; m[unit] = f }},
		{name: "directory masquerades as leaf", path: unit, alter: func(m map[string]fakeInstallInfo) { f := m[unit]; f.mode = fs.ModeDir | 0o755; m[unit] = f }},
		{name: "relative unit", path: restoreSystemdUnitName},
		{name: "wrong basename", path: "/etc/systemd/system/other.service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := trustedSystemdTree()
			if tc.alter != nil {
				tc.alter(tree)
			}
			inspect := func(path string) (fs.FileInfo, error) {
				info, ok := tree[path]
				if !ok {
					return nil, os.ErrNotExist
				}
				return info, nil
			}
			err := verifyTrustedSystemdUnitPath(tc.path, inspect)
			if (err == nil) != tc.accept {
				t.Fatalf("accepted=%t want=%t err=%v", err == nil, tc.accept, err)
			}
		})
	}
}

func TestUnsafeUnitOwnershipBlocksRealEnsureBeforeSystemctl(t *testing.T) {
	unitDir := t.TempDir()
	path := filepath.Join(unitDir, restoreSystemdUnitName)
	unit, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	// Exercise the leaf-ownership branch itself, not an unrelated /tmp
	// ancestor failure: synthesize trusted root-owned parents while marking
	// the exact existing unit inode as unprivileged.
	tree := map[string]fakeInstallInfo{}
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		tree[current] = fakeInstallInfo{path: current, mode: fs.ModeDir | 0o755}
		if current == "/" {
			break
		}
	}
	tree[path] = fakeInstallInfo{path: path, mode: 0o644, uid: 1001}
	inspect := func(name string) (fs.FileInfo, error) {
		info, ok := tree[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}
	runner := &recordingRunner{}
	manager := SystemdPersistence{
		Runner: runner, UnitDir: unitDir,
		VerifyExecutable: func(string) error { return nil },
		VerifyUnitPath: func(path string) error {
			return verifyTrustedSystemdUnitPath(path, inspect)
		},
	}
	_, _, err = manager.EnsureRestore(t.Context(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "not proven root-owned") {
		t.Fatalf("untrusted leaf UID was not rejected by the actual trust decision: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("unsafe unit caused systemctl mutation: %v", runner.commands)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != unit {
		t.Fatalf("untrusted unit was modified: %q %v", content, readErr)
	}
}

func TestUnitDirectoryCreationRejectsUnsafeAncestor(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "new", "units")
	// Even if the missing leaf itself could be created root-owned, a
	// preexisting user-owned ancestor must be rejected before MkdirAll.
	manager := SystemdPersistence{
		Runner: &recordingRunner{}, UnitDir: dir,
		VerifyExecutable: func(string) error { return nil },
	}
	_, _, err := manager.EnsureRestore(t.Context(), "/usr/local/bin/stl")
	if err == nil || !strings.Contains(err.Error(), "unsafe systemd restore unit directory") {
		t.Fatalf("unsafe existing ancestor accepted: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "new")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsafe ancestor resulted in new directory creation: %v", statErr)
	}
}

// This exercises the *actual EnsureRestore trust boundary*, including
// verification before systemctl enable. A fake Lstat supplies root UID
// metadata only because unprivileged CI cannot create root-owned fixtures.
func TestExistingUnitTrustIsCheckedBeforePrivilegedActivation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(map[string]fakeInstallInfo, string)
		allowed bool
	}{
		{name: "protected root owned existing unit", allowed: true},
		{name: "matching text but non-root file", edit: func(m map[string]fakeInstallInfo, p string) {
			f := m[p]
			f.uid = 1001
			m[p] = f
		}},
		{name: "matching text but group writable file", edit: func(m map[string]fakeInstallInfo, p string) {
			f := m[p]
			f.mode = 0o664
			m[p] = f
		}},
		{name: "matching text but world writable file", edit: func(m map[string]fakeInstallInfo, p string) {
			f := m[p]
			f.mode = 0o666
			m[p] = f
		}},
		{name: "matching text but unprivileged unit directory", edit: func(m map[string]fakeInstallInfo, p string) {
			parent := filepath.Dir(p)
			f := m[parent]
			f.uid = 1001
			m[parent] = f
		}},
		{name: "matching text but writable grandparent", edit: func(m map[string]fakeInstallInfo, p string) {
			parent := filepath.Dir(filepath.Dir(p))
			f := m[parent]
			f.mode = fs.ModeDir | 0o777
			m[parent] = f
		}},
		{name: "matching text but symlinked parent", edit: func(m map[string]fakeInstallInfo, p string) {
			parent := filepath.Dir(p)
			f := m[parent]
			f.mode = fs.ModeSymlink | 0o777
			m[parent] = f
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, restoreSystemdUnitName)
			unit, err := renderRestoreSystemdUnit("/usr/local/bin/stl")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
				t.Fatal(err)
			}
			tree := map[string]fakeInstallInfo{path: {path: path, mode: 0o644}}
			for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
				tree[parent] = fakeInstallInfo{path: parent, mode: fs.ModeDir | 0o755}
				if parent == "/" {
					break
				}
			}
			if tc.edit != nil {
				tc.edit(tree, path)
			}
			inspect := func(name string) (fs.FileInfo, error) {
				info, ok := tree[name]
				if !ok {
					return nil, os.ErrNotExist
				}
				return info, nil
			}
			runner := &recordingRunner{}
			manager := SystemdPersistence{
				Runner: runner, UnitDir: dir,
				VerifyExecutable: func(string) error { return nil },
				VerifyUnitPath: func(p string) error {
					return verifyTrustedSystemdUnitPath(p, inspect)
				},
			}
			_, _, err = manager.EnsureRestore(t.Context(), "/usr/local/bin/stl")
			if (err == nil) != tc.allowed {
				t.Fatalf("accepted=%t want=%t err=%v", err == nil, tc.allowed, err)
			}
			if tc.allowed {
				if !runner.enabled[restoreSystemdUnitName] {
					t.Fatal("trusted existing unit was not enabled")
				}
			} else if len(runner.commands) != 0 {
				t.Fatalf("untrusted unit reached systemctl: %v", runner.commands)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || string(got) != unit {
				t.Fatalf("unit contents mutated on trust validation: %q %v", got, readErr)
			}
		})
	}
}
