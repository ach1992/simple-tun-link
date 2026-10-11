package ipsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nativeFixturePath = "var/lib/simple-tun-link/ipsec/strongswan.conf"

// This uses a private fake filesystem root and the test runner's UID. The
// production entry point is fixed to the actual host root and UID 0.
func nativeConfigFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "var/lib/simple-tun-link/ipsec")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, nativeFixturePath)
	if err := os.WriteFile(path, NativeExclusiveConfigV1(), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, path
}

func nativeFixtureResult(root string) NativeConfigAssessment {
	return inspectNativeConfigAt(root, nativeFixturePath, uint32(os.Geteuid()), nil)
}

func TestNativeConfigArtifactRequiresExactProtectedPathAndBytes(t *testing.T) {
	t.Run("exact protected source bytes are observational only", func(t *testing.T) {
		root, _ := nativeConfigFixture(t)
		if got := nativeFixtureResult(root); got != NativeConfigExact {
			t.Fatalf("expected exact byte observation, got %s", got)
		}
	})
	t.Run("missing file is not provisioned", func(t *testing.T) {
		root, path := nativeConfigFixture(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if got := nativeFixtureResult(root); got != NativeConfigMissing {
			t.Fatalf("missing config was not rejected: %s", got)
		}
	})
	t.Run("missing private directory is not provisioned", func(t *testing.T) {
		root := t.TempDir()
		if got := nativeFixtureResult(root); got != NativeConfigMissing {
			t.Fatalf("missing private chain was accepted: %s", got)
		}
	})
	t.Run("same-size changed logging policy is conflict", func(t *testing.T) {
		root, path := nativeConfigFixture(t)
		content := NativeExclusiveConfigV1()
		needle := []byte("cfg = 1")
		if !strings.Contains(string(content), string(needle)) {
			t.Fatal("fixture policy missing")
		}
		content = []byte(strings.Replace(string(content), "cfg = 1", "cfg = 4", 1))
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := nativeFixtureResult(root); got != NativeConfigConflict {
			t.Fatalf("unsafe logging was accepted: %s", got)
		}
	})
	t.Run("unsafe file mode", func(t *testing.T) {
		root, path := nativeConfigFixture(t)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if got := nativeFixtureResult(root); got != NativeConfigConflict {
			t.Fatalf("group readable config was accepted: %s", got)
		}
	})
	t.Run("hardlinked file is not exclusive identity", func(t *testing.T) {
		root, path := nativeConfigFixture(t)
		if err := os.Link(path, path+".alias"); err != nil {
			t.Fatal(err)
		}
		if got := nativeFixtureResult(root); got != NativeConfigConflict {
			t.Fatalf("hardlink alias was accepted: %s", got)
		}
	})
	t.Run("symlinked config is not followed", func(t *testing.T) {
		root, path := nativeConfigFixture(t)
		if err := os.Rename(path, path+".foreign"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path+".foreign", path); err != nil {
			t.Fatal(err)
		}
		if got := nativeFixtureResult(root); got != NativeConfigConflict {
			t.Fatalf("symlink was accepted: %s", got)
		}
	})
	t.Run("symlinked parent is not followed", func(t *testing.T) {
		root, path := nativeConfigFixture(t)
		dir := filepath.Dir(path)
		if err := os.Rename(dir, dir+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dir+".moved", dir); err != nil {
			t.Fatal(err)
		}
		if got := nativeFixtureResult(root); got != NativeConfigConflict {
			t.Fatalf("symlinked directory was accepted: %s", got)
		}
	})
	t.Run("private parent must remain private", func(t *testing.T) {
		root, path := nativeConfigFixture(t)
		if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := nativeFixtureResult(root); got != NativeConfigConflict {
			t.Fatalf("nonprivate config directory was accepted: %s", got)
		}
	})
	t.Run("non-owner cannot attest any root", func(t *testing.T) {
		root, _ := nativeConfigFixture(t)
		if got := inspectNativeConfigAt(root, nativeFixturePath, uint32(os.Geteuid()+1), nil); got != NativeConfigConflict {
			t.Fatalf("wrong owner was trusted: %s", got)
		}
	})
}

func TestNativeConfigArtifactRejectsRacingReplacementEvenWithSameBytes(t *testing.T) {
	root, path := nativeConfigFixture(t)
	got := inspectNativeConfigAt(root, nativeFixturePath, uint32(os.Geteuid()), func() {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, NativeExclusiveConfigV1(), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if got != NativeConfigConflict {
		t.Fatalf("post-read inode replacement adopted: %s", got)
	}
	if got := nativeFixtureResult(root); got != NativeConfigExact {
		t.Fatalf("new observed bytes should not imply historical ownership: %s", got)
	}
}

func TestNativeConfigArtifactRejectsRacingParentReplacement(t *testing.T) {
	root, path := nativeConfigFixture(t)
	dir := filepath.Dir(path)
	got := inspectNativeConfigAt(root, nativeFixturePath, uint32(os.Geteuid()), func() {
		if err := os.Rename(dir, dir+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "strongswan.conf"), NativeExclusiveConfigV1(), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if got != NativeConfigConflict {
		t.Fatalf("post-read private directory replacement adopted: %s", got)
	}
}

func TestNativeConfigArtifactRejectsParentPermissionDrift(t *testing.T) {
	root, path := nativeConfigFixture(t)
	parent := filepath.Dir(path)
	got := inspectNativeConfigAt(root, nativeFixturePath, uint32(os.Geteuid()), func() {
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatal(err)
		}
	})
	if got != NativeConfigConflict {
		t.Fatalf("trusted parent made public mid-read: %s", got)
	}
}

func TestNativeConfigArtifactRejectsUnsafeParameters(t *testing.T) {
	root := t.TempDir()
	for _, candidate := range []string{"", "../escape", "/etc/strongswan.conf", "var//lib/file", "./var/lib/file"} {
		if got := inspectNativeConfigAt(root, candidate, uint32(os.Geteuid()), nil); got != NativeConfigUnverified {
			t.Fatalf("unexpected assessment %s for invalid relative path %q", got, candidate)
		}
	}
}
