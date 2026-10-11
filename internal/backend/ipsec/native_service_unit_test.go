package ipsec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nativeUnitFixturePath = "etc/systemd/system/simple-tun-link-ipsec.service"

func nativeUnitFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, nativeUnitFixturePath)
	if err := os.WriteFile(path, NativeExclusiveServiceUnitV1(), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, path
}

func inspectNativeUnitFixture(root string) NativeServiceUnitAssessment {
	return inspectNativeServiceUnitAt(root, uint32(os.Geteuid()), nil)
}

func TestNativeExclusiveServiceUnitHasSafeStandaloneControlBoundary(t *testing.T) {
	content := NativeExclusiveServiceUnitV1()
	text := string(content)
	for _, required := range []string{
		"Type=notify", "ExecStart=/usr/sbin/charon-systemd",
		"Environment=STRONGSWAN_CONF=" + NativeExclusiveConfigPath,
		"RuntimeDirectory=simple-tun-link/ipsec", "RuntimeDirectoryMode=0700",
		"UMask=0077", "Restart=no",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("native service unit missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"ExecReload=", "ExecStartPost=", "ExecStartPre=", "--load-all",
		"--reload", "EnvironmentFile=", "PassEnvironment=", "Alias=",
		"WantedBy=", "[Install]", "swanctl", "strongswan.service",
		"PSK=", "private_key=",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unsafe or premature native service behavior: %s", forbidden)
		}
	}
	if NativeExclusiveServiceUnitPath != "/etc/systemd/system/simple-tun-link-ipsec.service" {
		t.Fatal("unexpected native-exclusive unit path")
	}
	if err := CheckNativeExclusiveServiceUnitV1(content); err != nil {
		t.Fatal(err)
	}
	content[0] = '!'
	if bytes.Equal(content, NativeExclusiveServiceUnitV1()) {
		t.Fatal("returned unit bytes alias mutable global data")
	}
}

func TestNativeExclusiveServiceUnitRejectsTamperingWithoutEcho(t *testing.T) {
	for _, altered := range [][]byte{
		nil,
		append(NativeExclusiveServiceUnitV1(), []byte("ExecStartPost=/usr/sbin/swanctl --load-all\\n")...),
		bytes.Replace(NativeExclusiveServiceUnitV1(), []byte("Restart=no"), []byte("Restart=always"), 1),
		bytes.Replace(NativeExclusiveServiceUnitV1(), []byte(NativeExclusiveConfigPath), []byte("/etc/strongswan.conf"), 1),
		append(NativeExclusiveServiceUnitV1(), []byte("PSK=DO_NOT_PRINT\\n")...),
	} {
		err := CheckNativeExclusiveServiceUnitV1(altered)
		if err == nil {
			t.Fatal("accepted altered unit")
		}
		if strings.Contains(err.Error(), "DO_NOT_PRINT") || strings.Contains(err.Error(), "/etc/strongswan.conf") {
			t.Fatal("unit validation leaked untrusted input")
		}
	}
}

func TestNativeServiceUnitReadOnlyPinnedIdentity(t *testing.T) {
	t.Run("exact bytes are only an observation", func(t *testing.T) {
		root, _ := nativeUnitFixture(t)
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitExact {
			t.Fatalf("exact fixture result: %s", got)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitMissing {
			t.Fatalf("missing file result: %s", got)
		}
	})
	t.Run("missing parents", func(t *testing.T) {
		root := t.TempDir()
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitMissing {
			t.Fatalf("missing directory result: %s", got)
		}
	})
	t.Run("changed same-size ExecStart policy", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		altered := bytes.Replace(NativeExclusiveServiceUnitV1(), []byte("UMask=0077"), []byte("UMask=0000"), 1)
		if len(altered) != len(NativeExclusiveServiceUnitV1()) {
			t.Fatal("same-size policy alteration was not same-size")
		}
		if err := os.WriteFile(path, altered, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitConflict {
			t.Fatalf("foreign bytes result: %s", got)
		}
	})
	t.Run("unsafe file permissions", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitConflict {
			t.Fatalf("writable unit result: %s", got)
		}
	})
	t.Run("hardlink cannot prove exclusive inode", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		if err := os.Link(path, path+".other"); err != nil {
			t.Fatal(err)
		}
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitConflict {
			t.Fatalf("hardlink unit result: %s", got)
		}
	})
	t.Run("foreign file symlink", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		if err := os.Rename(path, path+".foreign"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path+".foreign", path); err != nil {
			t.Fatal(err)
		}
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitConflict {
			t.Fatalf("symlink unit result: %s", got)
		}
	})
	t.Run("foreign parent symlink", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		dir := filepath.Dir(path)
		if err := os.Rename(dir, dir+".foreign"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dir+".foreign", dir); err != nil {
			t.Fatal(err)
		}
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitConflict {
			t.Fatalf("symlink directory result: %s", got)
		}
	})
	t.Run("group writable parent", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		if err := os.Chmod(filepath.Dir(path), 0o775); err != nil {
			t.Fatal(err)
		}
		if got := inspectNativeUnitFixture(root); got != NativeServiceUnitConflict {
			t.Fatalf("writable parent result: %s", got)
		}
	})
	t.Run("wrong owner", func(t *testing.T) {
		root, _ := nativeUnitFixture(t)
		if got := inspectNativeServiceUnitAt(root, uint32(os.Geteuid()+1), nil); got != NativeServiceUnitConflict {
			t.Fatalf("wrong owner result: %s", got)
		}
	})
	t.Run("replaced same-byte inode during inspection", func(t *testing.T) {
		root, path := nativeUnitFixture(t)
		got := inspectNativeServiceUnitAt(root, uint32(os.Geteuid()), func() {
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, NativeExclusiveServiceUnitV1(), 0o644); err != nil {
				t.Fatal(err)
			}
		})
		if got != NativeServiceUnitConflict {
			t.Fatalf("raced unit replacement result: %s", got)
		}
		if again := inspectNativeUnitFixture(root); again != NativeServiceUnitExact {
			t.Fatalf("new but foreign inode should be only a byte observation: %s", again)
		}
	})
	t.Run("bad inspection root", func(t *testing.T) {
		if got := inspectNativeServiceUnitAt("relative", uint32(os.Geteuid()), nil); got != NativeServiceUnitUnverified {
			t.Fatalf("relative root accepted: %s", got)
		}
	})
}
