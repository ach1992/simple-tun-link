package ipsec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func nativePublicationFixture(t *testing.T) (string, string, uint32) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(root, nativeFixturePath), uint32(os.Geteuid())
}

func TestNativeConfigPublicationDurableNoClobberAndRestartInspection(t *testing.T) {
	root, path, uid := nativePublicationFixture(t)
	if got := inspectNativeOriginAt(root, uid); got != NativeOriginMissing {
		t.Fatalf("initial state: %s", got)
	}
	if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); err != nil {
		t.Fatal(err)
	}
	if got := inspectNativeOriginAt(root, uid); got != NativeOriginVerified {
		t.Fatalf("receipt-bound snapshot: %s", got)
	}
	if got := nativeFixtureResult(root); got != NativeConfigExact {
		t.Fatalf("existing doctor regressed: %s", got)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("config identity: %+v, %v", info, err)
	}
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, NativeExclusiveConfigV1()) {
		t.Fatal("published bytes differ")
	}
	// Presence of an exact STL-shaped file is never a replay/adoption permit.
	if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("unsafe replay: %v", err)
	}
	if got := inspectNativeOriginAt(root, uid); got != NativeOriginVerified {
		t.Fatalf("safe replay changed state: %s", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("unexpected staging leftovers after success: %d", len(entries))
	}
}

func TestNativeConfigPublicationNeverOverwritesForeignFile(t *testing.T) {
	t.Run("preexisting exact bytes are not adopted", func(t *testing.T) {
		root, path, uid := nativePublicationFixture(t)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, NativeExclusiveConfigV1(), 0o600); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Lstat(path)
		if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("foreign file adopted: %v", err)
		}
		after, _ := os.Lstat(path)
		if !os.SameFile(before, after) {
			t.Fatal("preexisting file replaced")
		}
		if got := inspectNativeOriginAt(root, uid); got != NativeOriginConflict {
			t.Fatalf("foreign bytes granted provenance: %s", got)
		}
	})
	t.Run("raced canonical file is not replaced", func(t *testing.T) {
		root, path, uid := nativePublicationFixture(t)
		foreign := []byte("external administrator file; must survive unchanged\n")
		err := publishNativeConfigAt(root, uid, nativePublishHooks{beforeCanonical: func() error {
			if err := os.WriteFile(path, foreign, 0o600); err != nil {
				t.Fatal(err)
			}
			return nil
		}})
		if !errors.Is(err, errNativePublicationPending) {
			t.Fatalf("race did not fail closed: %v", err)
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, foreign) {
			t.Fatalf("overwrote independent file: %v, %q", err, actual)
		}
		if got := inspectNativeOriginAt(root, uid); got != NativeOriginConflict {
			t.Fatalf("raced file adopted: %s", got)
		}
	})
	t.Run("symlink canonical is preserved", func(t *testing.T) {
		root, path, uid := nativePublicationFixture(t)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("another-config", path); err != nil {
			t.Fatal(err)
		}
		if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
			t.Fatalf("symlink not blocked: %v", err)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatal("symlink replaced")
		}
	})
}

func TestNativeConfigPublicationRequiresManualReconcileAfterInterruption(t *testing.T) {
	root, path, uid := nativePublicationFixture(t)
	err := publishNativeConfigAt(root, uid, nativePublishHooks{afterReceipt: func() error { return errors.New("simulate power loss") }})
	if !errors.Is(err, errNativePublicationPending) {
		t.Fatalf("missing interrupted publication classification: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected canonical: %v", err)
	}
	if got := inspectNativeOriginAt(root, uid); got != NativeOriginConflict {
		t.Fatalf("incomplete receipt treated as absence: %s", got)
	}
	// No automatic subsequent adoption/retry even though the journal is own.
	if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("interrupted receipt resumed: %v", err)
	}

	fresh, newPath, uid := nativePublicationFixture(t)
	err = publishNativeConfigAt(fresh, uid, nativePublishHooks{afterCanonical: func() error { return errors.New("simulate post-rename uncertainty") }})
	if !errors.Is(err, errNativePublicationPending) {
		t.Fatalf("post-publish uncertainty swallowed: %v", err)
	}
	if _, err := os.Lstat(newPath); err != nil {
		t.Fatalf("published inode must be preserved: %v", err)
	}
	if got := inspectNativeOriginAt(fresh, uid); got != NativeOriginVerified {
		t.Fatalf("receipt identity lost: %s", got)
	}
	if err := publishNativeConfigAt(fresh, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("post-failure automatic adoption: %v", err)
	}
}

func TestNativeConfigOriginRejectsTamperingAndIdentityReuse(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"receipt deletion", func(t *testing.T, path string) {
			if err := os.Remove(filepath.Join(filepath.Dir(path), nativeOriginName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt mode", func(t *testing.T, path string) {
			if err := os.Chmod(filepath.Join(filepath.Dir(path), nativeOriginName), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt symlink", func(t *testing.T, path string) {
			p := filepath.Join(filepath.Dir(path), nativeOriginName)
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed receipt nonce", func(t *testing.T, path string) {
			p := filepath.Join(filepath.Dir(path), nativeOriginName)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b = []byte(strings.Replace(string(b), `"schema_version":1`, `"schema_version":2`, 1))
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"in-place cfg4", func(t *testing.T, path string) {
			b := strings.Replace(string(NativeExclusiveConfigV1()), "cfg = 1", "cfg = 4", 1)
			if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"xattr removed", func(t *testing.T, path string) {
			if err := unix.Removexattr(path, nativeOriginXattr); err != nil {
				t.Fatal(err)
			}
		}},
		{"xattr altered", func(t *testing.T, path string) {
			if err := unix.Setxattr(path, nativeOriginXattr, []byte(strings.Repeat("f", 32)), 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"same bytes new inode", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, NativeExclusiveConfigV1(), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"private directory became public", func(t *testing.T, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra hardlink", func(t *testing.T, path string) {
			if err := os.Link(path, path+".linked"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			root, path, uid := nativePublicationFixture(t)
			if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, path)
			if got := inspectNativeOriginAt(root, uid); got != NativeOriginConflict {
				t.Fatalf("tampered origin accepted: %s", got)
			}
		})
	}
}

func TestNativeConfigPublicationProtectedParentAndUID(t *testing.T) {
	root, path, uid := nativePublicationFixture(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); !errors.Is(err, errNativePublicationConflict) {
		t.Fatalf("unsafe parent accepted: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe path touched: %v", err)
	}
	if got := inspectNativeOriginAt(root, uid); got != NativeOriginConflict {
		t.Fatalf("world-writable parent: %s", got)
	}
	// Invalid root and unauthorized UID fail before any publication.
	if err := publishNativeConfigAt("relative", uid, nativePublishHooks{}); err == nil {
		t.Fatal("relative root accepted")
	}
	root2, _, uid2 := nativePublicationFixture(t)
	if err := publishNativeConfigAt(root2, uid2+1, nativePublishHooks{}); err == nil {
		t.Fatal("foreign owner accepted")
	}
}

func TestNativeConfigOriginStrictReceiptFormatAndMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*testing.T, string)
	}{
		{"extra receipt field", func(t *testing.T, path string) {
			p := filepath.Join(filepath.Dir(path), nativeOriginName)
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			data = bytes.Replace(data, []byte("\"schema_version\":1,"), []byte("\"schema_version\":1,\"unexpected\":true,"), 1)
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"receipt appended data", func(t *testing.T, path string) {
			p := filepath.Join(filepath.Dir(path), nativeOriginName)
			file, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("{}\n"); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"unsafe special mode", func(t *testing.T, path string) {
			if err := unix.Chmod(path, 0o1600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, path, uid := nativePublicationFixture(t)
			if err := publishNativeConfigAt(root, uid, nativePublishHooks{}); err != nil {
				t.Fatal(err)
			}
			tc.edit(t, path)
			if got := inspectNativeOriginAt(root, uid); got != NativeOriginConflict {
				t.Fatalf("invalid receipt/mode allowed: %s", got)
			}
		})
	}
}

func TestNativeConfigPublicationRefusesSwappedPrivateDirectory(t *testing.T) {
	root, path, uid := nativePublicationFixture(t)
	originalParent := filepath.Dir(path)
	err := publishNativeConfigAt(root, uid, nativePublishHooks{beforeCanonical: func() error {
		if err := os.Rename(originalParent, originalParent+".foreign"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(originalParent, 0o700); err != nil {
			t.Fatal(err)
		}
		return nil
	}})
	if !errors.Is(err, errNativePublicationPending) {
		t.Fatalf("changed private directory accepted: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted replacement was modified: %v", err)
	}
	if got := inspectNativeOriginAt(root, uid); got != NativeOriginMissing {
		t.Fatalf("new foreign directory was treated as STL-owned: %s", got)
	}
}

// A crypto/rand.Read result of 16 zero bytes is valid input entropy. The
// publisher must draw again BEFORE any persisted receipt, because the reader
// explicitly requires a nonzero token.
func TestNativeConfigPublicationZeroNonceRetriesBeforeReceipt(t *testing.T) {
	root, path, uid := nativePublicationFixture(t)
	var accepted [16]byte
	accepted[0], accepted[15] = 0x42, 0x7f
	entropy := bytes.NewReader(append(make([]byte, 16), accepted[:]...))
	if err := publishNativeConfigAt(root, uid, nativePublishHooks{nonceSource: entropy}); err != nil {
		t.Fatalf("valid second draw failed: %v", err)
	}
	if entropy.Len() != 0 {
		t.Fatalf("did not consume the second 128-bit entropy draw: %d bytes remain", entropy.Len())
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), nativeOriginName))
	if err != nil {
		t.Fatal(err)
	}
	var receipt nativeOriginReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Nonce != hex.EncodeToString(accepted[:]) {
		t.Fatalf("origin token did not use the nonzero draw: %s", receipt.Nonce)
	}
	if got := inspectNativeOriginAt(root, uid); got != NativeOriginVerified {
		t.Fatalf("writer-produced nonzero receipt was rejected by the inspector: %s", got)
	}
}

func TestNativeConfigPublicationEntropyFailureBeforeAnyPublication(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entropy []byte
	}{
		{"all eight draws zero", make([]byte, 8*16)},
		{"zero draw followed by EOF", make([]byte, 16)},
		{"partial first draw", make([]byte, 15)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, path, uid := nativePublicationFixture(t)
			if err := publishNativeConfigAt(root, uid, nativePublishHooks{
				nonceSource: bytes.NewReader(tc.entropy),
			}); !errors.Is(err, errNativePublicationUnknown) {
				t.Fatalf("invalid entropy was not rejected without publication: %v", err)
			}
			if got := inspectNativeOriginAt(root, uid); got != NativeOriginMissing {
				t.Fatalf("failure produced unexpected receipt or canonical config: %s", got)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("entropy failure left %d staging or canonical files", len(entries))
			}
		})
	}
}
