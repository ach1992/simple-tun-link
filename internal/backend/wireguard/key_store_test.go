package wireguard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const (
	privateTestID  domain.LinkID = "lnk_00112233445566778899aabbccddeeff"
	privateTestID2 domain.LinkID = "lnk_ffeeddccbbaa99887766554433221100"
)

func testKeyStore(t *testing.T) (*KeyStore, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return store, root
}

func testGeneratedKey(t *testing.T) PrivateKey {
	t.Helper()
	key, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestProtectedWireGuardKeyStoreAtomicNoReplaceAndRestore(t *testing.T) {
	store, root := testKeyStore(t)
	key := testGeneratedKey(t)
	if err := store.PutNew(privateTestID, key); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{root, 0o700},
		{filepath.Join(root, "credentials"), 0o700},
		{filepath.Join(root, "credentials", string(privateTestID)+".wgkey"), 0o600},
	} {
		info, err := os.Lstat(item.path)
		if err != nil || info.Mode().Perm() != item.mode || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("unsafe file/directory mode or identity at protected state location: %+v %v", info, err)
		}
	}
	recovered, err := store.Load(privateTestID)
	if err != nil || recovered != key {
		t.Fatal("protected private key failed to restore")
	}
	other := testGeneratedKey(t)
	if err := store.PutNew(privateTestID, other); err == nil {
		t.Fatal("replacing an existing Link's private key must never succeed")
	}
	recovered, err = store.Load(privateTestID)
	if err != nil || recovered != key {
		t.Fatal("existing key changed after rejected replacement")
	}
	if err := store.PutNew(privateTestID2, other); err != nil {
		t.Fatal("separate Link cannot have an independently owned credential", err)
	}
	if recovered, err = store.Load(privateTestID2); err != nil || recovered != other {
		t.Fatal("separate Link private key corrupted")
	}
	files, err := os.ReadDir(filepath.Join(root, "credentials"))
	if err != nil || len(files) != 2 {
		t.Fatalf("temporary/private credential files not isolated and cleaned: %d, %v", len(files), err)
	}
}

func TestProtectedWireGuardKeyStoreRejectsUnsafePathsAndFiles(t *testing.T) {
	for _, name := range []string{"", ".", "./local", "/..", "/tmp/../other-root", "/"} {
		if _, err := NewKeyStore(name); err == nil {
			t.Errorf("accepted unsafe private key store root")
		}
	}
	t.Run("link-id", func(t *testing.T) {
		store, root := testKeyStore(t)
		if err := store.PutNew("../foreign", testGeneratedKey(t)); err == nil {
			t.Fatal("accepted invalid Link ID as a credential path")
		}
		if _, err := store.Load("../foreign"); err == nil {
			t.Fatal("loaded an invalid credential path")
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid Link ID touched the state filesystem")
		}
	})
	t.Run("state-root-symlink", func(t *testing.T) {
		real := filepath.Join(t.TempDir(), "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(real, alias); err != nil {
			t.Fatal(err)
		}
		store, err := NewKeyStore(alias)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutNew(privateTestID, testGeneratedKey(t)); err == nil {
			t.Fatal("followed a credential-directory symlink")
		}
		if _, err := os.Stat(filepath.Join(real, "credentials")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("unexpected credential write through directory symlink")
		}
	})
	t.Run("credentials-dir-symlink", func(t *testing.T) {
		store, root := testKeyStore(t)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		foreign := t.TempDir()
		if err := os.Symlink(foreign, filepath.Join(root, "credentials")); err != nil {
			t.Fatal(err)
		}
		if err := store.PutNew(privateTestID, testGeneratedKey(t)); err == nil {
			t.Fatal("followed credentials-directory symlink")
		}
		if entries, _ := os.ReadDir(foreign); len(entries) != 0 {
			t.Fatal("secret written to symlink target")
		}
	})
	t.Run("credential-leaf-symlink", func(t *testing.T) {
		store, root := testKeyStore(t)
		if err := os.MkdirAll(filepath.Join(root, "credentials"), 0o700); err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(root, "credentials", string(privateTestID)+".wgkey")
		other := filepath.Join(t.TempDir(), "other")
		if err := os.Symlink(other, dest); err != nil {
			t.Fatal(err)
		}
		if err := store.PutNew(privateTestID, testGeneratedKey(t)); err == nil {
			t.Fatal("overwrote a symlinked private-key identity")
		}
		if _, err := store.Load(privateTestID); err == nil {
			t.Fatal("followed a symlinked private key")
		}
		if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("symlink target unexpectedly created")
		}
	})
	t.Run("permissions-drift", func(t *testing.T) {
		store, root := testKeyStore(t)
		if err := store.PutNew(privateTestID, testGeneratedKey(t)); err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(root, "credentials", string(privateTestID)+".wgkey")
		if err := os.Chmod(name, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(privateTestID); err == nil {
			t.Fatal("read private credential with unsafe permissions")
		}
	})
	t.Run("hardlink-drift", func(t *testing.T) {
		store, root := testKeyStore(t)
		if err := store.PutNew(privateTestID, testGeneratedKey(t)); err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(root, "credentials", string(privateTestID)+".wgkey")
		if err := os.Link(name, filepath.Join(root, "key-copy")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(privateTestID); err == nil {
			t.Fatal("read private key with unexplained additional hardlink")
		}
	})
	t.Run("bad-existing-state-root-mode", func(t *testing.T) {
		store, root := testKeyStore(t)
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := store.PutNew(privateTestID, testGeneratedKey(t)); err == nil {
			t.Fatal("created credential inside a group/world-traversable state root")
		}
	})
	t.Run("malformed-on-disk", func(t *testing.T) {
		store, root := testKeyStore(t)
		if err := store.PutNew(privateTestID, testGeneratedKey(t)); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "credentials", string(privateTestID)+".wgkey")
		if err := os.WriteFile(path, []byte("invalid WireGuard key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(privateTestID); err == nil {
			t.Fatal("accepted malformed credential file")
		}
	})
}

func TestProtectedWireGuardKeyStoreConcurrentSameIDNoClobber(t *testing.T) {
	store, _ := testKeyStore(t)
	keys := []PrivateKey{testGeneratedKey(t), testGeneratedKey(t)}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range keys {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			errs[index] = store.PutNew(privateTestID, keys[index])
		}(i)
	}
	wg.Wait()
	passed := 0
	for _, err := range errs {
		if err == nil {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("concurrent publication must have exactly one winner, got %d", passed)
	}
	got, err := store.Load(privateTestID)
	if err != nil || (got != keys[0] && got != keys[1]) {
		t.Fatal("stored private key does not match a single completed writer")
	}
}

func TestProtectedWireGuardKeyStoreRejectsUntrustedWritableAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	store, err := NewKeyStore(filepath.Join(parent, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutNew(privateTestID, testGeneratedKey(t)); err == nil ||
		strings.Contains(err.Error(), "PRIVATE_KEY") {
		t.Fatal("accepted untrusted ancestor or leaked secret")
	}
}
