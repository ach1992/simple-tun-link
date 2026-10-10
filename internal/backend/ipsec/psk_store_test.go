package ipsec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	wgbackend "github.com/ach1992/simple-tun-link/internal/backend/wireguard"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

const (
	testPSKLink1 domain.LinkID = "lnk_00112233445566778899aabbccddeeff"
	testPSKLink2 domain.LinkID = "lnk_ffeeddccbbaa99887766554433221100"
)

func freshTestPSK(t *testing.T) []byte {
	t.Helper()
	raw, err := GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(raw) })
	return raw
}

func makePSKStore(t *testing.T) (*PSKStore, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewPSKStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return store, root
}

func TestIPsecOpaquePSKNeverGenericOutput(t *testing.T) {
	raw := freshTestPSK(t)
	key, err := ParsePSK(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zeroize()
	copied := key.SecretBytes()
	if !bytes.Equal(copied, raw) {
		t.Fatal("explicit PSK extraction failed")
	}
	clear(copied)
	secondCopy := key.SecretBytes()
	if !bytes.Equal(secondCopy, raw) {
		t.Fatal("caller cleared underlying PSK through returned slice")
	}
	clear(secondCopy)
	payload, err := json.Marshal(key)
	if err != nil || strings.Contains(string(payload), hex.EncodeToString(raw)) {
		t.Fatal("IPsec PSK leaked through generic JSON")
	}
	if fmt.Sprintf("%v", key) != "[IPsec PSK REDACTED]" ||
		fmt.Sprintf("%#v", key) != "[IPsec PSK REDACTED]" {
		t.Fatal("IPsec PSK leaked through generic formatting")
	}
	if _, err := ParsePSK(nil); err == nil {
		t.Fatal("missing IPsec PSK accepted")
	}
	if _, err := ParsePSK(bytes.Repeat([]byte{0x00}, 32)); err == nil {
		t.Fatal("all-zero IPsec PSK accepted")
	}
}

func TestIPsecProtectedPSKNoReplaceAndExactReplay(t *testing.T) {
	store, root := makePSKStore(t)
	key := freshTestPSK(t)
	other := freshTestPSK(t)
	if err := store.PutNew(testPSKLink1, key); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{root, 0o700},
		{filepath.Join(root, "credentials"), 0o700},
		{filepath.Join(root, "credentials", string(testPSKLink1)+".ipsecpsk"), 0o600},
	} {
		info, err := os.Lstat(tc.path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != tc.mode {
			t.Fatalf("unprotected IPsec credential identity at %s", tc.path)
		}
	}
	if err := store.EnsureExact(testPSKLink1, key); err != nil {
		t.Fatal("identical retry must be idempotent", err)
	}
	if err := store.EnsureExact(testPSKLink1, other); err == nil {
		t.Fatal("different IPsec key must not replace existing key")
	}
	if err := store.PutNew(testPSKLink1, other); err == nil {
		t.Fatal("new key clobbered existing Link identity")
	}
	got, err := store.Load(testPSKLink1)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Zeroize()
	b := got.SecretBytes()
	if !bytes.Equal(b, key) {
		t.Fatal("stored IPsec key changed after rejected replacement")
	}
	clear(b)
	if err := store.EnsureExact(testPSKLink2, other); err != nil {
		t.Fatal("second Link must have independent protected secret", err)
	}
	files, err := os.ReadDir(filepath.Join(root, "credentials"))
	if err != nil || len(files) != 2 {
		t.Fatal("temporary or foreign private credential artifacts are present", err)
	}
}

func TestIPsecPSKStoreRejectsInvalidPathsOrUnsafeAliases(t *testing.T) {
	for _, root := range []string{"", ".", "../state", "/tmp/../other", "/"} {
		if _, err := NewPSKStore(root); err == nil {
			t.Fatal("unsafe protected state root accepted")
		}
	}
	store, root := makePSKStore(t)
	if err := store.PutNew("../outside", freshTestPSK(t)); err == nil {
		t.Fatal("invalid Link ID accepted for credential write")
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid identity touched the state filesystem")
	}
	t.Run("state-symlink", func(t *testing.T) {
		real := filepath.Join(t.TempDir(), "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		alias, err := NewPSKStore(link)
		if err != nil {
			t.Fatal(err)
		}
		if err := alias.PutNew(testPSKLink1, freshTestPSK(t)); err == nil {
			t.Fatal("followed a symlinked protected state root")
		}
	})
	t.Run("credentials-directory-symlink", func(t *testing.T) {
		s, path := makePSKStore(t)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(path, "credentials")); err != nil {
			t.Fatal(err)
		}
		if err := s.PutNew(testPSKLink1, freshTestPSK(t)); err == nil {
			t.Fatal("followed a symlinked credential directory")
		}
		if entries, _ := os.ReadDir(outside); len(entries) != 0 {
			t.Fatal("credential written outside protected directory")
		}
	})
	t.Run("symlink-leaf", func(t *testing.T) {
		s, path := makePSKStore(t)
		if err := os.MkdirAll(filepath.Join(path, "credentials"), 0o700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "foreign-key")
		if err := os.Symlink(outside, filepath.Join(path, "credentials", string(testPSKLink1)+".ipsecpsk")); err != nil {
			t.Fatal(err)
		}
		if err := s.PutNew(testPSKLink1, freshTestPSK(t)); err == nil {
			t.Fatal("replaced a symlink credential file")
		}
		if _, err := s.Load(testPSKLink1); err == nil {
			t.Fatal("loaded a symlinked private PSK")
		}
		if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("foreign credential created through symlink")
		}
	})
	t.Run("writable-ancestor", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "untrusted")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		s, err := NewPSKStore(filepath.Join(parent, "state"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.PutNew(testPSKLink1, freshTestPSK(t)); err == nil {
			t.Fatal("wrote credential through writable ancestor")
		}
	})
}

func TestIPsecPSKStoreRejectsPermissionHardlinkAndContentDrift(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(t *testing.T, path string, raw []byte)
	}{
		{"world-readable", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.Link(path, filepath.Join(filepath.Dir(path), "copy")); err != nil {
				t.Fatal(err)
			}
		}},
		{"uppercase", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.WriteFile(path, []byte(strings.Repeat("AB", 32)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"trailing-data", func(t *testing.T, path string, raw []byte) {
			t.Helper()
			if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\nEXTRA"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"zero-key", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.WriteFile(path, []byte(strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, root := makePSKStore(t)
			raw := freshTestPSK(t)
			if err := s.PutNew(testPSKLink1, raw); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "credentials", string(testPSKLink1)+".ipsecpsk")
			tc.alter(t, path, raw)
			if _, err := s.Load(testPSKLink1); err == nil {
				t.Fatal("loaded compromised protected IPsec credential")
			}
			if err := s.EnsureExact(testPSKLink1, raw); err == nil {
				t.Fatal("accepted compromised credential on idempotent retry")
			}
		})
	}
}

// The shared directory guard must preserve both backends' separate file
// identities on the same host. An IPsec key write must not replace or
// disable an existing independent WireGuard credential.
func TestIPsecAndWireGuardProtectedCredentialNamespaceIsolation(t *testing.T) {
	ipsecStore, root := makePSKStore(t)
	wgStore, err := wgbackend.NewKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, _, err := wgbackend.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer privateKey.Zeroize()
	if err := wgStore.PutNew(testPSKLink1, privateKey); err != nil {
		t.Fatal(err)
	}
	raw := freshTestPSK(t)
	if err := ipsecStore.PutNew(testPSKLink1, raw); err != nil {
		t.Fatal(err)
	}
	wgRecovered, err := wgStore.Load(testPSKLink1)
	if err != nil || wgRecovered != privateKey {
		t.Fatal("IPsec PSK store changed an existing WireGuard credential")
	}
	wgRecovered.Zeroize()
	pskRecovered, err := ipsecStore.Load(testPSKLink1)
	if err != nil {
		t.Fatal(err)
	}
	defer pskRecovered.Zeroize()
	readCopy := pskRecovered.SecretBytes()
	if !bytes.Equal(readCopy, raw) {
		t.Fatal("WireGuard KeyStore changed the IPsec credential")
	}
	clear(readCopy)
	files, err := os.ReadDir(filepath.Join(root, "credentials"))
	if err != nil || len(files) != 2 {
		t.Fatalf("cross-backend credentials not isolated: %v, %v", files, err)
	}
}

func TestIPsecPSKStoreConcurrentNoClobber(t *testing.T) {
	s, root := makePSKStore(t)
	key1 := freshTestPSK(t)
	key2 := freshTestPSK(t)
	keys := [][]byte{key1, key2}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for index := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.PutNew(testPSKLink1, keys[i])
		}(index)
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("exactly one concurrent PSK creation should succeed: %d", wins)
	}
	got, err := s.Load(testPSKLink1)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Zeroize()
	copied := got.SecretBytes()
	if !bytes.Equal(copied, key1) && !bytes.Equal(copied, key2) {
		t.Fatal("concurrent writers created an unexpected key")
	}
	clear(copied)
	files, err := os.ReadDir(filepath.Join(root, "credentials"))
	if err != nil || len(files) != 1 {
		t.Fatal("concurrent update left private transient files", err)
	}
}
