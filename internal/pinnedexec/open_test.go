package pinnedexec

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenRetainsOriginalInodeAcrossSameBytePathReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "helper")
	body := []byte("public executable test fixture\n")
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	file, original, err := Open(path, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	got, err := io.ReadAll(file)
	if err != nil || string(got) != string(body) {
		t.Fatal("retained descriptor was not rewound to the verified contents")
	}
	// A renamed and byte-identical replacement must never obtain the
	// original inode while the transaction retains its descriptor.
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err := Inspect(path, digest)
	if err != nil {
		t.Fatal(err)
	}
	if current.SHA256 != original.SHA256 || current == original {
		t.Fatal("same bytes confused the replacement with the pinned original")
	}
	var held unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &held); err != nil ||
		uint64(held.Dev) != original.Device || held.Ino != original.Inode {
		t.Fatal("retained descriptor lost the original inode")
	}
}

func TestOpenFailureDoesNotReturnAUsableDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("wrong public test bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("approved public test bytes"))
	file, identity, err := Open(path, hex.EncodeToString(sum[:]))
	if err == nil || file != nil || identity != (Identity{}) {
		if file != nil {
			_ = file.Close()
		}
		t.Fatal("failed hash admission returned an executable pin")
	}
}
