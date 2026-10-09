package linux

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// An open source descriptor guards the otherwise-valid dev/inode comparison
// from filesystem ABA: after unlink, the original inode cannot be recycled
// until the operation/Undo closure no longer retains its descriptor.
func TestStagingOriginPinnedThroughUnlinkAndReplacement(t *testing.T) {
	dir := t.TempDir()
	contents := []byte(managedSystemdMarker + "\n[Unit]\nDescription=pinned unit\n")
	staged, identity, err := createOwnedStagingUnit(dir, contents, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	pinned, ok := identity.(*pinnedUnitIdentity)
	if !ok || pinned.origin == nil {
		t.Fatal("publication did not preserve the original open descriptor")
	}
	defer pinned.origin.Close()

	if !sameUnitFile(identity, identity) {
		t.Fatal("held inode does not compare equal to itself")
	}
	contentsOnDisk, current, err := readRegularUnit(staged)
	if err != nil || !sameUnitFile(identity, current) || !bytes.Equal(contentsOnDisk, contents) {
		t.Fatalf("original staged identity unreadable: %v", err)
	}
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	stillOpen, err := pinned.origin.Stat()
	if err != nil || !sameUnitFile(identity, stillOpen) {
		t.Fatalf("unlinked origin inode was not retained through its descriptor: %v", err)
	}
	for i := 0; i < 32; i++ {
		path := filepath.Join(dir, "replacement-unit")
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
		replacement, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if sameUnitFile(replacement, identity) {
			t.Fatal("filesystem recycled an inode while STL retained its original descriptor")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}
