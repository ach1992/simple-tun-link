package credentials

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func privateTestDir(t *testing.T) (int, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd, root
}

func requirePrivateFileUnchanged(t *testing.T, path string, expected []byte, device uint64, inode uint64) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Fatal("private credential inode or mode changed")
	}
	var rawSt unix.Stat_t
	if err := unix.Lstat(path, &rawSt); err != nil {
		t.Fatal(err)
	}
	if uint64(rawSt.Dev) != device || rawSt.Ino != inode || rawSt.Nlink != 1 {
		t.Fatal("private credential inode was replaced or linked")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if !bytes.Equal(raw, expected) {
		t.Fatal("failed credential operation changed existing file contents")
	}
}

func TestPrivateNoReplaceCreateAndExistingRetrySyncExactFileThenDirectory(t *testing.T) {
	dirfd, root := privateTestDir(t)
	name := "authorization-token"
	raw := []byte("test-only-private-credential\n")
	path := filepath.Join(root, name)

	var order []string
	newSync := func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
			t.Fatal("new file sync was not passed a checked regular-file descriptor", err)
		}
		order = append(order, "file")
		return unix.Fsync(fd)
	}
	dirSync := func(fd int) error {
		if fd != dirfd {
			t.Fatal("directory sync was not passed the held private directory")
		}
		order = append(order, "directory")
		return unix.Fsync(fd)
	}
	if err := writePrivateNoReplaceWithSync(dirfd, name, raw, newSync, dirSync); err != nil {
		t.Fatal(err)
	}
	if want := []string{"file", "directory"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("new-file synchronization order %v, want %v", order, want)
	}
	var original unix.Stat_t
	if err := unix.Lstat(path, &original); err != nil {
		t.Fatal(err)
	}

	order = nil
	existingSync := func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		if st.Dev != original.Dev || st.Ino != original.Ino {
			t.Fatal("existing retry synced a different inode than the verified file")
		}
		order = append(order, "file")
		return unix.Fsync(fd)
	}
	if err := writePrivateNoReplaceWithSync(dirfd, name, raw, existingSync, dirSync); err != nil {
		t.Fatal(err)
	}
	if want := []string{"file", "directory"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("existing-file synchronization order %v, want %v", order, want)
	}
	requirePrivateFileUnchanged(t, path, raw, uint64(original.Dev), original.Ino)
	checked, err := ReadPrivateFile(dirfd, name)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(checked)
	if !bytes.Equal(checked, raw) {
		t.Fatal("idempotent retry changed credential bytes")
	}
}

func TestPrivateNoReplaceRecoversInterruptedInitialFileSyncWithoutReplacingInode(t *testing.T) {
	dirfd, root := privateTestDir(t)
	name := "helper.json"
	raw := []byte("{\"private\":\"test-only\"}\n")
	failure := errors.New("simulated storage file-sync error")
	directorySynced := false
	err := writePrivateNoReplaceWithSync(dirfd, name, raw,
		func(int) error { return failure },
		func(int) error { directorySynced = true; return nil })
	if !errors.Is(err, failure) || directorySynced {
		t.Fatalf("incomplete first publication was accepted or directory synced: %v", err)
	}
	path := filepath.Join(root, name)
	var retained unix.Stat_t
	if err := unix.Lstat(path, &retained); err != nil {
		t.Fatal("uncertain file was deleted", err)
	}
	requirePrivateFileUnchanged(t, path, raw, uint64(retained.Dev), retained.Ino)

	var events []string
	err = writePrivateNoReplaceWithSync(dirfd, name, raw,
		func(fd int) error {
			var checked unix.Stat_t
			if err := unix.Fstat(fd, &checked); err != nil {
				return err
			}
			if checked.Dev != retained.Dev || checked.Ino != retained.Ino {
				t.Fatal("retry fsync does not target the original retained inode")
			}
			events = append(events, "file")
			return unix.Fsync(fd)
		}, func(fd int) error {
			events = append(events, "directory")
			return unix.Fsync(fd)
		})
	if err != nil || !reflect.DeepEqual(events, []string{"file", "directory"}) {
		t.Fatalf("existing matching file was accepted without data fsync and directory fsync: %v, %v", events, err)
	}
	requirePrivateFileUnchanged(t, path, raw, uint64(retained.Dev), retained.Ino)
	if err := WritePrivateNoReplace(dirfd, name, raw); err != nil {
		t.Fatal("real unmodified public API failed on another idempotent retry", err)
	}
}

func TestPrivateNoReplaceExistingSyncFailuresPreserveExactFile(t *testing.T) {
	for _, phase := range []string{"file", "directory"} {
		t.Run(phase, func(t *testing.T) {
			dirfd, root := privateTestDir(t)
			name := "test.pem"
			raw := []byte("test-only-credential\n")
			if err := WritePrivateNoReplace(dirfd, name, raw); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, name)
			var original unix.Stat_t
			if err := unix.Lstat(path, &original); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("simulated existing-file durability failure")
			var events []string
			err := writePrivateNoReplaceWithSync(dirfd, name, raw,
				func(fd int) error {
					events = append(events, "file")
					if phase == "file" {
						return failure
					}
					return unix.Fsync(fd)
				}, func(fd int) error {
					events = append(events, "directory")
					if phase == "directory" {
						return failure
					}
					return unix.Fsync(fd)
				})
			if !errors.Is(err, failure) {
				t.Fatalf("existing-file %s sync failed without propagating error: %v", phase, err)
			}
			want := []string{"file"}
			if phase == "directory" {
				want = append(want, "directory")
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("unexpected sync sequence on failure: %v, want %v", events, want)
			}
			requirePrivateFileUnchanged(t, path, raw, uint64(original.Dev), original.Ino)
			if err := WritePrivateNoReplace(dirfd, name, raw); err != nil {
				t.Fatal("exact-file retry did not recover from simulated sync failure", err)
			}
		})
	}
}

func TestPrivateNoReplaceRejectsUntrustedExistingInodeBeforeSync(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*testing.T, string, []byte)
	}{
		{"mismatched", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.WriteFile(path, []byte("different\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"world-readable", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.Link(path, filepath.Join(t.TempDir(), "alias")); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, path string, _ []byte) {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dirfd, root := privateTestDir(t)
			name := "helper.json"
			raw := []byte("expected private bytes\n")
			if err := WritePrivateNoReplace(dirfd, name, raw); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, name)
			tc.setup(t, path, raw)
			synced := false
			err := writePrivateNoReplaceWithSync(dirfd, name, raw,
				func(int) error { synced = true; return nil },
				func(int) error { synced = true; return nil })
			if err == nil || synced {
				t.Fatalf("unsafe existing %s passed validation or reached sync", tc.name)
			}
		})
	}
}
