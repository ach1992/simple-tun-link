package quichelper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pinnedexec"
	"github.com/ach1992/simple-tun-link/internal/quicwgorigin"
	"golang.org/x/sys/unix"
)

const markerDirectory = "quic-helper-origins"
const markerLimit = 16 << 10

// Attempt and positive birth evidence are deliberately different files.
// Neither an absent unit nor a missing birth receipt permits another start.
type attemptMarker struct {
	SchemaVersion                                      int           `json:"schema_version"`
	LinkID                                             domain.LinkID `json:"link_id"`
	Nonce                                              string        `json:"nonce"`
	JournalSHA256                                      string        `json:"journal_sha256"`
	Unit, Description, LaunchPath, CanonicalExecutable string
	Executable                                         pinnedexec.Identity
	Host                                               hostIdentity
	WireGuard                                          quicwgorigin.OriginalObservation
	StartedAfterUSec                                   uint64
}
type birthMarker struct {
	SchemaVersion int `json:"schema_version"`
	Attempt       attemptMarker
	Process       processObservation
}
type markerStore struct {
	root        string
	parent, dir int
}

func openMarkers(root string) (*markerStore, error) {
	parent, err := credentials.OpenProtected(root, false)
	if err != nil {
		return nil, fmt.Errorf("protected helper receipt root unavailable")
	}
	dir, err := credentials.OpenOwnedPrivateDir(parent, markerDirectory, true)
	if err != nil {
		unix.Close(parent)
		return nil, fmt.Errorf("protected helper receipt directory unavailable")
	}
	s := &markerStore{root: root, parent: parent, dir: dir}
	if unix.Fsync(parent) != nil || s.canonical() != nil {
		s.close()
		return nil, fmt.Errorf("helper receipt directory durability unverified")
	}
	return s, nil
}
func (s *markerStore) close() {
	if s == nil {
		return
	}
	_ = unix.Close(s.dir)
	_ = unix.Close(s.parent)
}
func attemptName(id domain.LinkID) string { return string(id) + ".attempt.json" }
func birthName(id domain.LinkID) string   { return string(id) + ".birth.json" }
func (s *markerStore) vacant(id domain.LinkID) error {
	if id.Validate() != nil {
		return fmt.Errorf("invalid helper receipt Link ID")
	}
	for _, name := range []string{attemptName(id), birthName(id)} {
		var st unix.Stat_t
		if unix.Fstatat(s.dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
			return fmt.Errorf("helper attempt or birth evidence exists or is uncertain")
		}
	}
	return s.canonical()
}

func sameDirectory(a, b int) bool {
	var x, y unix.Stat_t
	return unix.Fstat(a, &x) == nil && unix.Fstat(b, &y) == nil && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid
}
func (s *markerStore) canonical() error {
	parent, err := credentials.OpenProtected(s.root, false)
	if err != nil {
		return fmt.Errorf("helper receipt parent changed")
	}
	defer unix.Close(parent)
	dir, err := credentials.OpenOwnedPrivateDir(parent, markerDirectory, false)
	if err != nil {
		return fmt.Errorf("helper receipt directory changed")
	}
	defer unix.Close(dir)
	if !sameDirectory(s.parent, parent) || !sameDirectory(s.dir, dir) {
		return fmt.Errorf("helper receipt canonical directory replaced")
	}
	return nil
}

func (s *markerStore) writeAttempt(a attemptMarker) (*os.File, error) {
	return s.publish(attemptName(a.LinkID), a)
}
func (s *markerStore) writeBirth(b birthMarker) (*os.File, error) {
	return s.publish(birthName(b.Attempt.LinkID), b)
}
func (s *markerStore) verifyAttempt(a attemptMarker, f *os.File) error {
	return s.verify(attemptName(a.LinkID), a, f)
}
func (s *markerStore) verifyBirth(b birthMarker, f *os.File) error {
	return s.verify(birthName(b.Attempt.LinkID), b, f)
}

func (s *markerStore) publish(name string, value any) (*os.File, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("helper evidence cannot be encoded")
	}
	raw = append(raw, '\n')
	if len(raw) > markerLimit || s.canonical() != nil {
		return nil, fmt.Errorf("helper evidence exceeds bounds or path changed")
	}
	created, err := credentials.WritePrivateCreateOnly(s.dir, name, raw)
	if err != nil {
		return nil, fmt.Errorf("helper evidence publication uncertain")
	}
	fd, err := unix.Openat(s.dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("helper evidence pin unavailable")
	}
	f := os.NewFile(uintptr(fd), "quic-helper-origin-marker")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != created.Device || st.Ino != created.Inode || s.verify(name, value, f) != nil {
		f.Close()
		return nil, fmt.Errorf("helper originating evidence inode changed")
	}
	return f, nil
}

func (s *markerStore) verify(name string, value any, f *os.File) error {
	if f == nil || s.canonical() != nil {
		return fmt.Errorf("original helper evidence pin unavailable")
	}
	var held, path unix.Stat_t
	if unix.Fstat(int(f.Fd()), &held) != nil || unix.Fstatat(s.dir, name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != path.Dev || held.Ino != path.Ino || held.Mode != path.Mode || held.Uid != path.Uid || held.Nlink != 1 || path.Nlink != 1 || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&0o777 != 0o600 || held.Uid != uint32(os.Geteuid()) || held.Size < 2 || held.Size > markerLimit || held.Size != path.Size {
		return fmt.Errorf("original helper evidence inode is unsafe or changed")
	}
	want, err := json.Marshal(value)
	if err != nil {
		return err
	}
	want = append(want, '\n')
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("original helper evidence unreadable")
	}
	raw, err := io.ReadAll(io.LimitReader(f, markerLimit+1))
	if err != nil || !bytes.Equal(raw, want) {
		return fmt.Errorf("original helper evidence bytes differ")
	}
	var after unix.Stat_t
	if unix.Fstatat(s.dir, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || after.Dev != held.Dev || after.Ino != held.Ino || after.Mode != held.Mode || after.Size != held.Size || after.Nlink != 1 || after.Uid != held.Uid || after.Mtim != held.Mtim || after.Ctim != held.Ctim {
		return fmt.Errorf("original helper evidence changed during read")
	}
	return s.canonical()
}
