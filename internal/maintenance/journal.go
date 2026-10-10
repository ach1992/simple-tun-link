package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// COMMITTED v1 is exactly three ordered newline-terminated fields:
// status=committed, operation=install|update|uninstall, sha256=<64 lower hex>.
// Both the Bash installer and the Engine gate must agree on this format and
// on the installed-vs-retired canonical identities. A marker name alone is
// never recovery proof.
const (
	committedName  = "COMMITTED"
	journalMaxSize = 128
	recordMaxSize  = 256
)

var ownedVersionPattern = regexp.MustCompile(`^(v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?|dev-[0-9a-f]{12})$`)

func (g Gate) verifyRecoveryJournal(recovery, canonical, dir string) error {
	if err := verifyDirectory(recovery, g.testOnlyUnprivilegedPath); err != nil {
		return fmt.Errorf("untrusted transaction directory: %w", err)
	}
	data, err := g.readPrivateRegular(filepath.Join(recovery, committedName), journalMaxSize)
	if err != nil {
		return fmt.Errorf("missing or invalid committed recovery journal: %w", err)
	}
	fields := strings.Split(string(data), "\n")
	if len(fields) != 4 || fields[0] != "status=committed" || fields[3] != "" {
		return fmt.Errorf("incomplete or malformed committed recovery journal")
	}
	operation, ok := strings.CutPrefix(fields[1], "operation=")
	if !ok || (operation != "install" && operation != "update" && operation != "uninstall") {
		return fmt.Errorf("unknown committed recovery operation")
	}
	savedHash, ok := strings.CutPrefix(fields[2], "sha256=")
	if !ok || len(savedHash) != 64 || strings.Trim(savedHash, "0123456789abcdef") != "" {
		return fmt.Errorf("invalid committed recovery SHA-256")
	}
	// Parsing requires exactly the same canonical serialized bytes emitted by
	// scripts/install.sh commit_marker; no duplicates or extra fields survive.
	expected := fmt.Sprintf("status=committed\noperation=%s\nsha256=%s\n", operation, savedHash)
	if string(data) != expected {
		return fmt.Errorf("noncanonical committed recovery journal")
	}
	record := filepath.Join(dir, RecordName)
	alias := filepath.Join(filepath.Dir(canonical), "stlink")
	if operation == "uninstall" {
		for _, path := range []string{canonical, record, alias} {
			if err := requireAbsent(path); err != nil {
				return fmt.Errorf("committed uninstall is inconsistent with installed identity: %w", err)
			}
		}
		return nil
	}
	if err := g.verifyCommittedInstalled(canonical, record, alias, savedHash); err != nil {
		return fmt.Errorf("committed %s is inconsistent with installed identity: %w", operation, err)
	}
	return nil
}

func requireAbsent(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("cannot inspect %q: %w", path, err)
	}
	return fmt.Errorf("%q is still present", path)
}

func (g Gate) verifyCommittedInstalled(canonical, record, alias, wantHash string) error {
	executable, err := g.openTrustedRegular(canonical, false)
	if err != nil {
		return fmt.Errorf("installed executable: %w", err)
	}
	hash := sha256.New()
	_, hashErr := io.Copy(hash, executable)
	closeErr := executable.Close()
	if err := errors.Join(hashErr, closeErr); err != nil {
		return fmt.Errorf("cannot hash installed executable: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != wantHash {
		return fmt.Errorf("installed executable hash differs from committed journal")
	}
	recordBytes, err := g.readPrivateRegular(record, recordMaxSize)
	if err != nil {
		return fmt.Errorf("cannot trust ownership record: %w", err)
	}
	lines := strings.Split(string(recordBytes), "\n")
	if len(lines) != 5 || lines[0] != "format=1" || lines[1] != "project=simple-tun-link" ||
		lines[4] != "" || lines[3] != "sha256="+wantHash {
		return fmt.Errorf("ownership record structure/hash disagrees with committed journal")
	}
	version, ok := strings.CutPrefix(lines[2], "version=")
	if !ok || !ownedVersionPattern.MatchString(version) {
		return fmt.Errorf("ownership record has an invalid version")
	}
	first, err := os.Lstat(alias)
	if err != nil || first.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("installer-owned alias is missing or not a symlink")
	}
	link, err := os.Readlink(alias)
	if err != nil || link != "stl" {
		return fmt.Errorf("installer-owned alias does not point to stl")
	}
	second, err := os.Lstat(alias)
	if err != nil || !os.SameFile(first, second) {
		return fmt.Errorf("installer alias changed during identity proof")
	}
	return nil
}

func (g Gate) readPrivateRegular(path string, max int64) ([]byte, error) {
	f, err := g.openTrustedRegular(path, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if len(data) > int(max) {
		return nil, fmt.Errorf("private metadata exceeds bounded size")
	}
	return data, nil
}

// openTrustedRegular pins the inode through O_NOFOLLOW and checks that the
// directory entry still identifies that inode, avoiding symlink substitution.
// Under the real prefix, executable/metadata must also be root-protected.
func (g Gate) openTrustedRegular(path string, private bool) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !info.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		_ = f.Close()
		return nil, fmt.Errorf("file identity changed or is not a regular file")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("private metadata permissions are too broad")
	}
	if !g.testOnlyUnprivilegedPath {
		if err := verifyProtected(info); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}
