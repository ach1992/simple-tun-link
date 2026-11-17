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

// ownedInstallation is the installer's format=1 record, bound to the exact
// bytes of the canonical executable and the stlink alias by the proof below.
type ownedInstallation struct {
	version string
	hash    string
}

// verifiedInstalledIdentity is the common canonical installation identity
// validator used by both retained COMMITTED journal checks and Signed Mirror
// receipt reconciliation. It deliberately does not accept a running binary
// pathname as evidence of a completed installer transaction.
func (g Gate) verifiedInstalledIdentity(canonical, record, alias string) (ownedInstallation, error) {
	var identity ownedInstallation
	executable, err := g.openTrustedRegular(canonical, false)
	if err != nil {
		return identity, fmt.Errorf("installed executable: %w", err)
	}
	h := sha256.New()
	_, hashErr := io.Copy(h, executable)
	closeErr := executable.Close()
	if err := errors.Join(hashErr, closeErr); err != nil {
		return identity, fmt.Errorf("cannot hash installed executable: %w", err)
	}
	identity.hash = hex.EncodeToString(h.Sum(nil))
	recordBytes, err := g.readPrivateRegular(record, recordMaxSize)
	if err != nil {
		return ownedInstallation{}, fmt.Errorf("cannot trust ownership record: %w", err)
	}
	lines := strings.Split(string(recordBytes), "\n")
	if len(lines) != 5 || lines[0] != "format=1" || lines[1] != "project=simple-tun-link" ||
		lines[4] != "" || lines[3] != "sha256="+identity.hash {
		return ownedInstallation{}, fmt.Errorf("ownership record structure/hash disagrees with canonical executable")
	}
	version, ok := strings.CutPrefix(lines[2], "version=")
	if !ok || !ownedVersionPattern.MatchString(version) {
		return ownedInstallation{}, fmt.Errorf("ownership record has an invalid version")
	}
	identity.version = version
	first, err := os.Lstat(alias)
	if err != nil || first.Mode()&os.ModeSymlink == 0 {
		return ownedInstallation{}, fmt.Errorf("installer-owned alias is missing or not a symlink")
	}
	link, err := os.Readlink(alias)
	if err != nil || link != "stl" {
		return ownedInstallation{}, fmt.Errorf("installer-owned alias does not point to stl")
	}
	second, err := os.Lstat(alias)
	if err != nil || !os.SameFile(first, second) {
		return ownedInstallation{}, fmt.Errorf("installer alias changed during identity proof")
	}
	return identity, nil
}

func (g Gate) verifyCommittedInstalled(canonical, record, alias, wantHash string) error {
	identity, err := g.verifiedInstalledIdentity(canonical, record, alias)
	if err != nil {
		return err
	}
	if identity.hash != wantHash {
		return fmt.Errorf("committed journal hash differs from installed executable and record")
	}
	return nil
}

// VerifyCompletedInstallation validates only the canonical, durable
// installer-owned identity (not Link State). The caller MUST already hold
// the canonical exclusive maintenance lock. This read-only path is needed
// by Signed Mirror after self-upgrade: Engine Gate.Acquire deliberately
// rejects a running process whose executable has been replaced.
// Valid COMMITTED journals remain admissible, but missing/incomplete
// journals and mismatched record/executable identities never advance trust.
func (g Gate) VerifyCompletedInstallation(expectedVersion string) error {
	if !ownedVersionPattern.MatchString(expectedVersion) {
		return errors.New("expected installed version is invalid")
	}
	dir, canonical := g.Directory, g.Canonical
	if dir == "" {
		dir = DefaultDirectory
	}
	if canonical == "" {
		canonical = CanonicalSTL
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir ||
		!filepath.IsAbs(canonical) || filepath.Clean(canonical) != canonical {
		return errors.New("canonical installation paths are invalid")
	}
	if err := verifyDirectory(dir, g.testOnlyUnprivilegedPath); err != nil {
		return fmt.Errorf("installer-owned record directory is untrusted: %w", err)
	}
	if err := verifyDirectory(filepath.Dir(canonical), g.testOnlyUnprivilegedPath); err != nil {
		return fmt.Errorf("canonical executable directory is untrusted: %w", err)
	}
	identity, err := g.verifiedInstalledIdentity(canonical, filepath.Join(dir, RecordName),
		filepath.Join(filepath.Dir(canonical), "stlink"))
	if err != nil {
		return fmt.Errorf("canonical installation incomplete: %w", err)
	}
	if identity.version != expectedVersion {
		return errors.New("canonical install-record version differs from signed target")
	}
	if err := g.verifyRecoveryJournals(canonical, dir); err != nil {
		return fmt.Errorf("canonical installation has unresolved recovery: %w", err)
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
