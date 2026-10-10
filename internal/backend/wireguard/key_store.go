package wireguard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// KeyStore holds per-Link private WireGuard material apart from the ordinary
// desired-state snapshot. Only explicitly trusted credential code may call it.
// No operation silently replaces or removes an existing private key.
type KeyStore struct{ stateRoot string }

func NewKeyStore(stateRoot string) (*KeyStore, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || stateRoot == "/" {
		return nil, fmt.Errorf("private key state root must be an absolute, clean directory")
	}
	return &KeyStore{stateRoot: stateRoot}, nil
}

func (s *KeyStore) keyName(id domain.LinkID) (string, error) {
	if s == nil {
		return "", fmt.Errorf("key store is unavailable")
	}
	if err := id.Validate(); err != nil {
		return "", fmt.Errorf("invalid credential Link ID")
	}
	return string(id) + ".wgkey", nil
}

// PutRecipient binds explicitly imported Quick Link material to the receiver's
// expected public identity before making any filesystem change. A mismatched
// or malformed credential must not leave an orphaned receiver key.
func (s *KeyStore) PutRecipient(id domain.LinkID, credential []byte, expectedPublic string) error {
	if err := id.Validate(); err != nil {
		return fmt.Errorf("invalid recipient Link ID")
	}
	key, err := DecodePrivateKey(string(credential))
	if err != nil {
		return fmt.Errorf("invalid WireGuard recipient credential")
	}
	public, err := key.PublicKey()
	if err != nil || expectedPublic == "" || public != expectedPublic {
		return fmt.Errorf("WireGuard recipient credential does not match public identity")
	}
	return s.PutNew(id, key)
}

// PutNew atomically publishes a private key only if its Link ID has no prior
// key. On a post-publication error, the key is preserved for reconciliation;
// silently deleting it could strand an active or about-to-be-restored Link.
func (s *KeyStore) PutNew(id domain.LinkID, key PrivateKey) error {
	name, err := s.keyName(id)
	if err != nil {
		return err
	}
	if _, err := key.PublicKey(); err != nil {
		return err
	}
	dirfd, err := openProtectedCredentials(s.stateRoot, true)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("create private key file identity: %w", err)
	}
	tmp := "." + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := unix.Openat(dirfd, tmp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create private credential temporary file: %w", err)
	}
	defer unix.Unlinkat(dirfd, tmp, 0)

	if err := unix.Fchmod(fd, 0o600); err != nil {
		unix.Close(fd)
		return fmt.Errorf("protect private credential file: %w", err)
	}
	content := []byte(key.SecretWireValue() + "\n")
	defer clear(content)
	data := content
	for len(data) > 0 {
		n, writeErr := unix.Write(fd, data)
		if errors.Is(writeErr, unix.EINTR) {
			continue
		}
		if writeErr != nil || n <= 0 {
			unix.Close(fd)
			return fmt.Errorf("write protected private credential file")
		}
		data = data[n:]
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		return fmt.Errorf("sync new private credential file: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close new private credential file: %w", err)
	}

	// linkat refuses to replace an existing file, including a dangling
	// symlink, and publishes the fully synced inode in one namespace step.
	if err := unix.Linkat(dirfd, tmp, dirfd, name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("a credential already exists for this Link")
		}
		return fmt.Errorf("publish new private credential file: %w", err)
	}
	if err := unix.Unlinkat(dirfd, tmp, 0); err != nil {
		return fmt.Errorf("private credential published but temporary cleanup uncertain: %w", err)
	}
	if err := unix.Fsync(dirfd); err != nil {
		return fmt.Errorf("private credential published but durability uncertain: %w", err)
	}
	return nil
}

// EnsureRecipient is retry-safe after an earlier ambiguous activation failure.
// It never silently replaces an existing key: only the identical supplied
// canonical private key is acceptable on replay.
func (s *KeyStore) EnsureRecipient(id domain.LinkID, credential []byte, expectedPublic string) error {
	supplied, err := DecodePrivateKey(string(credential))
	if err != nil {
		return fmt.Errorf("invalid WireGuard recipient credential")
	}
	public, err := supplied.PublicKey()
	if err != nil || expectedPublic == "" || public != expectedPublic {
		return fmt.Errorf("WireGuard recipient credential does not match public identity")
	}
	existing, err := s.Load(id)
	if errors.Is(err, os.ErrNotExist) {
		return s.PutNew(id, supplied)
	}
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(existing.SecretWireValue()), credential) != 1 {
		return fmt.Errorf("WireGuard recipient credential conflicts with existing Link key")
	}
	return nil
}

// Load reads only a regular, singly-linked, same-owner, 0600 key file through
// an O_NOFOLLOW descriptor. It never logs or generically serializes secrets.
func (s *KeyStore) Load(id domain.LinkID) (PrivateKey, error) {
	key, file, err := s.openVerifiedKey(id)
	if file != nil {
		file.Close()
	}
	return key, err
}

// OpenForWireGuard passes a verified read-only credential descriptor to wg.
// The subprocess receives /proc/self/fd/3, never secret text or a writable
// path; even a concurrent filesystem rename cannot alter the opened inode.
func (s *KeyStore) OpenForWireGuard(id domain.LinkID, expectedPublic string) (*os.File, error) {
	key, file, err := s.openVerifiedKey(id)
	if err != nil {
		return nil, err
	}
	public, err := key.PublicKey()
	if err != nil || public != expectedPublic {
		file.Close()
		return nil, fmt.Errorf("protected WireGuard key does not match local public identity")
	}
	return file, nil
}

func (s *KeyStore) openVerifiedKey(id domain.LinkID) (PrivateKey, *os.File, error) {
	name, err := s.keyName(id)
	if err != nil {
		return PrivateKey{}, nil, err
	}
	dirfd, err := openProtectedCredentials(s.stateRoot, false)
	if err != nil {
		return PrivateKey{}, nil, err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return PrivateKey{}, nil, fmt.Errorf("cannot open protected WireGuard key: %w", err)
	}
	file := os.NewFile(uintptr(fd), "wireguard-credential")
	fail := func() (PrivateKey, *os.File, error) {
		file.Close()
		return PrivateKey{}, nil, fmt.Errorf("invalid protected WireGuard credential file")
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Mode&0o777 != 0o600 ||
		info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 {
		return fail()
	}
	bytes, err := io.ReadAll(io.LimitReader(file, wireKeyTextLen+3))
	if err != nil || len(bytes) != wireKeyTextLen+1 || bytes[wireKeyTextLen] != '\n' {
		clear(bytes)
		return fail()
	}
	key, err := DecodePrivateKey(string(bytes[:wireKeyTextLen]))
	clear(bytes)
	if err != nil {
		return fail()
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail()
	}
	return key, file, nil
}

// Keep the existing WireGuard callers on the exact same descriptor guards
// while IPsec adds a separate secret file namespace in the shared directory.
func openProtectedCredentials(root string, create bool) (int, error) {
	return credentials.OpenProtected(root, create)
}

// RetireExact deletes only a safely opened, canonical private key whose
// derived public identity matches the operator's expected local key. The
// caller MUST hold the canonical Engine Link lock and establish that no
// persisted intent, interface, firewall, or live WG identity uses this key.
// The final descriptor-to-path identity check rejects unexpected replacement
// before unlink; a privileged out-of-band actor can still race kernel unlink
// and remains an explicit host-level reconciliation risk.
// Missing key under a valid protected root/credentials directory is idempotent.
func (s *KeyStore) RetireExact(id domain.LinkID, expectedPublic string) (bool, error) {
	name, err := s.keyName(id)
	if err != nil {
		return false, err
	}
	dir, err := openProtectedCredentials(s.stateRoot, false)
	if err != nil {
		return false, err
	}
	defer unix.Close(dir)
	key, file, err := s.openVerifiedKey(id)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	actual, err := key.PublicKey()
	if err != nil || expectedPublic == "" || actual != expectedPublic {
		return false, fmt.Errorf("protected WireGuard credential identity does not match retirement confirmation")
	}
	var fromFD, fromName unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &fromFD); err != nil {
		return false, fmt.Errorf("cannot inspect verified retirement FD")
	}
	if err = unix.Fstatat(dir, name, &fromName, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, fmt.Errorf("cannot inspect retirement identity")
	}
	if fromName.Mode&unix.S_IFMT != unix.S_IFREG || fromName.Mode&0o777 != 0o600 ||
		fromName.Uid != uint32(os.Geteuid()) || fromName.Nlink != 1 ||
		fromName.Dev != fromFD.Dev || fromName.Ino != fromFD.Ino {
		return false, fmt.Errorf("protected retirement file changed; preserving credential")
	}
	if err = unix.Unlinkat(dir, name, 0); err != nil {
		return false, fmt.Errorf("cannot retire verified WireGuard credential: %w", err)
	}
	if err = unix.Fsync(dir); err != nil {
		return false, fmt.Errorf("credential unlinked but durability uncertain; reconcile protected storage")
	}
	return true, nil
}

// LocalPublicIdentity derives only the public identity of the protected
// sender credential. No raw private value or generic JSON leaves KeyStore.
func (s *KeyStore) LocalPublicIdentity(id domain.LinkID) (string, error) {
	key, err := s.Load(id)
	if err != nil {
		return "", err
	}
	defer key.Zeroize()
	return key.PublicKey()
}
