package wireguard

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

// Load reads only a regular, singly-linked, same-owner, 0600 key file through
// an O_NOFOLLOW descriptor. It does not invoke wg, log the private key, or
// expose material through a generic JSON/state interface.
func (s *KeyStore) Load(id domain.LinkID) (PrivateKey, error) {
	name, err := s.keyName(id)
	if err != nil {
		return PrivateKey{}, err
	}
	dirfd, err := openProtectedCredentials(s.stateRoot, false)
	if err != nil {
		return PrivateKey{}, err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("cannot open protected WireGuard key: %w", err)
	}
	file := os.NewFile(uintptr(fd), "wireguard-credential")
	defer file.Close()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Mode&0o777 != 0o600 ||
		info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 {
		return PrivateKey{}, fmt.Errorf("WireGuard credential file ownership or permissions invalid")
	}
	bytes, err := io.ReadAll(io.LimitReader(file, wireKeyTextLen+3))
	if err != nil || len(bytes) != wireKeyTextLen+1 || bytes[wireKeyTextLen] != '\n' {
		return PrivateKey{}, fmt.Errorf("invalid protected WireGuard credential file")
	}
	key, err := DecodePrivateKey(string(bytes[:wireKeyTextLen]))
	clear(bytes)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("invalid protected WireGuard credential file")
	}
	return key, nil
}

// openProtectedCredentials uses descriptor-relative, no-symlink traversal.
// The state root and credentials directory must be owned by the effective
// user and inaccessible to group/other users. Existing unsafe paths fail
// closed; they are not silently chmodded or replaced.
func openProtectedCredentials(root string, create bool) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(root, "/"), "/")
	for i, component := range append(components, "credentials") {
		last := i == len(components)
		isRoot := i == len(components)-1
		next, openErr := unix.Openat(fd, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create && (isRoot || last) {
			if mkErr := unix.Mkdirat(fd, component, 0o700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				unix.Close(fd)
				return -1, fmt.Errorf("create private credential directory: %w", mkErr)
			}
			if syncErr := unix.Fsync(fd); syncErr != nil {
				unix.Close(fd)
				return -1, fmt.Errorf("sync private credential directory parent: %w", syncErr)
			}
			next, openErr = unix.Openat(fd, component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			unix.Close(fd)
			return -1, fmt.Errorf("open protected credential directory component: %w", openErr)
		}
		var info unix.Stat_t
		if err := unix.Fstat(next, &info); err != nil {
			unix.Close(next)
			unix.Close(fd)
			return -1, fmt.Errorf("inspect protected credential directory: %w", err)
		}
		if isRoot || last {
			if info.Uid != uint32(os.Geteuid()) || info.Mode&0o077 != 0 {
				unix.Close(next)
				unix.Close(fd)
				return -1, fmt.Errorf("credential directory is not private and owner-controlled")
			}
		} else if info.Mode&0o022 != 0 && info.Mode&unix.S_ISVTX == 0 {
			// A non-sticky writable ancestor would allow a different user
			// to swap the protected state directory between invocations.
			unix.Close(next)
			unix.Close(fd)
			return -1, fmt.Errorf("credential path has untrusted writable ancestor")
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}
