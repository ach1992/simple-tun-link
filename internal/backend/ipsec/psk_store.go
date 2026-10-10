// Package ipsec holds only Link-scoped identities and protected credential
// primitives until the canonical Engine can verify safe daemon mutations.
package ipsec

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

const (
	pskLength      = 32
	pskWireHexSize = pskLength * 2
)

// PSK is deliberately opaque to generic JSON and formatting. Only callers
// handling an explicitly SENSITIVE Quick Link or VICI owner-bound transaction
// may extract a copy. Zeroize every borrowed secret copy when finished.
type PSK struct{ material [pskLength]byte }

func ParsePSK(raw []byte) (PSK, error) {
	if len(raw) != pskLength {
		return PSK{}, fmt.Errorf("IPsec v0.1 requires a 256-bit shared secret")
	}
	var key PSK
	copy(key.material[:], raw)
	var zero [pskLength]byte
	if subtle.ConstantTimeCompare(key.material[:], zero[:]) == 1 {
		key.Zeroize()
		return PSK{}, fmt.Errorf("IPsec PSK must not be all zero")
	}
	return key, nil
}

// SecretBytes returns a NEW copy only for an explicitly secret-bearing
// transaction. The caller must clear the returned bytes.
func (p PSK) SecretBytes() []byte {
	return append([]byte(nil), p.material[:]...)
}

func (p *PSK) Zeroize() {
	if p != nil {
		clear(p.material[:])
	}
}
func (PSK) String() string     { return "[IPsec PSK REDACTED]" }
func (p PSK) GoString() string { return p.String() }
func (PSK) MarshalJSON() ([]byte, error) {
	return json.Marshal("[IPsec PSK REDACTED]")
}

// PSKStore stores each Link's key in a protected file distinct from WireGuard.
// Its Put/Ensure operations must eventually be invoked ONLY by the Engine
// under canonical per-Link maintenance/resource locks. This preliminary
// module intentionally has no credential retirement or VICI load authority.
type PSKStore struct{ stateRoot string }

func NewPSKStore(stateRoot string) (*PSKStore, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || stateRoot == "/" {
		return nil, fmt.Errorf("private IPsec state root must be an absolute clean path")
	}
	return &PSKStore{stateRoot: stateRoot}, nil
}

func (s *PSKStore) keyName(id domain.LinkID) (string, error) {
	if s == nil {
		return "", fmt.Errorf("protected IPsec key store unavailable")
	}
	if err := id.Validate(); err != nil {
		return "", fmt.Errorf("invalid IPsec credential Link ID")
	}
	return string(id) + ".ipsecpsk", nil
}

// PutNew publishes a private PSK using a fully synced temporary inode plus
// no-replace linkat. An existing credential (even a symlink) is never replaced.
// A post-publication fsync failure retains the key for operator reconciliation.
func (s *PSKStore) PutNew(id domain.LinkID, raw []byte) error {
	name, err := s.keyName(id)
	if err != nil {
		return err
	}
	key, err := ParsePSK(raw)
	if err != nil {
		return err
	}
	defer key.Zeroize()
	dirfd, err := credentials.OpenProtected(s.stateRoot, true)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("cannot allocate secret file identity")
	}
	temp := "." + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := unix.Openat(dirfd, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("cannot stage protected IPsec credential")
	}
	defer unix.Unlinkat(dirfd, temp, 0)
	if err := unix.Fchmod(fd, 0o600); err != nil {
		unix.Close(fd)
		return fmt.Errorf("cannot protect staged IPsec credential")
	}
	content := make([]byte, pskWireHexSize+1)
	defer clear(content)
	hex.Encode(content[:pskWireHexSize], key.material[:])
	content[pskWireHexSize] = '\n'
	for len(content) > 0 {
		n, writeErr := unix.Write(fd, content)
		if errors.Is(writeErr, unix.EINTR) {
			continue
		}
		if writeErr != nil || n <= 0 {
			unix.Close(fd)
			return fmt.Errorf("cannot write protected IPsec credential")
		}
		content = content[n:]
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		return fmt.Errorf("cannot sync protected IPsec credential")
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("cannot close protected IPsec credential")
	}
	if err := unix.Linkat(dirfd, temp, dirfd, name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("IPsec credential already exists for this Link")
		}
		return fmt.Errorf("cannot publish protected IPsec credential")
	}
	if err := unix.Unlinkat(dirfd, temp, 0); err != nil {
		return fmt.Errorf("IPsec credential published but temporary cleanup uncertain")
	}
	if err := unix.Fsync(dirfd); err != nil {
		return fmt.Errorf("IPsec credential published but durability uncertain")
	}
	return nil
}

// EnsureExact permits an idempotent replay only with the identical 256-bit
// credential; it never replaces any existing Link key.
func (s *PSKStore) EnsureExact(id domain.LinkID, raw []byte) error {
	key, err := ParsePSK(raw)
	if err != nil {
		return err
	}
	defer key.Zeroize()
	existing, err := s.Load(id)
	if errors.Is(err, os.ErrNotExist) {
		return s.PutNew(id, raw)
	}
	if err != nil {
		return err
	}
	defer existing.Zeroize()
	if subtle.ConstantTimeCompare(existing.material[:], key.material[:]) != 1 {
		return fmt.Errorf("IPsec credential conflicts with the existing Link key")
	}
	return nil
}

// Load verifies a read-only O_NOFOLLOW descriptor: regular/singly-linked,
// owner-only 0600, strictly 64 lowercase hex digits and one newline.
// This is NOT an authorization to unload/replace a VICI daemon object.
func (s *PSKStore) Load(id domain.LinkID) (PSK, error) {
	name, err := s.keyName(id)
	if err != nil {
		return PSK{}, err
	}
	dirfd, err := credentials.OpenProtected(s.stateRoot, false)
	if err != nil {
		return PSK{}, err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return PSK{}, fmt.Errorf("cannot open protected IPsec credential: %w", err)
	}
	file := os.NewFile(uintptr(fd), "ipsec-credential")
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return PSK{}, fmt.Errorf("invalid protected IPsec credential file identity")
	}
	buf, err := io.ReadAll(io.LimitReader(file, pskWireHexSize+2))
	if err != nil || len(buf) != pskWireHexSize+1 || buf[pskWireHexSize] != '\n' {
		clear(buf)
		return PSK{}, fmt.Errorf("invalid protected IPsec credential encoding")
	}
	defer clear(buf)
	var key PSK
	if _, err := hex.Decode(key.material[:], buf[:pskWireHexSize]); err != nil {
		key.Zeroize() // Decode may have filled a prefix of the secret buffer.
		return PSK{}, fmt.Errorf("invalid protected IPsec credential encoding")
	}
	check := make([]byte, pskWireHexSize)
	hex.Encode(check, key.material[:])
	ok := subtle.ConstantTimeCompare(buf[:pskWireHexSize], check) == 1
	clear(check)
	if !ok {
		key.Zeroize()
		return PSK{}, fmt.Errorf("invalid protected IPsec credential encoding")
	}
	var zero [pskLength]byte
	if subtle.ConstantTimeCompare(key.material[:], zero[:]) == 1 {
		key.Zeroize()
		return PSK{}, fmt.Errorf("invalid protected IPsec credential material")
	}
	return key, nil
}
