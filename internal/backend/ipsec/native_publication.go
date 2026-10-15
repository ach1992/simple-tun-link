package ipsec

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The producer is called only by the separately confirmed, owner-locked
// native provisioner; these receipt names do not grant service authority.
const (
	nativeOriginName         = "strongswan.conf.origin"
	nativeOriginXattr        = "user.simple_tun_link.ipsec_origin"
	nativeOriginLimit        = 512
	nativeConfigStageName    = ".stl-native-config.pending"
	nativeConfigReceiptStage = ".stl-native-receipt.pending"
)

type NativeOriginAssessment string

const (
	NativeOriginVerified   NativeOriginAssessment = "receipt_bound_snapshot"
	NativeOriginMissing    NativeOriginAssessment = "not_provisioned"
	NativeOriginConflict   NativeOriginAssessment = "requires_reconciliation"
	NativeOriginUnverified NativeOriginAssessment = "unverified"
)

// InspectNativeExclusiveConfigOrigin checks a durable, STL-created publication
// record against the CURRENT protected file and its private inode xattr.
// It does not prove service/process/VICI/external-writer ownership, grant
// startup authority, or serialize another privileged actor after return.
func InspectNativeExclusiveConfigOrigin() NativeOriginAssessment {
	return inspectNativeOriginAt("/", 0)
}

type nativeOriginReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	Nonce         string `json:"nonce"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	ConfigSHA256  string `json:"config_sha256"`
}

var (
	errNativePublicationConflict = errors.New("native IPsec configuration publication conflicts with existing state")
	errNativePublicationUnknown  = errors.New("native IPsec configuration publication unverified")
	errNativePublicationPending  = errors.New("native IPsec configuration publication may be incomplete; reconcile before retry")
)

type nativePublishHooks struct {
	stageDirSync    func(int) error // test-only fsync failure seam; nil uses unix.Fsync
	afterStage      func() error    // test-only crash after durable pending config
	afterReceipt    func() error    // test-only failure injection
	beforeCanonical func() error
	afterCanonical  func() error
	nonceSource     io.Reader // test-only deterministic entropy seam; nil uses crypto/rand.Reader
}

// newNativeOriginNonce uses the exact nonzero nonce domain required by the
// origin receipt inspector. A zero draw is valid entropy output, but must not
// become a published receipt that our own inspector rejects. The retry bound
// also ensures a failing entropy source cannot hang a publication attempt.
func newNativeOriginNonce(source io.Reader) ([16]byte, error) {
	var nonce [16]byte
	if source == nil {
		return nonce, errNativePublicationUnknown
	}
	const maxDraws = 8
	for attempt := 0; attempt < maxDraws; attempt++ {
		if _, err := io.ReadFull(source, nonce[:]); err != nil {
			return [16]byte{}, err
		}
		if nonce != ([16]byte{}) {
			return nonce, nil
		}
	}
	return [16]byte{}, errNativePublicationUnknown
}

// publishNativeConfigAt is called by the exclusive, freshly confirmed native
// provisioner and private fixtures. Its durable fixed pending stage is inspected
// on future attempts. Receipt is synced BEFORE the no-replace canonical rename;
// ambiguous failures are retained for manual reconciliation, never adopted.
func publishNativeConfigAt(root string, owner uint32, hooks nativePublishHooks) error {
	chain, err := openNativePublicationChain(root, owner, true)
	if err != nil {
		if errors.Is(err, errNativePublicationConflict) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return errNativePublicationConflict
		}
		return errNativePublicationUnknown
	}
	defer chain.close()
	dir := chain.parent()
	if err := nativeMustBeAbsent(dir, nativeOriginName); err != nil {
		return err
	}
	if err := nativeMustBeAbsent(dir, "strongswan.conf"); err != nil {
		return err
	}
	for _, stage := range []string{nativeConfigStageName, nativeConfigReceiptStage} {
		if err := nativeMustBeAbsent(dir, stage); err != nil {
			return err
		}
	}
	if !chain.trusted(owner) {
		return errNativePublicationConflict
	}

	entropy := hooks.nonceSource
	if entropy == nil {
		entropy = rand.Reader
	}
	nonce, err := newNativeOriginNonce(entropy)
	if err != nil {
		return errNativePublicationUnknown
	}
	token := hex.EncodeToString(nonce[:])
	configStage := nativeConfigStageName
	receiptStage := nativeConfigReceiptStage
	// Stage is deliberately retained on ambiguous failures: an unverified
	// pathname must never be blindly unlinked, even if it looks STL-owned.
	fd, err := unix.Openat(dir, configStage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return errNativePublicationUnknown
	}
	defer unix.Close(fd)
	if unix.Fchmod(fd, 0o600) != nil || nativeWriteAll(fd, []byte(nativeExclusiveConfigV1)) != nil ||
		unix.Fsetxattr(fd, nativeOriginXattr, []byte(token), 0) != nil || unix.Fsync(fd) != nil {
		return errNativePublicationUnknown
	}
	var source unix.Stat_t
	if unix.Fstat(fd, &source) != nil || !nativeRegularIdentity(source, owner, len(nativeExclusiveConfigV1)) ||
		!nativePathMatchesFD(dir, configStage, fd, source) || !chain.trusted(owner) {
		return errNativePublicationUnknown
	}
	// Persist the fixed pending name BEFORE the receipt can be published.
	// If syncing fails, retention/durability is uncertain; never retry blindly.
	stageDirSync := unix.Fsync
	if hooks.stageDirSync != nil {
		stageDirSync = hooks.stageDirSync
	}
	if stageDirSync(dir) != nil {
		return errNativePublicationUnknown
	}
	if hooks.afterStage != nil && hooks.afterStage() != nil {
		return errNativePublicationUnknown
	}
	receipt := nativeOriginReceipt{SchemaVersion: 1, Nonce: token, Device: uint64(source.Dev), Inode: source.Ino,
		ConfigSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(nativeExclusiveConfigV1)))}
	wire, err := json.Marshal(receipt)
	if err != nil {
		return errNativePublicationUnknown
	}
	wire = append(wire, '\n')
	receiptFD, err := unix.Openat(dir, receiptStage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return errNativePublicationUnknown
	}
	defer unix.Close(receiptFD)
	if unix.Fchmod(receiptFD, 0o600) != nil || nativeWriteAll(receiptFD, wire) != nil || unix.Fsync(receiptFD) != nil {
		return errNativePublicationUnknown
	}
	if err := unix.Renameat2(dir, receiptStage, dir, nativeOriginName, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errNativePublicationConflict
		}
		return errNativePublicationUnknown
	}
	// A prepared record can survive interruption without a canonical file.
	// No provisioner retries or adopts such an incomplete transaction.
	if unix.Fsync(dir) != nil {
		return errNativePublicationPending
	}
	if hooks.afterReceipt != nil && hooks.afterReceipt() != nil {
		return errNativePublicationPending
	}
	if !chain.trusted(owner) || !nativePathMatchesFD(dir, configStage, fd, source) ||
		!nativePathMatchesFD(dir, nativeOriginName, receiptFD, unix.Stat_t{}) {
		return errNativePublicationPending
	}
	if hooks.beforeCanonical != nil && hooks.beforeCanonical() != nil {
		return errNativePublicationPending
	}
	if !chain.trusted(owner) || !nativePathMatchesFD(dir, configStage, fd, source) {
		return errNativePublicationPending
	}
	// This syscall will not overwrite an administrator's existing canonical
	// file, even if it is byte-identical or was raced in after the preflight.
	if err := unix.Renameat2(dir, configStage, dir, "strongswan.conf", unix.RENAME_NOREPLACE); err != nil {
		return errNativePublicationPending
	}
	if hooks.afterCanonical != nil && hooks.afterCanonical() != nil {
		return errNativePublicationPending
	}
	if unix.Fsync(dir) != nil {
		return errNativePublicationPending
	}
	if !chain.trusted(owner) || !nativePathMatchesFD(dir, "strongswan.conf", fd, unix.Stat_t{}) ||
		inspectNativeOriginAt(root, owner) != NativeOriginVerified {
		return errNativePublicationPending
	}
	return nil
}

func nativeMustBeAbsent(dir int, name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err == nil {
		return errNativePublicationConflict
	}
	return errNativePublicationUnknown
}

func nativeWriteAll(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func nativeRegularIdentity(st unix.Stat_t, owner uint32, size int) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o7777 == 0o600 &&
		st.Uid == owner && st.Nlink == 1 && st.Size == int64(size)
}

func nativePathMatchesFD(dir int, name string, fd int, before unix.Stat_t) bool {
	var current, entry unix.Stat_t
	if unix.Fstat(fd, &current) != nil || unix.Fstatat(dir, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	if before.Ino != 0 && !sameNativeIdentity(before, current) {
		return false
	}
	return sameNativeIdentity(current, entry)
}

type nativePublicationChain struct {
	fds   []int
	parts []string
}

func (c *nativePublicationChain) parent() int { return c.fds[len(c.fds)-1] }
func (c *nativePublicationChain) close() {
	for i := len(c.fds) - 1; i >= 0; i-- {
		_ = unix.Close(c.fds[i])
	}
}

// Reuse the exact canonical relative identity. Only the two private state
// directories may be created, never /var or /var/lib or a replaced symlink.
func openNativePublicationChain(root string, owner uint32, create bool) (*nativePublicationChain, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errNativePublicationUnknown
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	c := &nativePublicationChain{fds: []int{fd}, parts: []string{"var", "lib", "simple-tun-link", "ipsec"}}
	if !trustedNativeDirectory(fd, owner, false) {
		c.close()
		return nil, errNativePublicationConflict
	}
	for i, part := range c.parts {
		private := i >= 2
		next, openErr := unix.Openat(c.parent(), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) && create && private {
			if mkErr := unix.Mkdirat(c.parent(), part, 0o700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				c.close()
				return nil, mkErr
			}
			if syncErr := unix.Fsync(c.parent()); syncErr != nil {
				c.close()
				return nil, syncErr
			}
			next, openErr = unix.Openat(c.parent(), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			c.close()
			return nil, openErr
		}
		c.fds = append(c.fds, next)
		if !trustedNativeDirectory(next, owner, private) {
			c.close()
			return nil, errNativePublicationConflict
		}
	}
	if !c.trusted(owner) {
		c.close()
		return nil, errNativePublicationConflict
	}
	return c, nil
}

func (c *nativePublicationChain) trusted(owner uint32) bool {
	for i, fd := range c.fds {
		if !trustedNativeDirectory(fd, owner, i >= 3) {
			return false
		}
		if i > 0 {
			var st, opened unix.Stat_t
			if unix.Fstatat(c.fds[i-1], c.parts[i-1], &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
				unix.Fstat(fd, &opened) != nil || !sameNativeIdentity(st, opened) {
				return false
			}
		}
	}
	return true
}

// inspectNativeOriginAt never creates a file or directory. An incomplete
// receipt/config pair, replaced inode, forged xattr or altered byte profile
// is a conflict, not an authorization to adopt or repair anything.
func inspectNativeOriginAt(root string, owner uint32) NativeOriginAssessment {
	c, err := openNativePublicationChain(root, owner, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return NativeOriginMissing
		}
		if errors.Is(err, errNativePublicationConflict) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return NativeOriginConflict
		}
		return NativeOriginUnverified
	}
	defer c.close()
	dir := c.parent()
	// Canonical files being absent does not mean a prior transaction was
	// absent: every preserved pending stage blocks a fresh provisioner.
	for _, stage := range []string{nativeConfigStageName, nativeConfigReceiptStage} {
		if err := nativeMustBeAbsent(dir, stage); errors.Is(err, errNativePublicationConflict) {
			return NativeOriginConflict
		} else if err != nil {
			return NativeOriginUnverified
		}
	}
	rfd, re := unix.Openat(dir, nativeOriginName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if re == nil {
		defer unix.Close(rfd)
	}
	ffd, fe := unix.Openat(dir, "strongswan.conf", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if fe == nil {
		defer unix.Close(ffd)
	}
	if errors.Is(re, unix.ENOENT) && errors.Is(fe, unix.ENOENT) {
		return NativeOriginMissing
	}
	if (re == nil) != (fe == nil) || errors.Is(re, unix.ELOOP) || errors.Is(fe, unix.ELOOP) ||
		errors.Is(re, unix.ENOENT) || errors.Is(fe, unix.ENOENT) {
		return NativeOriginConflict
	}
	if re != nil || fe != nil {
		return NativeOriginUnverified
	}
	var rst, fst unix.Stat_t
	if unix.Fstat(rfd, &rst) != nil || unix.Fstat(ffd, &fst) != nil {
		return NativeOriginUnverified
	}
	if rst.Size <= 0 || rst.Size > nativeOriginLimit || !nativeRegularIdentity(rst, owner, int(rst.Size)) ||
		!nativeRegularIdentity(fst, owner, len(nativeExclusiveConfigV1)) {
		return NativeOriginConflict
	}
	wire := make([]byte, int(rst.Size)+1)
	n, err := nativeReadBounded(rfd, wire)
	if err != nil {
		return NativeOriginUnverified
	}
	if n != int(rst.Size) {
		return NativeOriginConflict
	}
	var receipt nativeOriginReceipt
	d := json.NewDecoder(bytes.NewReader(wire[:n]))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF {
		return NativeOriginConflict
	}
	wanted, marshalErr := json.Marshal(receipt)
	if marshalErr != nil || !bytes.Equal(wire[:n], append(wanted, '\n')) ||
		receipt.SchemaVersion != 1 || len(receipt.Nonce) != 32 || strings.ToLower(receipt.Nonce) != receipt.Nonce ||
		receipt.Inode != fst.Ino || receipt.Device != uint64(fst.Dev) ||
		receipt.ConfigSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(nativeExclusiveConfigV1))) {
		return NativeOriginConflict
	}
	token, decodeErr := hex.DecodeString(receipt.Nonce)
	if decodeErr != nil || len(token) != 16 || bytes.Equal(token, make([]byte, 16)) {
		return NativeOriginConflict
	}
	originXattr := make([]byte, 33)
	xn, xerr := unix.Fgetxattr(ffd, nativeOriginXattr, originXattr)
	if xerr != nil {
		if errors.Is(xerr, unix.ENODATA) || errors.Is(xerr, unix.ERANGE) {
			return NativeOriginConflict
		}
		return NativeOriginUnverified
	}
	if xn != 32 || !bytes.Equal(originXattr[:xn], []byte(receipt.Nonce)) {
		return NativeOriginConflict
	}
	contents := make([]byte, len(nativeExclusiveConfigV1)+1)
	n, err = nativeReadBounded(ffd, contents)
	if err != nil {
		return NativeOriginUnverified
	}
	if n != len(nativeExclusiveConfigV1) || !bytes.Equal(contents[:n], []byte(nativeExclusiveConfigV1)) {
		return NativeOriginConflict
	}
	if !nativePathMatchesFD(dir, nativeOriginName, rfd, rst) || !nativePathMatchesFD(dir, "strongswan.conf", ffd, fst) || !c.trusted(owner) {
		return NativeOriginConflict
	}
	return NativeOriginVerified
}

// Does not trust stated stat.Size without separately checked regular-file
// mode. The extra byte detects growth between fstat and read.
func nativeReadBounded(fd int, dst []byte) (int, error) {
	offset := 0
	for offset < len(dst) {
		n, err := unix.Read(fd, dst[offset:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			break
		}
		offset += n
	}
	return offset, nil
}
