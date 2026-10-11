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

// Both the writer and its test seam are unexported: no CLI/Engine/installer
// calls this primitive. These paths and their modes are NOT service ownership,
// activation, startup, package-management or deletion permissions.
const (
	nativeUnitOriginName       = "simple-tun-link-ipsec.service.origin"
	nativeUnitOriginXattr      = "user.simple_tun_link.ipsec_unit_origin"
	nativeUnitOriginLimit      = 512
	nativeUnitName             = "simple-tun-link-ipsec.service"
	nativeUnitStageName        = ".stl-ipsec-unit.pending"
	nativeUnitReceiptStageName = ".stl-ipsec-unit-receipt.pending"
)

type nativeUnitOriginReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	Nonce         string `json:"nonce"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	UnitSHA256    string `json:"unit_sha256"`
}

type nativeUnitPublishHooks struct {
	afterStage      func() error // test-only crash before receipt commit
	afterReceipt    func() error // test-only crash/race injection
	beforeCanonical func() error
	afterCanonical  func() error
	nonceSource     io.Reader // nil means crypto/rand.Reader
}

// openNativeUnitChain pins root -> /etc -> /etc/systemd -> system without
// following symlinks. Never create /etc/systemd or adopt a distro unit.
// Public systemd directories need protected root ownership, not private 0700.
func openNativeUnitChain(root string, owner uint32) (*nativePublicationChain, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errNativePublicationUnknown
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	c := &nativePublicationChain{fds: []int{fd}, parts: []string{"etc", "systemd", "system"}}
	if !trustedNativeDirectory(fd, owner, false) {
		c.close()
		return nil, errNativePublicationConflict
	}
	for _, part := range c.parts {
		next, openErr := unix.Openat(c.parent(), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			c.close()
			return nil, openErr
		}
		c.fds = append(c.fds, next)
		if !trustedNativeDirectory(next, owner, false) {
			c.close()
			return nil, errNativePublicationConflict
		}
	}
	if !trustedNativeUnitChain(c, owner) {
		c.close()
		return nil, errNativePublicationConflict
	}
	return c, nil
}

func trustedNativeUnitChain(c *nativePublicationChain, owner uint32) bool {
	for i, fd := range c.fds {
		if !trustedNativeDirectory(fd, owner, false) {
			return false
		}
		if i > 0 {
			var entry, opened unix.Stat_t
			if unix.Fstatat(c.fds[i-1], c.parts[i-1], &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
				unix.Fstat(fd, &opened) != nil || !sameNativeIdentity(entry, opened) {
				return false
			}
		}
	}
	return true
}

// publishNativeUnitAt is fixture-only, deliberately unreachable from the
// operational program. Its receipt is durable BEFORE the canonical no-replace
// rename, so crash/retry ambiguity cannot adopt a foreign or half-written unit.
// It neither daemon-reloads nor starts/installs a service. An ambiguous stage,
// even an STL-shaped one, is NEVER blindly removed or retried.
func publishNativeUnitAt(root string, owner uint32, hooks nativeUnitPublishHooks) error {
	unitChain, err := openNativeUnitChain(root, owner)
	if err != nil {
		return nativeUnitPublishOpenError(err)
	}
	defer unitChain.close()
	// Do not create even a private receipt directory when a foreign unit
	// already occupies the final canonical name.
	if err := nativeMustBeAbsent(unitChain.parent(), nativeUnitName); err != nil {
		return err
	}
	stateChain, err := openNativePublicationChain(root, owner, true)
	if err != nil {
		return nativeUnitPublishOpenError(err)
	}
	defer stateChain.close()
	uDir, sDir := unitChain.parent(), stateChain.parent()
	if err := nativeMustBeAbsent(uDir, nativeUnitName); err != nil {
		return err
	}
	if err := nativeMustBeAbsent(sDir, nativeUnitOriginName); err != nil {
		return err
	}
	// Fixed private staging names make a crash BEFORE receipt publication
	// observable on the next attempt; never orphan a random .tmp inode and
	// silently try a new nonce after an interrupted transaction.
	for _, pending := range []struct {
		dir  int
		name string
	}{{uDir, nativeUnitStageName}, {sDir, nativeUnitReceiptStageName}} {
		if err := nativeMustBeAbsent(pending.dir, pending.name); err != nil {
			return err
		}
	}
	if !trustedNativeUnitChain(unitChain, owner) || !stateChain.trusted(owner) {
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
	unitStage := nativeUnitStageName
	receiptStage := nativeUnitReceiptStageName
	fd, err := unix.Openat(uDir, unitStage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errNativePublicationConflict
		}
		return errNativePublicationUnknown
	}
	defer unix.Close(fd)
	if unix.Fchmod(fd, 0o600) != nil ||
		nativeWriteAll(fd, []byte(nativeExclusiveServiceUnitV1)) != nil ||
		unix.Fsetxattr(fd, nativeUnitOriginXattr, []byte(token), 0) != nil ||
		unix.Fsync(fd) != nil {
		return errNativePublicationUnknown
	}
	var source unix.Stat_t
	if unix.Fstat(fd, &source) != nil || !nativeRegularIdentity(source, owner, len(nativeExclusiveServiceUnitV1)) ||
		!trustedNativeUnitChain(unitChain, owner) || !stateChain.trusted(owner) {
		return errNativePublicationUnknown
	}
	if hooks.afterStage != nil && hooks.afterStage() != nil {
		return errNativePublicationUnknown
	}
	receipt := nativeUnitOriginReceipt{
		SchemaVersion: 1, Nonce: token, Device: uint64(source.Dev), Inode: source.Ino,
		UnitSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(nativeExclusiveServiceUnitV1))),
	}
	wire, err := json.Marshal(receipt)
	if err != nil {
		return errNativePublicationUnknown
	}
	wire = append(wire, 10)
	rfd, err := unix.Openat(sDir, receiptStage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errNativePublicationConflict
		}
		return errNativePublicationUnknown
	}
	defer unix.Close(rfd)
	if unix.Fchmod(rfd, 0o600) != nil || nativeWriteAll(rfd, wire) != nil || unix.Fsync(rfd) != nil {
		return errNativePublicationUnknown
	}
	var receiptBefore unix.Stat_t
	if unix.Fstat(rfd, &receiptBefore) != nil || !nativeRegularIdentity(receiptBefore, owner, len(wire)) {
		return errNativePublicationUnknown
	}
	if err := unix.Renameat2(sDir, receiptStage, sDir, nativeUnitOriginName, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errNativePublicationConflict
		}
		return errNativePublicationUnknown
	}
	// After a receipt exists, every failure is a pending transaction, even
	// when a file with the expected bytes appears at the target path.
	if unix.Fsync(sDir) != nil {
		return errNativePublicationPending
	}
	// rename may update ctime on the new receipt inode. Capture the
	// *committed* identity after rename, before any adversarial test hook,
	// rather than misclassifying an ordinary rename as a changed receipt.
	var receiptCommitted unix.Stat_t
	if unix.Fstat(rfd, &receiptCommitted) != nil ||
		!nativeRegularIdentity(receiptCommitted, owner, len(wire)) ||
		receiptCommitted.Dev != receiptBefore.Dev || receiptCommitted.Ino != receiptBefore.Ino {
		return errNativePublicationPending
	}
	if hooks.afterReceipt != nil && hooks.afterReceipt() != nil {
		return errNativePublicationPending
	}
	if !trustedNativeUnitChain(unitChain, owner) || !stateChain.trusted(owner) ||
		!nativePathMatchesFD(uDir, unitStage, fd, source) ||
		!nativePathMatchesFD(sDir, nativeUnitOriginName, rfd, receiptCommitted) {
		return errNativePublicationPending
	}
	if hooks.beforeCanonical != nil && hooks.beforeCanonical() != nil {
		return errNativePublicationPending
	}
	if !trustedNativeUnitChain(unitChain, owner) || !stateChain.trusted(owner) ||
		!nativePathMatchesFD(uDir, unitStage, fd, source) ||
		!nativePathMatchesFD(sDir, nativeUnitOriginName, rfd, receiptCommitted) {
		return errNativePublicationPending
	}
	// No symlink/hardlink/byte-identical/foreign unit can be overwritten by
	// this final operation, even if created immediately after the last check.
	if err := unix.Renameat2(uDir, unitStage, uDir, nativeUnitName, unix.RENAME_NOREPLACE); err != nil {
		return errNativePublicationPending
	}
	if hooks.afterCanonical != nil && hooks.afterCanonical() != nil {
		return errNativePublicationPending
	}
	if unix.Fsync(uDir) != nil {
		return errNativePublicationPending
	}
	if !trustedNativeUnitChain(unitChain, owner) || !stateChain.trusted(owner) ||
		!nativePathMatchesFD(uDir, nativeUnitName, fd, unix.Stat_t{}) ||
		inspectNativeUnitOriginAt(root, owner) != NativeOriginVerified {
		return errNativePublicationPending
	}
	return nil
}

func nativeUnitPublishOpenError(err error) error {
	if errors.Is(err, errNativePublicationConflict) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return errNativePublicationConflict
	}
	return errNativePublicationUnknown
}

// InspectNativeExclusiveServiceUnitOrigin uses fixed "/" and UID 0 only.
// A positive receipt-bound *snapshot* never attests systemd's loaded unit,
// transient/generated units, drop-ins, executable, environment, logger,
// package hooks, service process, VICI writers or future exclusive access.
func InspectNativeExclusiveServiceUnitOrigin() NativeOriginAssessment {
	return inspectNativeUnitOriginAt("/", 0)
}

func inspectNativeUnitOriginAt(root string, owner uint32) NativeOriginAssessment {
	uChain, uerr := openNativeUnitChain(root, owner)
	if uerr == nil {
		defer uChain.close()
	}
	sChain, serr := openNativePublicationChain(root, owner, false)
	if serr == nil {
		defer sChain.close()
	}
	for _, e := range []error{uerr, serr} {
		if e != nil && !errors.Is(e, unix.ENOENT) {
			if errors.Is(e, errNativePublicationConflict) || errors.Is(e, unix.ELOOP) || errors.Is(e, unix.ENOTDIR) {
				return NativeOriginConflict
			}
			return NativeOriginUnverified
		}
	}
	if uerr == nil {
		if status := nativeUnitPendingStatus(uChain.parent(), nativeUnitStageName); status != NativeOriginMissing {
			return status
		}
	}
	if serr == nil {
		if status := nativeUnitPendingStatus(sChain.parent(), nativeUnitReceiptStageName); status != NativeOriginMissing {
			return status
		}
	}
	// Absence is safe only when BOTH sides are absent. Any stray canonical
	// unit or private prepared receipt (including after an interrupted write)
	// blocks adoption, even when the opposite parent does not exist.
	if uerr != nil && serr != nil {
		return NativeOriginMissing
	}
	if uerr != nil {
		return nativeUnitOriginAbsentSide(sChain.parent(), nativeUnitOriginName)
	}
	if serr != nil {
		return nativeUnitOriginAbsentSide(uChain.parent(), nativeUnitName)
	}
	uDir, sDir := uChain.parent(), sChain.parent()
	uFD, ue := unix.Openat(uDir, nativeUnitName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if ue == nil {
		defer unix.Close(uFD)
	}
	rFD, re := unix.Openat(sDir, nativeUnitOriginName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if re == nil {
		defer unix.Close(rFD)
	}
	if errors.Is(ue, unix.ENOENT) && errors.Is(re, unix.ENOENT) {
		return NativeOriginMissing
	}
	if (ue == nil) != (re == nil) || errors.Is(ue, unix.ELOOP) || errors.Is(re, unix.ELOOP) ||
		errors.Is(ue, unix.ENOENT) || errors.Is(re, unix.ENOENT) {
		return NativeOriginConflict
	}
	if ue != nil || re != nil {
		return NativeOriginUnverified
	}
	var us, rs unix.Stat_t
	if unix.Fstat(uFD, &us) != nil || unix.Fstat(rFD, &rs) != nil {
		return NativeOriginUnverified
	}
	if !nativeRegularIdentity(us, owner, len(nativeExclusiveServiceUnitV1)) ||
		rs.Size <= 0 || rs.Size > nativeUnitOriginLimit || !nativeRegularIdentity(rs, owner, int(rs.Size)) {
		return NativeOriginConflict
	}
	wire := make([]byte, int(rs.Size)+1)
	n, err := nativeReadBounded(rFD, wire)
	if err != nil {
		return NativeOriginUnverified
	}
	if n != int(rs.Size) {
		return NativeOriginConflict
	}
	var receipt nativeUnitOriginReceipt
	decoder := json.NewDecoder(bytes.NewReader(wire[:n]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
		return NativeOriginConflict
	}
	wanted, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(wire[:n], append(wanted, 10)) ||
		receipt.SchemaVersion != 1 || len(receipt.Nonce) != 32 || strings.ToLower(receipt.Nonce) != receipt.Nonce ||
		receipt.Device != uint64(us.Dev) || receipt.Inode != us.Ino ||
		receipt.UnitSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(nativeExclusiveServiceUnitV1))) {
		return NativeOriginConflict
	}
	token, err := hex.DecodeString(receipt.Nonce)
	if err != nil || len(token) != 16 || bytes.Equal(token, make([]byte, 16)) {
		return NativeOriginConflict
	}
	xattr := make([]byte, 33)
	xn, xerr := unix.Fgetxattr(uFD, nativeUnitOriginXattr, xattr)
	if xerr != nil {
		if errors.Is(xerr, unix.ENODATA) || errors.Is(xerr, unix.ERANGE) {
			return NativeOriginConflict
		}
		return NativeOriginUnverified
	}
	if xn != 32 || !bytes.Equal(xattr[:xn], []byte(receipt.Nonce)) {
		return NativeOriginConflict
	}
	contents := make([]byte, len(nativeExclusiveServiceUnitV1)+1)
	n, err = nativeReadBounded(uFD, contents)
	if err != nil {
		return NativeOriginUnverified
	}
	if n != len(nativeExclusiveServiceUnitV1) || !bytes.Equal(contents[:n], []byte(nativeExclusiveServiceUnitV1)) {
		return NativeOriginConflict
	}
	if !nativePathMatchesFD(uDir, nativeUnitName, uFD, us) ||
		!nativePathMatchesFD(sDir, nativeUnitOriginName, rFD, rs) ||
		!trustedNativeUnitChain(uChain, owner) || !sChain.trusted(owner) {
		return NativeOriginConflict
	}
	return NativeOriginVerified
}

func nativeUnitOriginAbsentSide(dir int, name string) NativeOriginAssessment {
	err := nativeMustBeAbsent(dir, name)
	if err == nil {
		return NativeOriginMissing
	}
	if errors.Is(err, errNativePublicationConflict) {
		return NativeOriginConflict
	}
	return NativeOriginUnverified
}

// A fixed-name staged artifact is an interrupted publication, never a
// canonical vacancy signal. This reader does not delete or resume it.
func nativeUnitPendingStatus(dir int, name string) NativeOriginAssessment {
	err := nativeMustBeAbsent(dir, name)
	if err == nil {
		return NativeOriginMissing
	}
	if errors.Is(err, errNativePublicationConflict) {
		return NativeOriginConflict
	}
	return NativeOriginUnverified
}
