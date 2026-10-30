package quic

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ach1992/simple-tun-link/internal/credentials"
	"golang.org/x/sys/unix"
)

var errInvalidPinnedOperation = errors.New("invalid pinned QUIC material operation")

// MaterialIdentity is secret-free exact-generation evidence for canonical
// State. CertificateSHA256 hashes the leaf DER and AuthorizationSHA256 hashes
// the token without its file newline, matching HelperConfigIdentity. TLSKey,
// TrustCA and HelperConfig hashes cover the exact protected file bytes.
// The generation receipt independently binds every original file inode/hash.
type MaterialIdentity struct {
	CertificateSHA256, TLSKeySHA256, TrustCASHA256, AuthorizationSHA256, HelperConfigSHA256 string
	ObfuscationSHA256                                                                       string `json:"ObfuscationSHA256,omitempty"`
	DirectoryDevice, DirectoryInode, ReceiptDevice, ReceiptInode                            uint64
}

type pinnedMaterialFile struct {
	name     string
	file     *os.File
	original unix.Stat_t
}

// GenerationPin retains read-only descriptors through an Engine transaction.
// It must be used serially while the canonical locks remain held. Close only
// releases descriptors; it never removes material, stops a helper or publishes
// State. A pin does not freeze privileged in-place writes.
type GenerationPin struct {
	root, binary, nonce string
	plan                Plan
	port                uint16
	expected            HelperConfigIdentity
	verify              helperVerifier
	creds, parent, dir  int
	original            unix.Stat_t
	files               []pinnedMaterialFile
	identity            MaterialIdentity
	closed              bool
	recordedOnly        bool
}

func OpenPinnedGeneration(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity) (*GenerationPin, error) {
	return openPinnedGeneration(ctx, root, plan, port, binary, nonce, expected, InspectPinnedHysteria)
}

// OpenPinnedGenerationForRemoval checks the original receipt and exact bytes
// without granting current TLS trust. Expired original credentials must not
// prevent stopping/removing their owned Link. VerifyForLaunch remains required
// before any helper start, including a rollback of a Remove operation.
func OpenPinnedGenerationForRemoval(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity) (*GenerationPin, error) {
	return openPinnedGenerationMode(ctx, root, plan, port, binary, nonce, expected, InspectPinnedHysteria, true)
}

func openPinnedGeneration(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity, verify helperVerifier) (_ *GenerationPin, result error) {
	return openPinnedGenerationMode(ctx, root, plan, port, binary, nonce, expected, verify, false)
}

func openPinnedGenerationMode(ctx context.Context, root string, plan Plan, port uint16,
	binary, nonce string, expected HelperConfigIdentity, verify helperVerifier, recordedOnly bool) (_ *GenerationPin, result error) {
	if ctx == nil || verify == nil || !validGenerationNonce(nonce) || helperConfigPreflight(root, plan, port, binary) != nil {
		return nil, errInvalidPinnedOperation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := &GenerationPin{root: root, binary: binary, nonce: nonce, plan: plan, port: port,
		expected: expected, verify: verify, creds: -1, parent: -1, dir: -1, recordedOnly: recordedOnly}
	defer func() {
		if result != nil {
			_ = p.Close()
		}
	}()
	var err error
	p.creds, err = credentials.OpenProtected(root, false)
	if err != nil {
		return nil, err
	}
	p.parent, err = credentials.OpenOwnedPrivateDir(p.creds, "quic", false)
	if err != nil {
		return nil, err
	}
	p.dir, err = credentials.OpenOwnedPrivateDir(p.parent, string(plan.LinkID), false)
	if err != nil {
		return nil, err
	}
	if unix.Fstat(p.dir, &p.original) != nil || generationDirectoryPinned(p.parent, p.dir, string(plan.LinkID), p.original) != nil {
		return nil, fmt.Errorf("QUIC generation directory changed before pin")
	}
	if err := inspectGenerationReceiptFD(p.dir, plan, nonce, expected); err != nil {
		return nil, err
	}
	names, err := generationFiles(plan)
	if err != nil {
		return nil, err
	}
	names = append(names, generationReceiptName)
	role, _ := roleFiles(plan.Role)
	p.identity = MaterialIdentity{CertificateSHA256: expected.Credentials.CertificateSHA256,
		TrustCASHA256: expected.Credentials.TrustCASHA256, AuthorizationSHA256: expected.Credentials.AuthorizationSHA256,
		ObfuscationSHA256:  expected.Credentials.ObfuscationSHA256,
		HelperConfigSHA256: expected.ConfigSHA256, DirectoryDevice: uint64(p.original.Dev), DirectoryInode: p.original.Ino}
	for _, name := range names {
		witness, err := privateFileWitness(p.dir, name)
		if err != nil {
			return nil, err
		}
		fd, err := unix.Openat(p.dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("QUIC generation pin unavailable")
		}
		f := os.NewFile(uintptr(fd), "quic-generation-pin")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != witness.Device || st.Ino != witness.Inode {
			_ = f.Close()
			return nil, fmt.Errorf("QUIC generation changed before pin")
		}
		p.files = append(p.files, pinnedMaterialFile{name: name, file: f, original: st})
		if name == role[1] {
			p.identity.TLSKeySHA256 = witness.SHA256
		}
		if name == generationReceiptName {
			p.identity.ReceiptDevice, p.identity.ReceiptInode = witness.Device, witness.Inode
		}
	}
	if err := p.Verify(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Identity returns historical public evidence. It is not a capability to
// adopt or delete a currently matching filesystem or host object.
func (p *GenerationPin) Identity() MaterialIdentity {
	if p == nil {
		return MaterialIdentity{}
	}
	return p.identity
}

func (p *GenerationPin) Verify(ctx context.Context) error {
	if p == nil || p.closed || p.dir < 0 || ctx == nil {
		return errInvalidPinnedOperation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := generationDirectoryPinned(p.parent, p.dir, string(p.plan.LinkID), p.original); err != nil {
		return err
	}
	for _, pin := range p.files {
		var held, path unix.Stat_t
		if unix.Fstat(int(pin.file.Fd()), &held) != nil || unix.Fstatat(p.dir, pin.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			!samePinnedMaterial(pin.original, held) || !samePinnedMaterial(held, path) {
			return fmt.Errorf("QUIC original material inode changed")
		}
	}
	if err := inspectGenerationReceiptFD(p.dir, p.plan, p.nonce, p.expected); err != nil {
		return err
	}
	if !p.recordedOnly {
		if err := p.verifyLaunch(); err != nil {
			return err
		}
	}
	// Re-resolve the canonical private parents to detect a directory swap
	// even when our retained descriptors still expose an intact old tree.
	creds, err := credentials.OpenProtected(p.root, false)
	if err != nil {
		return fmt.Errorf("QUIC generation canonical private parent unavailable")
	}
	defer unix.Close(creds)
	if !sameGenerationDirectoryFD(p.creds, creds) {
		return fmt.Errorf("QUIC generation canonical private parent changed")
	}
	parent, err := credentials.OpenOwnedPrivateDir(creds, "quic", false)
	if err != nil {
		return fmt.Errorf("QUIC generation canonical QUIC parent unavailable")
	}
	defer unix.Close(parent)
	if !sameGenerationDirectoryFD(p.parent, parent) {
		return fmt.Errorf("QUIC generation canonical QUIC parent changed")
	}
	if err := generationDirectoryPinned(parent, p.dir, string(p.plan.LinkID), p.original); err != nil {
		return err
	}
	return ctx.Err()
}

// VerifyForLaunch requires current TLS validity and the exact admitted helper
// configuration even for a pin opened only to remove an original generation.
func (p *GenerationPin) VerifyForLaunch(ctx context.Context) error {
	if err := p.Verify(ctx); err != nil {
		return err
	}
	if !p.recordedOnly {
		return nil
	}
	return p.verifyLaunch()
}

func (p *GenerationPin) verifyLaunch() error {
	actual, err := inspectHelperConfigFD(p.dir, p.root, p.plan, p.port, p.binary, p.verify)
	if err != nil || actual != p.expected {
		return fmt.Errorf("QUIC pinned generation semantic drift or TLS validity failure")
	}
	return nil
}

func (p *GenerationPin) Close() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	var result error
	for _, pin := range p.files {
		result = errors.Join(result, pin.file.Close())
	}
	p.files = nil
	for _, fd := range []int{p.dir, p.parent, p.creds} {
		if fd >= 0 {
			result = errors.Join(result, unix.Close(fd))
		}
	}
	p.dir, p.parent, p.creds = -1, -1, -1
	return result
}

func samePinnedMaterial(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
