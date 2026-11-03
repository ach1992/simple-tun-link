package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/carrier/quic"
	"github.com/ach1992/simple-tun-link/internal/carrier/wss"
	"golang.org/x/sys/unix"
)

// menuExpectedCompanionRecord matches the canonical embedded installer's
// published format. The WSS archive pin differs from its executable pin.
func menuExpectedCompanionRecord(spec menuCompanionSpec) ([]byte, error) {
	var kind menuCompanionKind
	switch spec.action {
	case "companion-wss":
		kind = menuCompanionWSS
	case "companion-quic":
		kind = menuCompanionQUIC
	default:
		return nil, fmt.Errorf("unknown selected companion")
	}
	approved, ok := menuPinnedCompanion(kind, runtime.GOARCH)
	if !ok || spec.action != approved.action || spec.argument != approved.argument ||
		spec.version != approved.version || spec.asset != approved.asset ||
		spec.digest != approved.digest {
		return nil, fmt.Errorf("selected companion identity is not the approved release")
	}
	if kind == menuCompanionWSS {
		binaryHash := wss.PinnedAMD64SHA256
		if runtime.GOARCH == "arm64" {
			binaryHash = wss.PinnedARM64SHA256
		}
		return []byte(fmt.Sprintf("format=1\nproject=simple-tun-link\ncompanion=wstunnel\nversion=11.0.0\narchive_sha256=%s\nsha256=%s\n",
			spec.digest, binaryHash)), nil
	}
	binaryHash := quic.PinnedAMD64SHA256
	if runtime.GOARCH == "arm64" {
		binaryHash = quic.PinnedARM64SHA256
	}
	return []byte(fmt.Sprintf("format=1\nproject=simple-tun-link\ncompanion=hysteria\nversion=2.13.0\nsha256=%s\n", binaryHash)), nil
}

// menuInspectOwnedCompanionRecord is a read-only part of first-use admission,
// not a substitute for the canonical installer or its maintenance lock.
// Descriptor-relative, NOFOLLOW traversal prevents redirected record reads;
// the caller must first verify the independently pinned executable.
func menuInspectOwnedCompanionRecord(spec menuCompanionSpec, owner uint32) error {
	const unverified = "companion ownership record is missing, unsafe or inconsistent"
	expected, err := menuExpectedCompanionRecord(spec)
	if err != nil || !filepath.IsAbs(spec.record) || filepath.Clean(spec.record) != spec.record ||
		spec.record == "/" || len(expected) == 0 || len(expected) > 512 {
		return fmt.Errorf(unverified)
	}
	components := strings.Split(strings.TrimPrefix(spec.record, "/"), "/")
	parent, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf(unverified)
	}
	defer func() { _ = unix.Close(parent) }()
	for _, component := range components[:len(components)-1] {
		fd, err := unix.Openat(parent, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf(unverified)
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
			(stat.Uid != 0 && stat.Uid != owner) ||
			(stat.Mode&0o022 != 0 && stat.Mode&unix.S_ISVTX == 0) {
			_ = unix.Close(fd)
			return fmt.Errorf(unverified)
		}
		_ = unix.Close(parent)
		parent = fd
	}
	fd, err := unix.Openat(parent, components[len(components)-1],
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf(unverified)
	}
	file := os.NewFile(uintptr(fd), "companion-install-record")
	defer file.Close()

	var before, after, entry unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != owner || before.Mode&0o7777 != 0o600 ||
		before.Nlink != 1 || before.Size != int64(len(expected)) {
		return fmt.Errorf(unverified)
	}
	contents, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil || !bytes.Equal(contents, expected) {
		return fmt.Errorf(unverified)
	}
	if unix.Fstat(fd, &after) != nil ||
		unix.Fstatat(parent, components[len(components)-1], &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!menuSameRecordIdentity(before, after) || !menuSameRecordIdentity(after, entry) {
		return fmt.Errorf(unverified)
	}
	return nil
}

func menuSameRecordIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink &&
		a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Used by Create and Import; an exact pinned executable without a matching
// canonical install record is unverified and must never be silently adopted.
func menuInspectInstalledCompanion(spec menuCompanionSpec, executableInspect func() error) error {
	if err := executableInspect(); err != nil {
		return err
	}
	return menuInspectOwnedCompanionRecord(spec, uint32(os.Geteuid()))
}
