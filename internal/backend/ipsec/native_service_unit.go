package ipsec

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// NativeExclusiveServiceUnitPath is the proposed STL-specific systemd unit.
// It must never replace, alias, enable or stop a distro strongSwan unit.
const NativeExclusiveServiceUnitPath = "/etc/systemd/system/simple-tun-link-ipsec.service"

// The reviewed unit deliberately has NO ExecStartPost, ExecReload or Install
// section. Distro strongswan.service units may run swanctl --load-all on
// startup/reload, which would bypass per-Link ownership and secret admission.
// The separately confirmed native provisioner may publish these exact
// bytes and start this reviewed private service only after effective
// pre-start D-Bus admission; a unit file alone grants no execution right.
//
// RuntimeDirectoryMode and UMask are defensive intentions, NOT proof of
// effective socket access or confinement. Prior to any operational start,
// systemd's *loaded* unit, every drop-in/generator, package hooks, executable,
// selected environment, process, private VICI writer and CFG logging policy
// must be attested independently.
const nativeExclusiveServiceUnitV1 = `# Proposed STL-exclusive charon-systemd unit v1; not an activation permit.
[Unit]
Description=simple-tun-link private IPsec IKEv2 daemon
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
Environment=STRONGSWAN_CONF=/var/lib/simple-tun-link/ipsec/strongswan.conf
UMask=0077
RuntimeDirectory=simple-tun-link/ipsec
RuntimeDirectoryMode=0700
ExecStart=/usr/sbin/charon-systemd
Restart=no
`

// NativeExclusiveServiceUnitV1 returns a fresh, exact byte copy. It never
// invokes systemctl or alters /etc, packages, the daemon, VICI or the kernel.
func NativeExclusiveServiceUnitV1() []byte {
	return []byte(nativeExclusiveServiceUnitV1)
}

// CheckNativeExclusiveServiceUnitV1 is a strict source-profile check, NOT an
// origin receipt or loaded/effective systemd unit attestation.
func CheckNativeExclusiveServiceUnitV1(data []byte) error {
	if !bytes.Equal(data, []byte(nativeExclusiveServiceUnitV1)) {
		return fmt.Errorf("native-exclusive IPsec service unit differs from reviewed profile")
	}
	return nil
}

// NativeServiceUnitAssessment is only a time-local file observation. Even an
// exact result does NOT prove STL published the inode or systemd uses it.
type NativeServiceUnitAssessment string

const (
	NativeServiceUnitExact      NativeServiceUnitAssessment = "exact_bytes_only"
	NativeServiceUnitMissing    NativeServiceUnitAssessment = "not_provisioned"
	NativeServiceUnitConflict   NativeServiceUnitAssessment = "untrusted"
	NativeServiceUnitUnverified NativeServiceUnitAssessment = "unverified"
)

// InspectNativeExclusiveServiceUnit is read-only, restricted to the canonical
// host root and UID 0; no caller-supplied path or user identity is accepted.
func InspectNativeExclusiveServiceUnit() NativeServiceUnitAssessment {
	return inspectNativeServiceUnitAt("/", 0, nil)
}

// The test seam runs against a disposable fake root. Production never calls
// it with an alternate path or owner. The inspected identity cannot grant
// future startup or deletion authority; arbitrary root/systemd actors are
// outside this file reader's serialization boundary.
func inspectNativeServiceUnitAt(root string, owner uint32, afterRead func()) NativeServiceUnitAssessment {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return NativeServiceUnitUnverified
	}
	parts := []string{"etc", "systemd", "system", "simple-tun-link-ipsec.service"}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return NativeServiceUnitUnverified
	}
	fds := []int{rootFD}
	defer func() {
		for i := len(fds) - 1; i >= 0; i-- {
			_ = unix.Close(fds[i])
		}
	}()
	if !trustedNativeDirectory(rootFD, owner, false) {
		return NativeServiceUnitConflict
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fds[len(fds)-1], part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nativeServiceUnitOpenStatus(err)
		}
		fds = append(fds, next)
		if !trustedNativeDirectory(next, owner, false) {
			return NativeServiceUnitConflict
		}
	}
	parent := fds[len(fds)-1]
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nativeServiceUnitOpenStatus(err)
	}
	fds = append(fds, fd)
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return NativeServiceUnitUnverified
	}
	// A more private read-only or owner-only unit is acceptable. Reject
	// set-ID/sticky bits, all execution, group/other writes and missing
	// owner readability; the source profile does not require world read.
	mode := before.Mode & 0o7777
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != owner ||
		mode&0o7000 != 0 || mode&0o111 != 0 || mode&0o022 != 0 || mode&0o400 == 0 ||
		before.Nlink != 1 || before.Size != int64(len(nativeExclusiveServiceUnitV1)) {
		return NativeServiceUnitConflict
	}
	// File must be regular before a bounded read. Never copy its bytes,
	// pathname, or raw read errors into diagnostics or logs.
	data := make([]byte, len(nativeExclusiveServiceUnitV1)+1)
	used := 0
	for used < len(data) {
		n, readErr := unix.Read(fd, data[used:])
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			clear(data)
			return NativeServiceUnitUnverified
		}
		if n == 0 {
			break
		}
		used += n
	}
	equal := bytes.Equal(data[:used], []byte(nativeExclusiveServiceUnitV1))
	clear(data)
	if !equal {
		return NativeServiceUnitConflict
	}
	if afterRead != nil {
		afterRead() // test-only inode/path replacement injection
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil {
		return NativeServiceUnitUnverified
	}
	if !sameNativeIdentity(before, after) {
		return NativeServiceUnitConflict
	}
	for i := len(fds) - 1; i > 0; i-- {
		var entry, opened unix.Stat_t
		if unix.Fstatat(fds[i-1], parts[i-1], &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			unix.Fstat(fds[i], &opened) != nil {
			return NativeServiceUnitConflict
		}
		if !sameNativeIdentity(entry, opened) {
			return NativeServiceUnitConflict
		}
		if i < len(fds)-1 && !trustedNativeDirectory(fds[i], owner, false) {
			return NativeServiceUnitConflict
		}
	}
	if !trustedNativeDirectory(rootFD, owner, false) {
		return NativeServiceUnitConflict
	}
	return NativeServiceUnitExact
}

func nativeServiceUnitOpenStatus(err error) NativeServiceUnitAssessment {
	switch {
	case errors.Is(err, unix.ENOENT):
		return NativeServiceUnitMissing
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return NativeServiceUnitConflict
	default:
		return NativeServiceUnitUnverified
	}
}
