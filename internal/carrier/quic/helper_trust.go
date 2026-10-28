package quic

import (
	"fmt"
	"runtime"

	"github.com/ach1992/simple-tun-link/internal/linux"
)

const (
	// Official HyNetworks/hysteria app/v2.13.0 Linux release SHA-256.
	// These are *binary* pins, not checksums of compressed archives.
	PinnedAMD64SHA256 = "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
	PinnedARM64SHA256 = "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"
	DefaultExecutable = "/usr/local/libexec/stl/hysteria"
)

// InspectPinnedHysteria establishes read-only, owner-checked, exact-inode
// identity for a separately installed official helper. It cannot install,
// start or admit a managed Link. The eventual Engine process owner must pin
// this same executable identity at startup and through service restore.
func InspectPinnedHysteria(binary string) (linux.PinnedExecutableIdentity, error) {
	if runtime.GOOS != "linux" {
		return linux.PinnedExecutableIdentity{}, fmt.Errorf("Hysteria helper supported only on Linux")
	}
	var digest string
	switch runtime.GOARCH {
	case "amd64":
		digest = PinnedAMD64SHA256
	case "arm64":
		digest = PinnedARM64SHA256
	default:
		return linux.PinnedExecutableIdentity{}, fmt.Errorf("no approved Hysteria helper for this architecture")
	}
	return linux.InspectPinnedExecutable(binary, digest)
}
