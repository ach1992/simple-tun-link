package linux

import "github.com/ach1992/simple-tun-link/internal/pinnedexec"

// PinnedExecutableIdentity preserves the existing Linux/WSS trust API.
// The single underlying verifier lives below the Linux service adapters so
// canonical Engine code may inspect QUIC material without an import cycle.
type PinnedExecutableIdentity = pinnedexec.Identity

// InspectPinnedExecutable retains the existing exact trusted-binary checks.
func InspectPinnedExecutable(binary, expectedSHA256 string) (PinnedExecutableIdentity, error) {
	return pinnedexec.Inspect(binary, expectedSHA256)
}
