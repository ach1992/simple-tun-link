// Package hostidentity supplies positive, kernel-issued host lifetime
// identity for fail-closed, Owner-approved cold-reboot recovery. It cannot
// establish absence of objects created by a different actor in the NEW boot.
package hostidentity

import (
	"fmt"
	"os"
	"strings"
)

const kernelBootID = "/proc/sys/kernel/random/boot_id"

// ValidBootID accepts canonical, lowercase Linux kernel boot UUIDs only.
// A stored UUID is nonsecret, but its absence/malformed state never becomes
// an authorization to release original WSS resource reservations.
func ValidBootID(v string) bool {
	if len(v) != 36 || v == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch i {
		case 8, 13, 18, 23:
			if v[i] != '-' {
				return false
			}
		default:
			if !((v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f')) {
				return false
			}
		}
	}
	return true
}

// CurrentKernelBootID reads a trusted, fixed kernel procfs identity. No CLI,
// env, JSON document, user-configurable file path or caller token can override
// it in the production binary. A new kernel boot invalidates ALL old kernel
// WG instances, including moved-UP/DOWN across network namespaces.
func CurrentKernelBootID() (string, error) {
	value, err := os.ReadFile(kernelBootID)
	if err != nil || len(value) > 64 {
		return "", fmt.Errorf("kernel boot generation unavailable")
	}
	id := strings.TrimSpace(string(value))
	if !ValidBootID(id) {
		return "", fmt.Errorf("kernel boot generation invalid")
	}
	return id, nil
}
