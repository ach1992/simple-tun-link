// Package hostidentity supplies positive, kernel-issued host lifetime
// identity for fail-closed, Owner-approved cold-reboot recovery. It cannot
// establish absence of objects created by a different actor in the NEW boot.
package hostidentity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	kernelBootID = "/proc/sys/kernel/random/boot_id"
	// Linux UAPI linux/nsfs.h: PID_NS_INIT_INO (initial host PID namespace).
	// A nested PID namespace cannot attest that the HOST kernel rebooted.
	initialPIDNamespace = "pid:[4026531836]"
)

// ErrUntrustedKernelBootSource is a fail-closed maintenance-only result.
// It never permits a previously reserved WSS crash journal to be consumed.
var ErrUntrustedKernelBootSource = errors.New("host kernel boot identity provenance unverified")

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

// originalHostProcMount requires an unshadowed procfs /proc mount. A bind
// mount over boot_id (including systemd-nspawn's random per-container UUID),
// or over ANY ancestor below /proc, must never prove host-kernel extinction.
// Linux mountinfo escapes spaces but none occur in this fixed target path.
func originalHostProcMount(mountinfo []byte) bool {
	found := false
	for _, line := range bytes.Split(mountinfo, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(string(line))
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+2 >= len(fields) {
			return false // incomplete namespace mount inventory
		}
		point := fields[4]
		if point == "/proc" {
			if found || fields[3] != "/" || fields[separator+1] != "proc" || fields[separator+2] != "proc" {
				return false
			}
			found = true
		} else if strings.HasPrefix(point, "/proc/") &&
			(point == kernelBootID || strings.HasPrefix(kernelBootID, point+"/")) {
			return false // a boot-ID file or ancestor has its own mount
		}
	}
	return found
}

// hostKernelBootSource admits only the initial host PID namespace and a
// completely unshadowed procfs path. Filesystem type and mount topology are
// checked together; neither a plausible UUID nor a procfs-looking path alone
// authenticates a kernel reboot. Fail closed for containers, synthetic procfs,
// inaccessible mounts and unsupported host mount arrangements.
func hostKernelBootSource() error {
	for _, path := range []string{"/proc/self/ns/pid", "/proc/1/ns/pid"} {
		got, err := os.Readlink(path)
		if err != nil || got != initialPIDNamespace {
			return ErrUntrustedKernelBootSource
		}
	}
	for i, path := range []string{"/proc", "/proc/sys", "/proc/sys/kernel", "/proc/sys/kernel/random", kernelBootID} {
		info, err := os.Lstat(path)
		if err != nil || (i < 4 && !info.IsDir()) || (i == 4 && !info.Mode().IsRegular()) {
			return ErrUntrustedKernelBootSource
		}
	}
	return nil
}

// CurrentKernelBootID obtains a host-kernel issued UUID ONLY from an attested
// original procfs file in the initial PID namespace. The mount inventory is
// checked before and after the read to reject ordinary mount replacement;
// privileged adversarial concurrent mount manipulation remains outside STL's
// documented root-trust boundary. No CLI/env/file argument can override this.
func CurrentKernelBootID() (string, error) {
	if err := hostKernelBootSource(); err != nil {
		return "", err
	}
	before, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || !originalHostProcMount(before) {
		return "", ErrUntrustedKernelBootSource
	}
	fd, err := unix.Open(kernelBootID, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", ErrUntrustedKernelBootSource
	}
	file := os.NewFile(uintptr(fd), kernelBootID)
	defer file.Close()
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &statfs); err != nil || statfs.Type != unix.PROC_SUPER_MAGIC {
		return "", ErrUntrustedKernelBootSource
	}
	value, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || len(value) > 64 {
		return "", fmt.Errorf("kernel boot generation unavailable")
	}
	after, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || !bytes.Equal(before, after) || !originalHostProcMount(after) || hostKernelBootSource() != nil {
		return "", ErrUntrustedKernelBootSource
	}
	id := strings.TrimSpace(string(value))
	if !ValidBootID(id) {
		return "", fmt.Errorf("kernel boot generation invalid")
	}
	return id, nil
}
