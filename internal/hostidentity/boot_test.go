package hostidentity

import (
	"errors"
	"strings"
	"testing"
)

func TestValidBootIDStrictCanonicalAndActualKernel(t *testing.T) {
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"12345678-abcd-4abc-8abc-0123456789ab", true},
		{"88eabd6c-22ab-4c9b-9d23-fb076330638c", true},
		{"", false}, {"not-a-uuid", false},
		{"00000000-0000-0000-0000-000000000000", false},
		{"12345678-ABCD-4abc-8abc-0123456789ab", false},
		{"12345678-abcd-4abc-8abc-0123456789ab ", false},
		{"12345678abcd4abc8abc0123456789ab", false},
	} {
		if got := ValidBootID(tc.value); got != tc.valid {
			t.Fatalf("boot ID %q accepted=%t wanted=%t", tc.value, got, tc.valid)
		}
	}
	got, err := CurrentKernelBootID()
	if errors.Is(err, ErrUntrustedKernelBootSource) {
		// CI may itself run in an untrusted container or with shadowed procfs.
		// Cold-boot clearance MUST be unavailable there, not silently admitted.
		t.Log("kernel-reboot recovery correctly unavailable on this host namespace/mount arrangement")
		return
	}
	if err != nil || !ValidBootID(got) {
		t.Fatalf("original host-proc kernel identity unexpectedly unreadable: %v", err)
	}
}

func TestOriginalHostProcMountRejectsVirtualizedAndBindMountedBootIDs(t *testing.T) {
	const host = "25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
	const unrelated = "26 25 0:25 / /proc/sys/fs/binfmt_misc rw,relatime - autofs systemd-1 rw\n"
	for _, tc := range []struct {
		name      string
		mountinfo string
		accept    bool
	}{
		{"host-proc", host, true},
		{"unrelated-submount", host + unrelated, true},
		{"nspawn-virtual-file", host + "90 25 0:44 /run/host/proc-sys-kernel-random-boot-id /proc/sys/kernel/random/boot_id ro - tmpfs tmpfs rw\n", false},
		{"synthetic-procfs-boot-file", host + "90 25 0:23 /123/fake /proc/sys/kernel/random/boot_id ro - proc proc rw\n", false},
		{"shadowed-sys", host + "90 25 0:23 /sys /proc/sys ro - proc proc rw\n", false},
		{"shadowed-random", host + "90 25 0:23 /sys/kernel/random /proc/sys/kernel/random ro - proc proc rw\n", false},
		{"duplicate-proc", host + host, false},
		{"wrong-proc-fstype", strings.Replace(host, "- proc proc", "- tmpfs tmpfs", 1), false},
		{"nonroot-proc", strings.Replace(host, "0:23 / /proc", "0:23 /child /proc", 1), false},
		{"missing-proc", unrelated, false},
		{"incomplete-inventory", host + "malformed\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := originalHostProcMount([]byte(tc.mountinfo)); got != tc.accept {
				t.Fatalf("mount provenance accepted=%t wanted=%t", got, tc.accept)
			}
		})
	}
}

func TestInitialHostPIDNamespaceIdentityIsKernelReserved(t *testing.T) {
	// Linux UAPI linux/nsfs.h PID_NS_INIT_INO; nested pid namespaces get
	// allocated inodes, not the fixed host initial-namespace inode.
	if initialPIDNamespace != "pid:[4026531836]" {
		t.Fatal("initial kernel PID namespace identity changed")
	}
}
