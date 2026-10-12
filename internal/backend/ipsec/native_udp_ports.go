package ipsec

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Every observed IKE (500) and NAT-T (4500) UDP binding in the calling
// network namespace must belong to the exact attested systemd MainPID.
// /proc/net/udp{,6} report socket inode, never credential/SA material.
func verifyNativeUDPPorts(pid uint32) error {
	if pid < 2 {
		return fmt.Errorf("native UDP socket owner missing")
	}
	owned := make(map[uint64]bool)
	fdRoot := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(fdRoot)
	if err != nil || len(fds) > 8192 {
		return fmt.Errorf("native daemon descriptor inventory unavailable")
	}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdRoot, fd.Name()))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			} // daemon closed an FD between readdir and readlink
			return fmt.Errorf("native daemon descriptor identity ambiguous")
		}
		if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
			continue
		}
		inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
		if err != nil || inode == 0 {
			return fmt.Errorf("untrusted native socket inode")
		}
		owned[inode] = true
	}
	seen := map[uint16]bool{}
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("unreadable IKE UDP inventory")
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, 4<<20+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > 4<<20 {
			clear(raw)
			return fmt.Errorf("unreadable bounded IKE UDP inventory")
		}
		lines := strings.Split(string(raw), "\n")
		clear(raw)
		for _, line := range lines[1:] {
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			if len(parts) < 10 {
				return fmt.Errorf("incomplete native UDP inventory")
			}
			local := parts[1]
			last := strings.LastIndexByte(local, ':')
			if last < 0 || len(local)-last-1 != 4 {
				return fmt.Errorf("invalid native UDP endpoint")
			}
			value, err := strconv.ParseUint(local[last+1:], 16, 16)
			if err != nil {
				return fmt.Errorf("invalid native UDP port")
			}
			port := uint16(value)
			if port != 500 && port != 4500 {
				continue
			}
			inode, err := strconv.ParseUint(parts[9], 10, 64)
			if err != nil || inode == 0 || !owned[inode] {
				return fmt.Errorf("foreign or unknown IKE/NAT-T UDP listener")
			}
			seen[port] = true
		}
	}
	if !seen[500] || !seen[4500] {
		return fmt.Errorf("native daemon must own both standard IKE/NAT-T UDP listeners")
	}
	return nil
}
