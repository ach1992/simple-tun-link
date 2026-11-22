// Package spoof implements the opt-in Spoof Carrier primitives. Its inventory
// is local to each endpoint; only the owning Link's explicit destination is
// eligible for transport. No source IP proves reachability or ownership.
package spoof

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const DefaultSourcesPath = "/root/stl/spoof/sources.txt"

type Inventory struct {
	Addresses  []netip.Addr
	Duplicates int
}

// ReadSources re-reads an operator-owned local source inventory on each
// discovery/recovery cycle. It intentionally sets no source count, public-IP,
// geography, ASN or source-ownership policy. Duplicates are reported without
// repeatedly probing the same address. No packets or host changes occur here.
func ReadSources(path string) (Inventory, error) {
	if path == "" {
		path = DefaultSourcesPath
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Inventory{}, fmt.Errorf("source file must be an absolute normalized path: %q", path)
	}
	// The source file is untrusted operator input to a privileged network
	// service. Do not follow a last-component symlink during open.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return Inventory{}, fmt.Errorf("source file %q is missing: create a file with one IPv4 per line, then Recheck: %w", path, err)
		}
		return Inventory{}, fmt.Errorf("cannot open source file %q: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Inventory{}, fmt.Errorf("inspect source file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return Inventory{}, fmt.Errorf("source file %q must be a regular file", path)
	}

	var out Inventory
	seen := make(map[netip.Addr]struct{})
	scanner := bufio.NewScanner(f)
	// A source record consists of an IPv4 literal and optional comment.
	// Limit one malformed/comment line's memory, not the total inventory size.
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for line := 1; scanner.Scan(); line++ {
		value, _, _ := strings.Cut(scanner.Text(), "#")
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() {
			return Inventory{}, fmt.Errorf("source file %q line %d: expected one literal IPv4, found %q", path, line, value)
		}
		if _, duplicate := seen[ip]; duplicate {
			out.Duplicates++
			continue
		}
		seen[ip] = struct{}{}
		out.Addresses = append(out.Addresses, ip)
	}
	if err := scanner.Err(); err != nil {
		return Inventory{}, fmt.Errorf("reading source file %q after line %d: %w", path, len(out.Addresses), err)
	}
	if len(out.Addresses) == 0 {
		return Inventory{}, fmt.Errorf("source file %q contains no IPv4 addresses: add at least one and Recheck", path)
	}
	return out, nil
}
