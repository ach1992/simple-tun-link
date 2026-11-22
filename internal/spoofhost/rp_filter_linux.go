//go:build linux

package spoofhost

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

// RPFilterStatus reports Linux's effective reverse-path policy on the actual
// incoming interface. Shared sysctls must not be silently mutated per Link.
type RPFilterStatus struct {
	IngressInterface string `json:"ingress_interface,omitempty"`
	All              int    `json:"all"`
	Interface        int    `json:"interface"`
	Effective        int    `json:"effective"`
	Mode             string `json:"mode"`
	Note             string `json:"note,omitempty"`
	ReadError        string `json:"read_error,omitempty"`
}

func ReadRPFilterStatus(link domain.Link) RPFilterStatus { return readRPFilterAt("/proc/sys", link) }

func readRPFilterAt(procRoot string, link domain.Link) RPFilterStatus {
	r := RPFilterStatus{IngressInterface: link.Spoof.IngressInterface, Mode: "UNVERIFIED"}
	if r.IngressInterface == "" {
		r.Note = "Incoming interface not specified; use --ingress-device for precise rp_filter diagnosis. STL did not modify sysctls."
		return r
	}
	if strings.ContainsAny(r.IngressInterface, "/\\\x00\r\n") ||
		r.IngressInterface == "." || r.IngressInterface == ".." || len(r.IngressInterface) > 15 {
		r.ReadError = "invalid incoming interface"
		return r
	}
	read := func(name string) (int, error) {
		content, err := os.ReadFile(filepath.Join(procRoot, "net", "ipv4", "conf", name, "rp_filter"))
		if err != nil {
			return 0, fmt.Errorf("read rp_filter for %s: %w", name, err)
		}
		value, err := strconv.Atoi(strings.TrimSpace(string(content)))
		if err != nil || value < 0 || value > 2 {
			return 0, fmt.Errorf("invalid rp_filter for %s: %q", name, strings.TrimSpace(string(content)))
		}
		return value, nil
	}
	var err error
	r.All, err = read("all")
	if err != nil {
		r.ReadError = err.Error()
		return r
	}
	r.Interface, err = read(r.IngressInterface)
	if err != nil {
		r.ReadError = err.Error()
		return r
	}
	r.Effective = max(r.All, r.Interface)
	switch r.Effective {
	case 0:
		r.Mode = "OFF"
	case 1:
		r.Mode = "STRICT"
		r.Note = "Strict reverse-path checks may reject asymmetric incoming Source IPs; confirm actual source, reverse FIB and drop evidence before changing policy. Per-interface loose=2 can override all=1 but changes every service on that NIC; STL did not change it."
	case 2:
		r.Mode = "LOOSE"
		r.Note = "Loose mode still requires a reverse route; no setting here can override ISP anti-spoof or independent firewall."
	}
	return r
}
