//go:build linux

package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/linux"
)

// LinuxProbeOptions configures read-only Link diagnostics. Interface must be
// the selected Link's actual kernel interface, supplied by its backend;
// BackendOverhead must come from the backend, never from a common guess.
type LinuxProbeOptions struct {
	Runner          linux.Runner
	Interface       string
	BackendOverhead int
	ManualMTU       int
	IPBinary        string
	PingBinary      string
}

func (o LinuxProbeOptions) binaries() (ip, ping string) {
	ip, ping = o.IPBinary, o.PingBinary
	if ip == "" {
		ip = "ip"
	}
	if ping == "" {
		ping = "ping"
	}
	return ip, ping
}

func validDevice(name string) bool {
	if len(name) == 0 || len(name) > 15 || name == "." || name == ".." || name[0] == '-' {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("_.-:@", c)) {
			return false
		}
	}
	return true
}

func validateLinuxProbeOptions(link domain.Link, o LinuxProbeOptions) error {
	if o.Runner == nil {
		return fmt.Errorf("Linux diagnostics runner is required")
	}
	if err := link.Validate(); err != nil {
		return err
	}
	if !link.Addresses.Local.Addr().Is4() || !link.Addresses.Peer.Addr().Is4() ||
		link.Addresses.Local.Addr().IsUnspecified() || link.Addresses.Peer.Addr().IsUnspecified() {
		return fmt.Errorf("Linux IPv4 diagnostics require specified Link Addresses")
	}
	if !validDevice(o.Interface) {
		return fmt.Errorf("Linux diagnostics requires a valid selected Link interface")
	}
	ip, ping := o.binaries()
	for _, binary := range []string{ip, ping} {
		if binary == "" || binary[0] == '-' || strings.ContainsAny(binary, " \t\n\r\x00=") {
			return fmt.Errorf("invalid Linux diagnostics binary path")
		}
	}
	return nil
}

type linuxProbeInterfaceJSON struct {
	IfIndex  int      `json:"ifindex"`
	IfName   string   `json:"ifname"`
	MTU      int      `json:"mtu"`
	Flags    []string `json:"flags"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func inspectLinuxInterface(ctx context.Context, runner linux.Runner, binary string, address bool, name string) (linuxProbeInterfaceJSON, error) {
	args := []string{"-json", "link", "show", "dev", name}
	if address {
		args = []string{"-4", "-json", "address", "show", "dev", name}
	}
	result, err := runner.Run(ctx, binary, args...)
	if err != nil {
		return linuxProbeInterfaceJSON{}, fmt.Errorf("inspect Linux interface: %w", err)
	}
	var rows []linuxProbeInterfaceJSON
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		return linuxProbeInterfaceJSON{}, fmt.Errorf("parse Linux interface inspection: %w", err)
	}
	if len(rows) != 1 || rows[0].IfName != name || rows[0].IfIndex <= 0 ||
		rows[0].MTU < MinIPv4MTU {
		return linuxProbeInterfaceJSON{}, fmt.Errorf("Linux interface observation is unavailable or inconsistent")
	}
	for _, flag := range rows[0].Flags {
		if flag == "UP" {
			return rows[0], nil
		}
	}
	return linuxProbeInterfaceJSON{}, fmt.Errorf("Linux interface is not up")
}

// PreflightLinux reads only the peer-underlay route and the two relevant
// interfaces. No default route is assumed. BackendOverhead stays backend-owned.
func PreflightLinux(ctx context.Context, link domain.Link, o LinuxProbeOptions) (MTUConstraints, error) {
	if ctx == nil {
		return MTUConstraints{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return MTUConstraints{}, err
	}
	if err := validateLinuxProbeOptions(link, o); err != nil {
		return MTUConstraints{}, err
	}
	if o.BackendOverhead <= 0 {
		return MTUConstraints{}, fmt.Errorf("Linux diagnostics requires backend-provided encapsulation overhead")
	}
	ip, _ := o.binaries()
	route, err := (linux.RouteResolver{Runner: o.Runner, IPBinary: ip}).Resolve(ctx, link.Underlay.Peer)
	if err != nil {
		return MTUConstraints{}, fmt.Errorf("inspect Link underlay route: %w", err)
	}
	if route.Source != link.Underlay.Local || !validDevice(route.Device) {
		return MTUConstraints{}, fmt.Errorf("Link underlay route does not match the selected source/device")
	}
	underlay, err := inspectLinuxInterface(ctx, o.Runner, ip, false, route.Device)
	if err != nil {
		return MTUConstraints{}, fmt.Errorf("inspect Link underlay MTU: %w", err)
	}
	tunnel, err := inspectLinuxInterface(ctx, o.Runner, ip, true, o.Interface)
	if err != nil {
		return MTUConstraints{}, fmt.Errorf("inspect selected Link interface: %w", err)
	}
	localAddressPresent := false
	for _, info := range tunnel.AddrInfo {
		if info.Family != "inet" {
			continue
		}
		addr, parseErr := netip.ParseAddr(info.Local)
		if parseErr == nil && addr.Is4() && info.PrefixLen >= 0 && info.PrefixLen <= 32 &&
			netip.PrefixFrom(addr, info.PrefixLen) == link.Addresses.Local {
			localAddressPresent = true
			break
		}
	}
	if !localAddressPresent {
		return MTUConstraints{}, fmt.Errorf("selected Link interface does not own the requested local Link Address")
	}
	mtu := underlay.MTU
	if route.MTU > 0 && route.MTU < mtu {
		mtu = route.MTU
	}
	constraints := MTUConstraints{UnderlayMTU: mtu, BackendOverhead: o.BackendOverhead, ManualOverride: o.ManualMTU}
	if _, err := mtuCeiling(constraints); err != nil {
		return MTUConstraints{}, err
	}
	return constraints, nil
}

// LinuxDFProber performs exactly one DF echo probe, bound to one Link ID,
// interface and pair of Link Addresses. It never changes network state.
type LinuxDFProber struct {
	runner linux.Runner
	link   domain.Link
	dev    string
	ping   string
}

func NewLinuxDFProber(link domain.Link, o LinuxProbeOptions) (*LinuxDFProber, error) {
	if err := validateLinuxProbeOptions(link, o); err != nil {
		return nil, err
	}
	_, ping := o.binaries()
	return &LinuxDFProber{runner: o.Runner, link: link, dev: o.Interface, ping: ping}, nil
}

var pingReply = regexp.MustCompile(`(?m)^\d+ bytes from ([0-9.]+): icmp_seq=1\b[^\n]*\btime=([0-9]+(?:\.[0-9]+)?) ms`)
var pingStats = regexp.MustCompile(`(?m)^1 packets transmitted, ([01]) received,`)

func pingTooLarge(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "message too long") ||
		strings.Contains(lower, "frag needed and df set") ||
		strings.Contains(lower, "packet too big") || strings.Contains(lower, "packet too large")
}

func parsePingSample(result linux.CommandResult, runErr error, peer netip.Addr) (ProbeSample, error) {
	output := string(result.Stdout)
	if pingTooLarge(output + "\n" + string(result.Stderr)) {
		return ProbeSample{Outcome: ProbeTooLarge}, nil
	}
	if runErr != nil {
		if errors.Is(runErr, exec.ErrNotFound) {
			return ProbeSample{Outcome: ProbeUnsupported}, nil
		}
		var cmdErr *linux.CommandError
		if !errors.As(runErr, &cmdErr) {
			return ProbeSample{}, fmt.Errorf("execute Linux ICMP probe failed")
		}
		if cmdErr.TimedOut || cmdErr.Canceled {
			return ProbeSample{}, fmt.Errorf("Linux ICMP probe execution was interrupted")
		}
		if cmdErr.ExitCode != 1 {
			return ProbeSample{Outcome: ProbeUnsupported}, nil
		}
	}
	stats := pingStats.FindStringSubmatch(output)
	if len(stats) != 2 {
		return ProbeSample{}, fmt.Errorf("Linux ICMP probe returned no verifiable transmission summary")
	}
	if stats[1] == "0" {
		// iputils includes an explicit errors counter for local/tool or
		// ICMP error replies. They are not silent transmitted-packet loss.
		if strings.Contains(output, " errors,") {
			return ProbeSample{Outcome: ProbeUnsupported}, nil
		}
		if runErr != nil {
			return ProbeSample{Outcome: ProbeTimeout}, nil
		}
		return ProbeSample{}, fmt.Errorf("Linux ICMP probe returned inconsistent zero-reply status")
	}
	// A one-packet summary is not sufficient: the received reply must name
	// the intended peer and carry a parseable RTT for sequence number one.
	if runErr != nil {
		return ProbeSample{}, fmt.Errorf("Linux ICMP probe reported a failed echo exchange")
	}
	match := pingReply.FindStringSubmatch(output)
	if len(match) != 3 || match[1] != peer.String() {
		return ProbeSample{}, fmt.Errorf("Linux ICMP probe reply was not attributable to the requested peer")
	}
	millis, err := strconv.ParseFloat(match[2], 64)
	if err != nil || millis < 0 || millis > 1000 {
		return ProbeSample{}, fmt.Errorf("Linux ICMP probe RTT was invalid")
	}
	return ProbeSample{Outcome: ProbeReply, RTT: time.Duration(millis * float64(time.Millisecond))}, nil
}

func (p *LinuxDFProber) Probe(ctx context.Context, link domain.Link, packetBytes int) (ProbeSample, error) {
	if ctx == nil {
		return ProbeSample{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return ProbeSample{}, err
	}
	if p == nil || p.runner == nil || link.ID != p.link.ID ||
		link.Addresses != p.link.Addresses || link.Underlay != p.link.Underlay || link.Backend != p.link.Backend ||
		link.Encapsulation != p.link.Encapsulation {
		return ProbeSample{}, fmt.Errorf("Linux ICMP probe is not bound to the requested Link")
	}
	if packetBytes < MinIPv4MTU || packetBytes > MaxIPv4MTU {
		return ProbeSample{}, fmt.Errorf("invalid inner IPv4 probe datagram size")
	}
	// env fixes the iputils output language without shell evaluation;
	// -I selects the exact Link interface and its required local source.
	args := []string{"LC_ALL=C", p.ping, "-4", "-n", "-c", "1", "-W", "1", "-M", "do",
		"-s", strconv.Itoa(packetBytes - 28), "-I", p.dev, "-I",
		p.link.Addresses.Local.Addr().String(), p.link.Addresses.Peer.Addr().String()}
	result, err := p.runner.Run(ctx, "env", args...)
	if ctx.Err() != nil {
		return ProbeSample{}, ctx.Err()
	}
	return parsePingSample(result, err, p.link.Addresses.Peer.Addr())
}

// ObserveLinux composes the read-only OS adapter with the already accepted
// backend-neutral decision/report model. It never applies the suggested MTU.
func ObserveLinux(ctx context.Context, link domain.Link, o LinuxProbeOptions) (Report, error) {
	constraints, err := PreflightLinux(ctx, link, o)
	if err != nil {
		return Report{}, err
	}
	prober, err := NewLinuxDFProber(link, o)
	if err != nil {
		return Report{}, err
	}
	return Observe(ctx, link, constraints, prober)
}
