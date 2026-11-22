//go:build linux

package spoofhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	spoofcarrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// managedIngress is an operator-opt-in, Link-owned INPUT allow; default firewall
// policy and every unrelated rule remain untouched. We use the IPv4 iptables
// compatibility CLI, which may be backed by iptables-nft or legacy. This does
// not claim to override independent nftables chains, provider ACLs or rp_filter.
type managedIngress struct {
	endpoint netip.AddrPort
	protocol string
	private  bool // decrypted peer -> local TUN INPUT, not an outer receiver
}

func ingressRules(link domain.Link) ([]managedIngress, error) {
	if !link.Spoof.ManageIngress {
		return nil, nil
	}
	if link.Spoof.Interface == "" {
		return nil, errors.New("managed Spoof ingress requires a specific operator-approved --device interface")
	}
	local := netip.AddrPortFrom(link.Underlay.Local, link.Spoof.ListenPort)
	other, err := domain.ParseSpoofAlternates(link.Spoof.LocalAlternates, local)
	if err != nil {
		return nil, err
	}
	endpoints := append([]netip.AddrPort{local}, other...)
	names := []string{"udp", "icmp", "tcp", "gre", "ipip", "proto58", "l2tpv3"}
	outer := link.Spoof.OuterProtocol
	if outer != "" && outer != "auto" {
		names = []string{outer}
	}
	// Both protocol-58 wire variants use the same IPv4 protocol number, so
	// only one narrowly-scoped underlying allow is necessary.
	if outer == "proto58-echo" {
		names = []string{"proto58"}
	}
	out := make([]managedIngress, 0, len(endpoints)*len(names)+1)
	for _, ep := range endpoints {
		for _, profile := range names {
			out = append(out, managedIngress{endpoint: ep, protocol: profile})
		}
	}
	// A host-wide INPUT DROP can permit an authenticated outer handshake
	// while silently dropping its decrypted private IPv4 packets as they
	// enter the local TUN. Inspect and, only when blocked, admit the exact
	// peer -> local private pair through this Link-owned TUN interface.
	out = append(out, managedIngress{protocol: "private", private: true})
	return out, nil
}
func (r managedIngress) args(link domain.Link) ([]string, string, error) {
	if r.private {
		if r.protocol != "private" || !link.Addresses.Local.Addr().Is4() || !link.Addresses.Peer.Addr().Is4() {
			return nil, "", errors.New("Spoof private TUN ingress requires exact IPv4 peers")
		}
		name, err := spoofcarrier.TunnelName(link.ID)
		if err != nil {
			return nil, "", err
		}
		local, peer := link.Addresses.Local.Addr().String(), link.Addresses.Peer.Addr().String()
		args := []string{"-i", name, "-s", peer + "/32", "-d", local + "/32"}
		canonical := string(link.ID) + "|private|" + name + "|" + peer + "|" + local
		digest := sha256.Sum256([]byte(canonical))
		marker := "stl:spoof:" + string(link.ID) + ":" + hex.EncodeToString(digest[:8])
		args = append(args, "-m", "comment", "--comment", marker, "-j", "ACCEPT")
		return args, marker, nil
	}
	if !r.endpoint.Addr().Is4() || r.endpoint.Port() == 0 {
		return nil, "", errors.New("invalid managed Spoof receiver")
	}
	args := []string{"-i", link.Spoof.Interface, "-d", r.endpoint.Addr().String() + "/32"}
	protocol := r.protocol
	if protocol == "proto58-echo" {
		protocol = "proto58"
	}
	switch protocol {
	case "udp":
		args = append(args, "-p", "udp", "--dport", strconv.Itoa(int(r.endpoint.Port())))
	case "tcp":
		args = append(args, "-p", "tcp", "--dport", strconv.Itoa(int(r.endpoint.Port())))
	case "icmp":
		args = append(args, "-p", "icmp", "--icmp-type", "echo-reply")
	case "gre":
		args = append(args, "-p", "47")
	case "ipip":
		args = append(args, "-p", "4")
	case "proto58":
		args = append(args, "-p", "58")
	case "l2tpv3":
		args = append(args, "-p", "115")
	default:
		return nil, "", fmt.Errorf("unsupported Spoof ingress profile %q", r.protocol)
	}
	canonical := string(link.ID) + "|" + link.Spoof.Interface + "|" + r.endpoint.String() + "|" + protocol
	digest := sha256.Sum256([]byte(canonical))
	marker := "stl:spoof:" + string(link.ID) + ":" + hex.EncodeToString(digest[:8])
	args = append(args, "-m", "comment", "--comment", marker, "-j", "ACCEPT")
	return args, marker, nil
}
func readOwnedMarkerCount(output, marker string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "--comment" && strings.Trim(fields[i+1], "\"'") == marker {
				count++
			}
		}
	}
	return count
}

// PreflightIngressPrerequisites is read-only. It runs before writing a
// confidential Setup Code so unavailable firewall backends do not create
// a misleading half-provisioned Link.
func PreflightIngressPrerequisites(ctx context.Context, link domain.Link) error {
	if !link.Spoof.ManageIngress {
		return nil
	}
	if _, err := ingressRules(link); err != nil {
		return err
	}
	if err := validateIngressDevice(link); err != nil {
		return err
	}
	if _, err := ingressExecutable(); err != nil {
		return err
	}
	if _, err := runIngress(ctx, "-S", "INPUT"); err != nil {
		return fmt.Errorf("managed Spoof INPUT inspection prerequisite: %w", err)
	}
	return nil
}

func ingressExecutable() (string, error) {
	for _, path := range []string{"/usr/sbin/iptables", "/sbin/iptables"} {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("managed Spoof ingress needs iptables (iptables-nft or legacy); install the supported host firewall CLI or disable explicit --manage-ingress")
}
func runIngress(ctx context.Context, args ...string) (string, error) {
	executable, err := ingressExecutable()
	if err != nil {
		return "", err
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// Never run a shell or infer untrusted rule names; fixed INPUT only.
	command := exec.CommandContext(c, executable, append([]string{"-w", "5"}, args...)...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	bytes, err := command.CombinedOutput()
	if len(bytes) > 2*1024*1024 {
		return "", errors.New("Spoof iptables inventory exceeded bounded diagnostic buffer")
	}
	if err != nil {
		return "", fmt.Errorf("iptables %v: %w: %s", args, err, strings.TrimSpace(string(bytes)))
	}
	return string(bytes), nil
}
func checkIngress(ctx context.Context, link domain.Link, r managedIngress) (bool, error) {
	args, marker, err := r.args(link)
	if err != nil {
		return false, err
	}
	_, checkErr := runIngress(ctx, append([]string{"-C", "INPUT"}, args...)...)
	listing, inspectErr := runIngress(ctx, "-S", "INPUT")
	if inspectErr != nil {
		return false, fmt.Errorf("inspect exact Spoof INPUT firewall: %w", inspectErr)
	}
	count := readOwnedMarkerCount(listing, marker)
	if count > 1 {
		return false, fmt.Errorf("multiple rules with exact Spoof Link firewall ownership marker %s", marker)
	}
	if checkErr == nil {
		if count != 1 {
			return false, fmt.Errorf("Spoof firewall check succeeded but exact ownership marker absent %s", marker)
		}
		return true, nil
	}
	if count != 0 {
		return false, fmt.Errorf("Spoof firewall ownership marker exists but exact rule could not be verified: %s: %w", marker, checkErr)
	}
	return false, nil
}
func inspectIngress(ctx context.Context, link domain.Link) (exists, ready bool, err error) {
	rules, err := ingressRules(link)
	if err != nil {
		return false, false, err
	}
	if len(rules) == 0 {
		return false, true, nil
	}
	snapshot, err := runIngress(ctx, "-S", "INPUT")
	if err != nil {
		return false, false, fmt.Errorf("inspect current INPUT policy: %w", err)
	}
	ready = true
	for _, r := range rules {
		required, e := needsIngressException(snapshot, link, r)
		if e != nil {
			return exists, false, e
		}
		present, e := checkIngress(ctx, link, r)
		if e != nil {
			return exists, false, e
		}
		exists = exists || present
		if required != present {
			ready = false
		}
	}
	return exists, ready, nil
}
func validateIngressDevice(link domain.Link) error {
	if !link.Spoof.ManageIngress {
		return nil
	}
	network, err := net.InterfaceByName(link.Spoof.Interface)
	if err != nil || network.Flags&net.FlagUp == 0 {
		return errors.New("Spoof selected ingress device missing or DOWN")
	}
	local := netip.AddrPortFrom(link.Underlay.Local, link.Spoof.ListenPort)
	other, _ := domain.ParseSpoofAlternates(link.Spoof.LocalAlternates, local)
	all := append([]netip.AddrPort{local}, other...)
	addresses, err := network.Addrs()
	if err != nil {
		return err
	}
	for _, ep := range all {
		present := false
		for _, address := range addresses {
			prefix, e := netip.ParsePrefix(address.String())
			if e == nil && prefix.Addr() == ep.Addr() {
				present = true
				break
			}
		}
		if !present {
			return fmt.Errorf("Spoof managed ingress real receive IPv4 %s not assigned to selected interface %s", ep.Addr(), network.Name)
		}
	}
	return nil
}
func ensureIngress(ctx context.Context, link domain.Link) (func(context.Context) error, error) {
	rules, err := ingressRules(link)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return func(context.Context) error { return nil }, nil
	}
	if err = validateIngressDevice(link); err != nil {
		return nil, err
	}
	snapshot, err := runIngress(ctx, "-S", "INPUT")
	if err != nil {
		return nil, fmt.Errorf("inspect INPUT policy before deciding Spoof rule changes: %w", err)
	}
	var created []managedIngress
	undo := func(c context.Context) error {
		var problems []error
		for i := len(created) - 1; i >= 0; i-- {
			if e := removeIngressRule(c, link, created[i]); e != nil {
				problems = append(problems, e)
			}
		}
		return errors.Join(problems...)
	}
	for _, r := range rules {
		required, e := needsIngressException(snapshot, link, r)
		if e != nil {
			return nil, errors.Join(e, undo(context.WithoutCancel(ctx)))
		}
		present, e := checkIngress(ctx, link, r)
		if e != nil {
			return nil, errors.Join(e, undo(context.WithoutCancel(ctx)))
		}
		if !required {
			// A permissive host must not accumulate unnecessary Link
			// exceptions. Reconcile only rules attributed to this Link.
			if present {
				if e = removeIngressRule(ctx, link, r); e != nil {
					return nil, errors.Join(e, undo(context.WithoutCancel(ctx)))
				}
			}
			continue
		}
		if present {
			continue
		}
		args, _, e := r.args(link)
		if e != nil {
			return nil, errors.Join(e, undo(context.WithoutCancel(ctx)))
		}
		// Prepend *only* this specific Link's permitted listener tuple before
		// pre-existing DROP rules. Strictly opt-in and fully reversible.
		if _, e = runIngress(ctx, append([]string{"-I", "INPUT", "1"}, args...)...); e != nil {
			// Ambiguous add: verify whether exact rule now exists before undo.
			if installed, checkErr := checkIngress(context.WithoutCancel(ctx), link, r); checkErr == nil && installed {
				created = append(created, r)
			}
			return nil, errors.Join(fmt.Errorf("apply managed Spoof INPUT rule: %w", e), undo(context.WithoutCancel(ctx)))
		}
		created = append(created, r)
		if installed, e := checkIngress(ctx, link, r); e != nil || !installed {
			return nil, errors.Join(fmt.Errorf("verify managed Spoof INPUT rule: installed=%v: %w", installed, e), undo(context.WithoutCancel(ctx)))
		}
	}
	return undo, nil
}
func removeIngressRule(ctx context.Context, link domain.Link, r managedIngress) error {
	installed, err := checkIngress(ctx, link, r)
	if err != nil {
		return err
	}
	if !installed {
		return nil
	}
	args, _, err := r.args(link)
	if err != nil {
		return err
	}
	if _, err = runIngress(ctx, append([]string{"-D", "INPUT"}, args...)...); err != nil {
		return err
	}
	if still, verifyErr := checkIngress(ctx, link, r); verifyErr != nil || still {
		return fmt.Errorf("remove exact Spoof firewall ownership unverified: present=%t err=%v", still, verifyErr)
	}
	return nil
}
func removeIngress(ctx context.Context, link domain.Link) error {
	rules, err := ingressRules(link)
	if err != nil {
		return err
	}
	var removed []managedIngress
	for _, r := range rules {
		exists, e := checkIngress(ctx, link, r)
		if e != nil {
			return errors.Join(e, restoreIngress(ctx, link, removed))
		}
		if !exists {
			continue
		}
		if e = removeIngressRule(ctx, link, r); e != nil {
			return errors.Join(e, restoreIngress(ctx, link, removed))
		}
		removed = append(removed, r)
	}
	return nil
}
func restoreIngress(ctx context.Context, link domain.Link, prior []managedIngress) error {
	var failures []error
	for _, r := range prior {
		present, err := checkIngress(context.WithoutCancel(ctx), link, r)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if present {
			continue
		}
		args, _, _ := r.args(link)
		_, err = runIngress(context.WithoutCancel(ctx), append([]string{"-I", "INPUT", "1"}, args...)...)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
