//go:build linux

package main

// This adapter is deliberately NON-FIELD: it refuses to create raw sockets
// unless running in a private, detached, veth-only Linux network namespace
// with no default/public routes. It accepts only finite, signed RFC1918 plans.
import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// requireIsolatedPrivateNamespace is a fail-closed defense in depth, not a
// substitute for the external A-R-B topology inspection in an acceptance lab.
func requireIsolatedPrivateNamespace(ifName, exactIP string) error {
	peer, err := netip.ParseAddr(exactIP)
	if err != nil || !peer.Is4() || !peer.IsPrivate() || peer.Is4In6() {
		return errors.New("netns diagnostic requires exact private IPv4 address")
	}
	if len(ifName) < 4 || len(ifName) > 15 || !strings.HasPrefix(ifName, "sdg") {
		return errors.New("netns test interface must use task-owned sdg* identity")
	}
	for _, c := range ifName {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return errors.New("invalid isolated lab interface name")
		}
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if self == host {
		return errors.New("raw lab forbidden in host/initial network namespace")
	}
	virtual, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", ifName))
	if err != nil || !strings.Contains(virtual, "/devices/virtual/net/") {
		return errors.New("only isolated virtual network interfaces are permitted")
	}
	nic, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}
	if nic.Flags&net.FlagUp == 0 || nic.Flags&net.FlagLoopback != 0 {
		return errors.New("private lab veth is down or loopback")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	physicalCount := 0
	ownPrivate := false
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 {
			continue
		}
		physicalCount++
		if item.Name != ifName || item.Index != nic.Index {
			return errors.New("network namespace contains an unexpected external interface")
		}
		addrs, err := item.Addrs()
		if err != nil {
			return err
		}
		for _, address := range addrs {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				return errors.New("unsupported interface address")
			}
			// IPv6 link local is harmless, but routable/public IPv6 is not.
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				return errors.New("cannot parse interface address")
			}
			// net.IP often represents a normal IPv4 as a 16-byte
			// IPv4-mapped address. Unmap before checking family; otherwise
			// an owned RFC1918 veth falsely looks like public IPv6.
			ip = ip.Unmap()
			if ip.Is6() {
				if !ip.IsLinkLocalUnicast() {
					return errors.New("non-local IPv6 address in isolated lab")
				}
				continue
			}
			if !ip.IsPrivate() {
				return errors.New("unexpected non-RFC1918 interface IPv4")
			}
			ownPrivate = true
		}
	}
	if physicalCount != 1 || !ownPrivate {
		return errors.New("isolated netns must contain exactly one private veth and loopback")
	}
	// /proc/net/route reflects the currently joined namespace. Allow only
	// explicitly private network routes; reject default and public destinations.
	routes, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(routes)), "\n")
	if len(lines) < 2 {
		return errors.New("no trustworthy lab route table")
	}
	routesSeen := 0
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			return errors.New("malformed namespace route table")
		}
		if fields[0] != ifName {
			return errors.New("private namespace has route on an unapproved interface")
		}
		encoded, err := strconv.ParseUint(fields[1], 16, 32)
		if err != nil {
			return err
		}
		dest := netip.AddrFrom4([4]byte{byte(encoded), byte(encoded >> 8), byte(encoded >> 16), byte(encoded >> 24)})
		if dest.IsUnspecified() || !dest.IsPrivate() {
			return errors.New("non-private or default IPv4 route in isolated namespace")
		}
		routesSeen++
	}
	if routesSeen == 0 {
		return errors.New("private namespace route table is empty")
	}
	// IPv6 default routes are forbidden even though this tool sends IPv4 only.
	ipv6routes, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(ipv6routes)), "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && f[0] == strings.Repeat("0", 32) && f[1] == "00" {
			return errors.New("IPv6 default route in private network namespace")
		}
	}
	return nil
}

func makeRawIPv4UDPPacket(src, dst netip.Addr, destPort int, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() || !src.IsPrivate() || !dst.IsPrivate() || src.Is4In6() || dst.Is4In6() {
		return nil, errors.New("raw lab packet must use exact private IPv4 source/destination")
	}
	if destPort < 1024 || destPort > 65535 || len(payload) < 128 || len(payload) > labMaxPacket {
		return nil, errors.New("invalid raw private-lab port/payload size")
	}
	if 20+8+len(payload) > 1500 {
		return nil, errors.New("packet size exceeds lab MTU")
	}
	out := make([]byte, 20+8+len(payload))
	out[0] = 0x45
	out[8] = 64
	out[9] = 17 // IPv4 UDP
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint16(out[6:8], 0x4000) // DF, no fragmentation
	copy(out[12:16], src.AsSlice())
	copy(out[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(out[20:22], 24101)
	binary.BigEndian.PutUint16(out[22:24], uint16(destPort))
	binary.BigEndian.PutUint16(out[24:26], uint16(8+len(payload)))
	// UDP checksum zero is legal for IPv4. Kernel fills IPv4 header checksum
	// when IP_HDRINCL is enabled; payload authenticates separately with Ed25519.
	copy(out[28:], payload)
	return out, nil
}

func privateRawSend(ctx context.Context, o labOptions, challengePath, ifName string) (string, int, error) {
	env, err := readOfflineChallenge(challengePath)
	if err != nil {
		return "", 0, err
	}
	roots, err := certificateRoots(o.CA)
	if err != nil {
		return "", 0, err
	}
	signer, err := challengeSignerCertificate(env, roots, time.Now())
	if err != nil {
		return "", 0, err
	}
	plan := env.Challenge
	if plan.Environment != "isolated_private_raw" || plan.Sender != o.Sender || plan.Receiver != o.Receiver {
		return "", 0, errors.New("netns sender requires exact signed isolated-private challenge and roles")
	}
	if o.DestinationIP != plan.DestinationIP {
		return "", 0, errors.New("receiver address does not match signed challenge")
	}
	if o.DataPort < 1024 || o.DataPort > 65535 {
		return "", 0, errors.New("valid exact diagnostic UDP port required")
	}
	if err := requireIsolatedPrivateNamespace(ifName, plan.DestinationIP); err != nil {
		return "", 0, err
	}
	cert, err := loadLabCredential(o.Cert, o.Key)
	if err != nil {
		return "", 0, err
	}
	own, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", 0, err
	}
	if !own.Equal(signer) {
		return "", 0, errors.New("local sender signing key differs from signed challenge")
	}
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return "", 0, errors.New("expected Ed25519 sender key")
	}
	dst := netip.MustParseAddr(plan.DestinationIP)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return "", 0, fmt.Errorf("isolated NET_RAW capability needed: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return "", 0, err
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName); err != nil {
		return "", 0, err
	}
	sockaddr := &syscall.SockaddrInet4{Addr: dst.As4()}
	sent := 0
	for _, sample := range plan.Samples {
		if ctx.Err() != nil {
			return plan.RunID, sent, ctx.Err()
		}
		source, err := netip.ParseAddr(sample.Candidate.IP)
		if err != nil || !source.IsPrivate() || !source.Is4() {
			return plan.RunID, sent, errors.New("invalid signed source")
		}
		payload, err := makeOfflinePacket(plan, sample, key)
		if err != nil {
			return plan.RunID, sent, err
		}
		packet, err := makeRawIPv4UDPPacket(source, dst, o.DataPort, payload)
		if err != nil {
			return plan.RunID, sent, err
		}
		if err := syscall.Sendto(fd, packet, 0, sockaddr); err != nil {
			return plan.RunID, sent, err
		}
		sent++
		time.Sleep(45 * time.Millisecond)
	}
	return plan.RunID, sent, nil
}

func rawPrivateCLI(args []string) error {
	if len(args) < 1 {
		return errors.New("lab netns-send|netns-listen only inside isolated RFC1918 namespace")
	}
	op := args[0]
	if op != "netns-send" && op != "netns-listen" {
		return errors.New("unknown raw lab operation")
	}
	flags := flag.NewFlagSet("lab "+op, flag.ContinueOnError)
	var o labOptions
	var challenge, ifName, state, bindIP string
	var window int
	flags.StringVar(&o.Cert, "cert", "", "node lab certificate PEM")
	flags.StringVar(&o.Key, "key", "", "node lab private key PEM")
	flags.StringVar(&o.CA, "ca", "", "lab CA PEM")
	flags.StringVar(&o.File, "file", "", "receiver's exact RFC1918 candidate allowlist CSV/JSON")
	flags.StringVar(&o.Sender, "sender", "A", "sender A or B")
	flags.StringVar(&o.Receiver, "receiver", "B", "receiver A or B")
	flags.StringVar(&challenge, "challenge", "", "sender signed isolated_private_raw challenge JSON")
	flags.StringVar(&ifName, "interface", "", "task-owned sdg* virtual interface inside isolated netns")
	flags.StringVar(&o.DestinationIP, "destination-ip", "", "exact private receiver IP bound to signed challenge (sender)")
	flags.StringVar(&bindIP, "bind-ip", "", "exact owned private interface IP on receiver")
	flags.IntVar(&o.DataPort, "data-port", 0, "explicit 1024..65535 bound UDP port")
	flags.IntVar(&window, "window-seconds", 8, "bounded receiver observation window 1..120")
	flags.StringVar(&state, "state-dir", "", "private consumed-run ledger directory")
	flags.StringVar(&o.Output, "out", "", "new signed JSON peer observation file")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if challenge == "" || o.Cert == "" || o.Key == "" || o.CA == "" || ifName == "" || o.DataPort < 1024 || o.DataPort > 65535 {
		return errors.New("netns diagnostic requires exact --challenge --cert --key --ca --interface --data-port")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if op == "netns-send" {
		if o.DestinationIP == "" {
			return errors.New("netns-send requires --destination-ip")
		}
		run, count, err := privateRawSend(ctx, o, challenge, ifName)
		if err != nil {
			return err
		}
		return pretty(map[string]any{
			"run_id": run, "submitted": count, "transport": "ISOLATED_PRIVATE_RAW_IPV4_UDP",
			"sender_egress": "NOT_TESTED", "independent_peer_receipt": "NOT_TESTED",
			"return_to_sender": "NOT_TESTED", "private_l3": "NOT_TESTED",
		})
	}
	if bindIP == "" || o.Output == "" || state == "" || o.File == "" {
		return errors.New("netns-listen requires --bind-ip --file --out --state-dir")
	}
	bind, err := netip.ParseAddr(bindIP)
	if err != nil || !bind.IsPrivate() || !bind.Is4() {
		return errors.New("receiver bind must be RFC1918 IPv4")
	}
	ready := make(chan labReady, 1)
	done := make(chan error, 1)
	go func() {
		done <- offlineListenBound(ctx, o, challenge, state, time.Duration(window)*time.Second, ready, net.IP(bind.AsSlice()), ifName, "isolated_private_raw")
	}()
	select {
	case r := <-ready:
		if err := pretty(r); err != nil {
			return err
		}
		if err := <-done; err != nil {
			return err
		}
		return pretty(map[string]any{"status": "SIGNED_RECEIPT_WRITTEN", "receipt": o.Output, "environment": "isolated_private_raw", "egress_and_return": "NOT_TESTED"})
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
