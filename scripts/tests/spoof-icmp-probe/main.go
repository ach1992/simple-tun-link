//go:build linux

// ICMP packet reachability probe for the private STL262 lab only.
// This is NOT a product carrier, nor proof of Noise transport or any
// public-host Internet deliverability. It never sends to a public destination.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const magic = "STL262-ICMP-PRIVATE-LAB-ONLY"

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func prepareICMP(src, dst netip.Addr, nonce [8]byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, errors.New("IPv4 required")
	}
	length := 20 + 8 + len(magic) + len(nonce)
	packet := make([]byte, length)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	packet[8] = 42
	packet[9] = unix.IPPROTO_ICMP
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	packet[20] = 0 // Echo Reply; the real endpoint kernel must NOT reflexively reply
	binary.BigEndian.PutUint16(packet[24:26], 0x262)
	binary.BigEndian.PutUint16(packet[26:28], 1)
	copy(packet[28:28+len(magic)], magic)
	copy(packet[28+len(magic):], nonce[:])
	binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:]))
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	return packet, nil
}
func run(mode string, real, peer, source netip.Addr) error {
	permitted := netip.MustParsePrefix("10.244.62.0/24")
	if !permitted.Contains(real) || !permitted.Contains(peer) || !source.Is4() ||
		source.IsUnspecified() || source.IsMulticast() {
		return errors.New("private STL262 lab address contract required")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if mode == "send" {
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			return err
		}
		if err = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "eth0"); err != nil {
			return err
		}
		var nonce [8]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		packet, err := prepareICMP(source, peer, nonce)
		if err != nil {
			return err
		}
		var dst unix.SockaddrInet4
		copy(dst.Addr[:], peer.AsSlice())
		for i := 0; i < 5; i++ {
			if err = unix.Sendto(fd, packet, 0, &dst); err != nil {
				return err
			}
			time.Sleep(120 * time.Millisecond)
		}
		fmt.Printf("SENT: 5 raw Echo Reply packets source=%s destination=%s (delivery unverified)\n", source, peer)
		return nil
	}
	if mode != "receive" {
		return errors.New("use send or receive")
	}
	deadline := time.Now().Add(9 * time.Second)
	buf := make([]byte, 8192)
	for time.Now().Before(deadline) {
		if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
			return err
		}
		n, _, e := unix.Recvfrom(fd, buf, 0)
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil {
			return e
		}
		b := buf[:n]
		if len(b) < 20+8+len(magic)+8 || b[0]>>4 != 4 {
			continue
		}
		headLen := int(b[0]&0x0f) * 4
		if headLen < 20 || len(b) < headLen+8+len(magic)+8 {
			continue
		}
		if b[9] != unix.IPPROTO_ICMP || b[headLen] != 0 || b[headLen+1] != 0 {
			continue
		}
		if string(b[headLen+8:headLen+8+len(magic)]) != magic {
			continue
		}
		if got, _ := netip.AddrFromSlice(b[12:16]); got != source {
			continue
		}
		if got, _ := netip.AddrFromSlice(b[16:20]); got != real {
			continue
		}
		if checksum(b[headLen:]) != 0 {
			continue
		}
		fmt.Printf("DELIVERED: raw ICMP Echo Reply from forged source=%s to actual peer=%s payload match=yes checksum=verified\n", source, real)
		return nil
	}
	return errors.New("no ICMP probe from expected Source reached exact real peer")
}
func main() {
	mode := flag.String("mode", "", "send or receive")
	realStr := flag.String("real", "", "actual receiving endpoint private IP")
	peerStr := flag.String("peer", "", "known actual peer private IP")
	sourceStr := flag.String("source", "", "forged source private-lab candidate IP")
	flag.Parse()
	real, err := netip.ParseAddr(*realStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid local real address")
		os.Exit(2)
	}
	peer, err := netip.ParseAddr(*peerStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid peer real address")
		os.Exit(2)
	}
	src, err := netip.ParseAddr(*sourceStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid source")
		os.Exit(2)
	}
	if err = run(*mode, real, peer, src); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
