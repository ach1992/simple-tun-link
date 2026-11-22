//go:build linux

package spoofhost

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	spoofcarrier "github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

// privateICMPProbe is an independent private-L3 application exchange, not
// an outer Noise keepalive or a TUN.WritePacket success counter. The Linux
// kernel must receive the decrypted peer /32 and generate the echo reply.
// Failure proves only that this ICMP probe did not succeed, not that TCP/UDP
// are also blocked (ICMP might be explicitly filtered).
func privateICMPProbe(ctx context.Context, local, peer netip.Addr) error {
	if !local.Is4() || !peer.Is4() || local == peer {
		return errors.New("private ICMP probe requires distinct IPv4 Link addresses")
	}
	var token [10]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	id := binary.BigEndian.Uint16(token[:2])
	seq := binary.BigEndian.Uint16(token[2:4])
	message := make([]byte, 8+len(token))
	message[0] = 8 // ICMPv4 echo request
	binary.BigEndian.PutUint16(message[4:6], id)
	binary.BigEndian.PutUint16(message[6:8], seq)
	copy(message[8:], token[:])
	binary.BigEndian.PutUint16(message[2:4], icmp16Checksum(message))
	conn, err := net.DialIP("ip4:icmp", &net.IPAddr{IP: net.IP(local.AsSlice())},
		&net.IPAddr{IP: net.IP(peer.AsSlice())})
	if err != nil {
		return fmt.Errorf("open private ICMP test socket: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2500 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := conn.Write(message); err != nil {
		return fmt.Errorf("send private ICMP test on Link route: %w", err)
	}
	buf := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, src, err := conn.ReadFromIP(buf)
		if err != nil {
			return fmt.Errorf("private ICMP echo reply missing or filtered: %w", err)
		}
		if src == nil || !src.IP.Equal(net.IP(peer.AsSlice())) {
			continue
		}
		body := buf[:n]
		// Raw IPv4 sockets may expose the IPv4 header on some kernels.
		if len(body) >= 20 && body[0]>>4 == 4 {
			header := int(body[0]&15) * 4
			if header < 20 || len(body) < header {
				continue
			}
			body = body[header:]
		}
		if privateICMPEchoMatches(body, id, seq, token[:]) {
			return nil
		}
	}
}

func privateICMPEchoMatches(reply []byte, id, seq uint16, token []byte) bool {
	return len(reply) == 8+len(token) && reply[0] == 0 && reply[1] == 0 &&
		binary.BigEndian.Uint16(reply[4:6]) == id &&
		binary.BigEndian.Uint16(reply[6:8]) == seq &&
		string(reply[8:]) == string(token) && icmp16Checksum(reply) == 0
}

func icmp16Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		word := uint32(data[i]) << 8
		if i+1 < len(data) {
			word |= uint32(data[i+1])
		}
		sum += word
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type privateProbeResult struct {
	session     *spoofcarrier.Session
	destination netip.AddrPort
	err         error
}
