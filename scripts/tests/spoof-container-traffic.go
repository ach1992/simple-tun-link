//go:build linux

// Spoof private-L3 traffic acceptance harness for task-owned isolated Linux
// containers only. NOT an STL production component.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

type options struct {
	mode, protocol, local, peer        string
	port, connections, size, datagrams int
}

func result(v any) { _ = json.NewEncoder(os.Stdout).Encode(v) }
func run(opts options) error {
	if opts.port < 1 || opts.port > 65535 {
		return errors.New("bad test port")
	}
	here := net.JoinHostPort(opts.local, strconv.Itoa(opts.port))
	peer := net.JoinHostPort(opts.peer, strconv.Itoa(opts.port))
	const timeout = 45 * time.Second
	switch opts.protocol {
	case "tcp":
		if opts.mode == "server" {
			server, err := net.Listen("tcp4", here)
			if err != nil {
				return err
			}
			defer server.Close()
			fmt.Println("READY TCP", here)
			total := 0
			for i := 0; i < opts.connections; i++ {
				if err = server.(*net.TCPListener).SetDeadline(time.Now().Add(timeout)); err != nil {
					return err
				}
				conn, e := server.Accept()
				if e != nil {
					return e
				}
				_ = conn.SetDeadline(time.Now().Add(timeout))
				var header [4]byte
				if _, e = io.ReadFull(conn, header[:]); e != nil {
					conn.Close()
					return e
				}
				size := int(binary.BigEndian.Uint32(header[:]))
				if size < 1 || size > 32<<20 {
					conn.Close()
					return errors.New("invalid test packet length")
				}
				h := sha256.New()
				count, e := io.CopyN(h, conn, int64(size))
				if e != nil || int(count) != size {
					conn.Close()
					return fmt.Errorf("test TCP digest read: %v", e)
				}
				if _, e = conn.Write(h.Sum(nil)); e != nil {
					conn.Close()
					return e
				}
				conn.Close()
				total += size
			}
			result(map[string]any{"protocol": "tcp", "server": "verified", "connections": opts.connections, "bytes": total})
			return nil
		}
		if opts.size < 1 || opts.size > 32<<20 {
			return errors.New("invalid test size")
		}
		payload := make([]byte, opts.size)
		if _, err := rand.Read(payload); err != nil {
			return err
		}
		digest := sha256.Sum256(payload)
		started := time.Now()
		for i := 0; i < opts.connections; i++ {
			conn, err := net.DialTimeout("tcp4", peer, timeout)
			if err != nil {
				return err
			}
			_ = conn.SetDeadline(time.Now().Add(timeout))
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(opts.size))
			if _, err = conn.Write(append(header[:], payload...)); err != nil {
				conn.Close()
				return err
			}
			var reply [32]byte
			if _, err = io.ReadFull(conn, reply[:]); err != nil {
				conn.Close()
				return err
			}
			conn.Close()
			if reply != digest {
				return fmt.Errorf("TCP digest mismatch on transfer %d", i)
			}
		}
		result(map[string]any{"protocol": "tcp", "client": "verified", "connections": opts.connections, "bytes": opts.size * opts.connections, "elapsed_seconds": time.Since(started).Seconds()})
		return nil
	case "udp":
		if opts.datagrams < 1 || opts.datagrams > 20000 {
			return errors.New("invalid datagram count")
		}
		addr, err := net.ResolveUDPAddr("udp4", here)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if opts.mode == "server" {
			fmt.Println("READY UDP", here)
			for i := 0; i < opts.datagrams; i++ {
				var buf [2048]byte
				n, remote, e := conn.ReadFromUDP(buf[:])
				if e != nil {
					return e
				}
				if n != 1028 || binary.BigEndian.Uint32(buf[:4]) != uint32(i) {
					return fmt.Errorf("UDP sequence/payload mismatch at %d", i)
				}
				sum := sha256.Sum256(buf[:n])
				var ack [36]byte
				binary.BigEndian.PutUint32(ack[:4], uint32(i))
				copy(ack[4:], sum[:])
				if _, e = conn.WriteToUDP(ack[:], remote); e != nil {
					return e
				}
			}
			result(map[string]any{"protocol": "udp", "server": "verified", "datagrams": opts.datagrams})
			return nil
		}
		destination, err := net.ResolveUDPAddr("udp4", peer)
		if err != nil {
			return err
		}
		started := time.Now()
		for i := 0; i < opts.datagrams; i++ {
			var message [1028]byte
			binary.BigEndian.PutUint32(message[:4], uint32(i))
			if _, err = rand.Read(message[4:]); err != nil {
				return err
			}
			if _, err = conn.WriteToUDP(message[:], destination); err != nil {
				return err
			}
			var reply [36]byte
			n, remote, e := conn.ReadFromUDP(reply[:])
			if e != nil {
				return e
			}
			sum := sha256.Sum256(message[:])
			if n != 36 || !remote.IP.Equal(destination.IP) || binary.BigEndian.Uint32(reply[:4]) != uint32(i) {
				return fmt.Errorf("UDP remote/sequence mismatch at %d", i)
			}
			for j := range sum {
				if reply[j+4] != sum[j] {
					return fmt.Errorf("UDP digest mismatch at %d", i)
				}
			}
		}
		result(map[string]any{"protocol": "udp", "client": "verified", "datagrams": opts.datagrams, "elapsed_seconds": time.Since(started).Seconds()})
		return nil
	}
	return errors.New("unsupported protocol")
}
func main() {
	var o options
	flag.StringVar(&o.mode, "mode", "client", "client|server")
	flag.StringVar(&o.protocol, "protocol", "tcp", "tcp|udp")
	flag.StringVar(&o.local, "local", "", "local private Link IPv4")
	flag.StringVar(&o.peer, "peer", "", "peer private Link IPv4")
	flag.IntVar(&o.port, "port", 55222, "test-only TCP/UDP port")
	flag.IntVar(&o.connections, "connections", 4, "TCP transfers")
	flag.IntVar(&o.size, "bytes", 1<<20, "each TCP transfer size")
	flag.IntVar(&o.datagrams, "datagrams", 150, "UDP datagrams")
	flag.Parse()
	if o.mode != "client" && o.mode != "server" {
		fmt.Fprintln(os.Stderr, "FAIL: invalid mode")
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
