//go:build linux

// Rawprobe is a test-only executable for owner-scoped network namespaces.
// It is not part of the installed stl command or a public diagnostic API.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
)

func main() {
	mode := flag.String("mode", "", "recv/send/ordinary-send")
	bind := flag.String("bind", "", "local real UDP endpoint")
	peer := flag.String("peer", "", "known real peer UDP endpoint")
	file := flag.String("sources", "", "local source file")
	src := flag.String("source", "", "operator-selected source IPv4")
	dev := flag.String("device", "", "local egress interface")
	flag.Parse()
	switch *mode {
	case "recv":
		local, err := netip.ParseAddrPort(*bind)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		conn, err := spoof.OpenReceiver(local)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		data := make([]byte, 4096)
		n, remote, err := conn.ReadFromUDPAddrPort(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "recv-timeout-or-error:", err)
			os.Exit(1)
		}
		fmt.Printf("received from=%s payload=%q\n", remote, data[:n])
	case "send":
		dst, err := netip.ParseAddrPort(*peer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		source, err := netip.ParseAddr(*src)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		inv, err := spoof.ReadSources(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		send, err := spoof.OpenRawSender(dst, 32001, inv, *dev)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer send.Close()
		if err := send.Send(source, []byte("stl262-private-probe")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("send accepted locally (NOT peer-delivery proof)")
	case "ordinary-send":
		dst, err := net.ResolveUDPAddr("udp4", *peer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		conn, err := net.DialUDP("udp4", nil, dst)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ordinary")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("ordinary send accepted locally (NOT peer-delivery proof)")
	default:
		fmt.Fprintln(os.Stderr, "exact -mode recv|send|ordinary-send required")
		os.Exit(2)
	}
}
