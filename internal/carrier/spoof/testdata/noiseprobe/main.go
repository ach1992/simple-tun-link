//go:build linux

// Noiseprobe is an isolated network-namespace test helper. It is NOT a
// standalone production Link manager, TUN agent, release binary or public API.
// It demonstrates a real encrypted in-band Noise exchange across asymmetric
// selected spoof-source paths with no ordinary transport connection.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
	"github.com/ach1992/simple-tun-link/internal/spoofhost"
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "noise netns probe:", err)
		os.Exit(1)
	}
}

func readFrame(conn *net.UDPConn, expected domain.LinkID, attempt [16]byte, kind spoof.FrameKind) spoof.Frame {
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	buffer := make([]byte, 4096)
	n, outer, err := conn.ReadFromUDPAddrPort(buffer)
	check(err)
	f, err := spoof.DecodeFrame(buffer[:n])
	check(err)
	if f.LinkID != expected || f.Attempt != attempt || f.Kind != kind {
		check(fmt.Errorf("Noise frame not expected: kind=%v Link=%s, observed outer src=%s", f.Kind, f.LinkID, outer))
	}
	return f
}

func makeConfig(offer pairing.SpoofSetup, m spoofhost.Material, attempt [16]byte) spoof.HandshakeConfig {
	return spoof.HandshakeConfig{
		Role: spoof.Role(m.Role()), LinkID: offer.LinkID(), Attempt: attempt,
		CreatorEndpoint: offer.CreatorEndpoint(), RecipientEndpoint: offer.RecipientEndpoint(),
		CreatorPrivateIP: offer.CreatorPrivateIPv4(), RecipientPrivateIP: offer.RecipientPrivateIPv4(),
		LocalPrivateKey: m.StaticPrivateKey(), BootstrapSecret: m.BootstrapKey(),
		PeerPublicKey: func() []byte {
			if m.Role() == "recipient" {
				pub := offer.CreatorPublicKey()
				return pub[:]
			}
			return nil
		}(),
	}
}

func sendFrame(sender *spoof.RawSender, source netip.Addr, kind spoof.FrameKind, id domain.LinkID, attempt [16]byte, payload []byte) {
	frame, err := (spoof.Frame{Kind: kind, LinkID: id, Attempt: attempt, Payload: payload}).Encode()
	check(err)
	check(sender.Send(source, frame))
}

func run() error {
	mode := flag.String("mode", "", "create/creator/recipient/creator-tun/recipient-tun")
	root := flag.String("root", "", "absolute local protected material root")
	setupFile := flag.String("setup", "", "confidential single-transfer Setup Code file")
	sourceFile := flag.String("sources", "", "local source inventory")
	selectedSource := flag.String("source", "", "selected local IPv4")
	iface := flag.String("device", "", "local outgoing device")
	flag.Parse()
	if *root == "" || *setupFile == "" {
		return errors.New("local protected material root and Setup Code file required")
	}
	if *mode == "create" {
		if err := os.MkdirAll(*root, 0700); err != nil {
			return err
		}
		if err := os.Chmod(*root, 0700); err != nil {
			return err
		}
		id, err := domain.NewLinkID()
		if err != nil {
			return err
		}
		private, pub, err := spoof.GenerateIdentity()
		if err != nil {
			return err
		}
		offer, err := pairing.NewSpoofSetup(id,
			netip.MustParseAddrPort("10.77.0.1:42001"), netip.MustParseAddrPort("10.77.0.2:42002"),
			netip.MustParseAddr("10.89.0.0"), netip.MustParseAddr("10.89.0.1"), pub)
		if err != nil {
			return err
		}
		secret := offer.Secret()
		m, err := spoofhost.NewMaterial(id, "creator", private, secret)
		if err != nil {
			return err
		}
		if _, err = spoofhost.StageMaterial(*root, m); err != nil {
			return err
		}
		code, err := offer.EncodeSensitive()
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*setupFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err = f.WriteString(code + "\n"); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println("created private A and one confidential offline Setup Code without B identity")
		return nil
	}
	code, err := os.ReadFile(*setupFile)
	if err != nil {
		return err
	}
	offer, err := pairing.DecodeSensitiveSpoofSetup(string(code))
	if err != nil {
		return err
	}
	src, err := netip.ParseAddr(*selectedSource)
	if err != nil {
		return err
	}
	inv, err := spoof.ReadSources(*sourceFile)
	if err != nil {
		return err
	}
	var local, remote netip.AddrPort
	if strings.HasPrefix(*mode, "creator") {
		local, remote = offer.CreatorEndpoint(), offer.RecipientEndpoint()
	}
	if strings.HasPrefix(*mode, "recipient") {
		local, remote = offer.RecipientEndpoint(), offer.CreatorEndpoint()
	}
	if !local.IsValid() {
		return errors.New("invalid test-only Noise endpoint mode")
	}
	receiver, err := spoof.OpenReceiver(local)
	if err != nil {
		return err
	}
	defer receiver.Close()
	sender, err := spoof.OpenRawSender(remote, local.Port(), inv, *iface)
	if err != nil {
		return err
	}
	defer sender.Close()
	var m spoofhost.Material
	if strings.HasPrefix(*mode, "creator") {
		m, _, err = spoofhost.ReadMaterial(*root, offer.LinkID(), "")
		if err != nil {
			return err
		}
	} else {
		if err := os.MkdirAll(*root, 0700); err != nil {
			return err
		}
		m, _, err = spoofhost.ReadMaterial(*root, offer.LinkID(), "")
		if err != nil {
			if !os.IsNotExist(err) && !strings.Contains(err.Error(), "no such file or directory") {
				return err
			}
			private, _, keyErr := spoof.GenerateIdentity()
			if keyErr != nil {
				return keyErr
			}
			m, keyErr = spoofhost.NewMaterial(offer.LinkID(), "recipient", private, offer.Secret())
			if keyErr != nil {
				return keyErr
			}
			if _, keyErr = spoofhost.StageMaterial(*root, m); keyErr != nil {
				return keyErr
			}
		}
		if m.Role() != "recipient" || m.BootstrapKey() != offer.Secret() {
			return errors.New("locally protected B identity is not bound to the exact original Setup Code")
		}
	}
	if strings.HasPrefix(*mode, "creator") {
		_ = receiver.SetReadDeadline(time.Now().Add(6 * time.Second))
		buffer := make([]byte, 4096)
		n, _, err := receiver.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		first, err := spoof.DecodeFrame(buffer[:n])
		if err != nil {
			return err
		}
		if first.LinkID != offer.LinkID() || first.Kind != spoof.KindHandshake1 {
			return errors.New("unexpected initial Noise handshake")
		}
		a, err := spoof.NewHandshake(makeConfig(offer, m, first.Attempt))
		if err != nil {
			return err
		}
		m2, _, err := a.Handle(first.Payload)
		if err != nil {
			return err
		}
		sendFrame(sender, src, spoof.KindHandshake2, offer.LinkID(), first.Attempt, m2)
		last := readFrame(receiver, offer.LinkID(), first.Attempt, spoof.KindHandshake3)
		_, s, err := a.Handle(last.Payload)
		if err != nil {
			return err
		}
		if *mode == "creator-tun" {
			return runTUNTunnel(offer, m, s, receiver, sender, src)
		}
		data, err := s.Seal(spoof.KindData, []byte("encrypted private packet A to B"))
		if err != nil {
			return err
		}
		if err := sender.Send(src, data); err != nil {
			return err
		}
		_ = receiver.SetReadDeadline(time.Now().Add(6 * time.Second))
		n, _, err = receiver.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		kind, plaintext, err := s.Open(buffer[:n])
		if err != nil || kind != spoof.KindData || !bytes.Equal(plaintext, []byte("encrypted private packet B to A")) {
			return fmt.Errorf("invalid authenticated B->A inner packet kind=%d: %w", kind, err)
		}
		fmt.Println("PASS: A authenticated B and decrypted B->A packet on selected different Source")
		return nil
	}
	if strings.HasPrefix(*mode, "recipient") {
		attempt, err := spoof.NewAttempt()
		if err != nil {
			return err
		}
		b, err := spoof.NewHandshake(makeConfig(offer, m, attempt))
		if err != nil {
			return err
		}
		m1, err := b.Start()
		if err != nil {
			return err
		}
		sendFrame(sender, src, spoof.KindHandshake1, offer.LinkID(), attempt, m1)
		second := readFrame(receiver, offer.LinkID(), attempt, spoof.KindHandshake2)
		m3, s, err := b.Handle(second.Payload)
		if err != nil {
			return err
		}
		sendFrame(sender, src, spoof.KindHandshake3, offer.LinkID(), attempt, m3)
		if *mode == "recipient-tun" {
			return runTUNTunnel(offer, m, s, receiver, sender, src)
		}
		data, err := s.Seal(spoof.KindData, []byte("encrypted private packet B to A"))
		if err != nil {
			return err
		}
		if err := sender.Send(src, data); err != nil {
			return err
		}
		_ = receiver.SetReadDeadline(time.Now().Add(6 * time.Second))
		buffer := make([]byte, 4096)
		n, _, err := receiver.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		kind, plaintext, err := s.Open(buffer[:n])
		if err != nil || kind != spoof.KindData || !bytes.Equal(plaintext, []byte("encrypted private packet A to B")) {
			return fmt.Errorf("invalid authenticated A->B inner packet kind=%d: %w", kind, err)
		}
		fmt.Println("PASS: B authenticated A and decrypted A->B packet over selected different Source")
		return nil
	}
	return errors.New("unsupported test helper mode")
}

// runTUNTunnel is a test-only end-to-end data-plane probe. Its TUN/routes
// are namespace-local and disappear when the file descriptor/process closes.
// The production application Engine and service ownership are NOT yet wired.
func runTUNTunnel(offer pairing.SpoofSetup, m spoofhost.Material, session *spoof.Session,
	receiver *net.UDPConn, sender *spoof.RawSender, source netip.Addr) error {
	local, peer := offer.CreatorPrivateIPv4(), offer.RecipientPrivateIPv4()
	if m.Role() == "recipient" {
		local, peer = peer, local
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tun, err := spoof.OpenPrivateTUN(ctx, offer.LinkID(), 1280, local, peer)
	if err != nil {
		return err
	}
	defer tun.Close()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for workerCtx.Err() == nil {
			packet, err := tun.ReadPacket(workerCtx)
			if err != nil {
				if workerCtx.Err() == nil {
					failures <- err
				}
				return
			}
			frame, err := session.Seal(spoof.KindData, packet)
			if err != nil {
				failures <- err
				return
			}
			if err := sender.Send(source, frame); err != nil {
				failures <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for workerCtx.Err() == nil {
			_ = receiver.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			n, _, err := receiver.ReadFromUDPAddrPort(buf)
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			if err != nil {
				if workerCtx.Err() == nil {
					failures <- err
				}
				return
			}
			kind, packet, err := session.Open(buf[:n])
			if err != nil {
				continue
			} // Unauthenticated/tampered packets have no TUN effects
			if kind != spoof.KindData {
				continue
			}
			if err := tun.WritePacket(workerCtx, packet); err != nil {
				failures <- err
				return
			}
		}
	}()
	fmt.Printf("READY: %s private TUN %s peer %s (Noise authenticated; real app traffic pending)\n", m.Role(), local, peer)
	var failed error
	select {
	case failed = <-failures:
	case <-ctx.Done():
	}
	cancel()
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return failed
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Noise netns failed:", err)
		os.Exit(1)
	}
}
