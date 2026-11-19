package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// A single CONNECT-IP stream must carry more than its initial 8 MiB H2
// flow-control window in either direction. This exercises the real TLS/H2
// framing and WINDOW_UPDATE protocol, not a kernel route or WAN benchmark.
func TestNativeMASQUEBidirectionalFlowControlBeyondInitialWindow(t *testing.T) {
	const packets = 7168
	const packetBytes = 1200 // 8.2 MiB of private datagrams per direction
	const batchSize = 32

	makePacket := func(index int, fromClient bool) []byte {
		p := make([]byte, packetBytes)
		p[0] = 0x45 // IPv4, 20-byte header
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		p[8], p[9] = 64, 17
		if fromClient {
			copy(p[12:16], []byte{10, 251, 95, 2})
			copy(p[16:20], []byte{10, 251, 95, 1})
		} else {
			copy(p[12:16], []byte{10, 251, 95, 1})
			copy(p[16:20], []byte{10, 251, 95, 2})
		}
		binary.BigEndian.PutUint32(p[20:24], uint32(index))
		return p
	}

	serverCert, roots := testTLS(t)
	clientCert, peerSPKI := testClientIdentity(t)
	pipe := &channelPrivatePipe{
		toServer: make(chan []byte, 32),
		toClient: make(chan []byte, 32),
	}
	addr := availableListener(t)
	srv, err := NewH2Server(H2ListenConfig{
		ListenAddress: addr, TLSServerName: "masque-test.invalid",
		ServerCert: serverCert, PeerSPKI: peerSPKI,
		LocalIPv4: netip.MustParseAddr("10.251.95.1"),
		PeerIPv4:  netip.MustParseAddr("10.251.95.2"),
	}, pipe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Serve(ctx) }()

	// A refused connection may simply precede the listener's first bind.
	var client *H2Client
	for attempt := 0; attempt < 20; attempt++ {
		client, err = DialH2(ctx, H2Config{
			Address: addr, ServerName: "masque-test.invalid",
			Roots: roots, ClientCert: &clientCert,
			ExpectedIPv4:   netip.MustParseAddr("10.251.95.2"),
			ConnectTimeout: 2 * time.Second,
		})
		if err == nil {
			break
		}
		if !isDialConnectRefused(err) {
			t.Fatalf("authenticated CONNECT-IP dial: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("listener did not become available: %v", err)
	}
	defer client.Close()

	received := make(chan error, 1)
	go func() {
		for i := 0; i < packets; i++ {
			select {
			case got := <-pipe.toServer:
				if !bytes.Equal(got, makePacket(i, true)) {
					received <- fmt.Errorf("client-to-server packet %d changed", i)
					return
				}
			case <-ctx.Done():
				received <- ctx.Err()
				return
			}
		}
		received <- nil
	}()

	for i := 0; i < packets; i += batchSize {
		batch := make([][]byte, 0, batchSize)
		for j := i; j < i+batchSize && j < packets; j++ {
			batch = append(batch, makePacket(j, true))
		}
		if err := client.SendPackets(ctx, batch); err != nil {
			t.Fatalf("client-to-server flow control at packet %d: %v", i, err)
		}
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}

	delivered := make(chan error, 1)
	go func() {
		for i := 0; i < packets; i++ {
			select {
			case pipe.toClient <- makePacket(i, false):
			case <-ctx.Done():
				delivered <- ctx.Err()
				return
			}
		}
		delivered <- nil
	}()
	for i := 0; i < packets; i++ {
		got, err := client.ReadPacket(ctx)
		if err != nil {
			t.Fatalf("server-to-client flow control at packet %d: %v", i, err)
		}
		if !bytes.Equal(got, makePacket(i, false)) {
			t.Fatalf("server-to-client packet %d changed", i)
		}
	}
	if err := <-delivered; err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = client.Close()
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("server did not stop cleanly: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}
