package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// An idle CONNECT-IP stream must remain available without private-IP
// activity. If an authenticated peer stops transmitting H2 frames, its
// session must expire and allow a fresh connection using the SAME identity.
func TestNativeMASQUEH2QuietLinkAndSilentPeerRecovery(t *testing.T) {
	serverIdentity, root := testTLS(t)
	clientIdentity, peerSPKI := testClientIdentity(t)
	pipe := &channelPrivatePipe{
		toServer: make(chan []byte, 4),
		toClient: make(chan []byte, 4),
	}
	addr := availableListener(t)
	srv, err := newH2ServerWithLiveness(H2ListenConfig{
		ListenAddress: addr, TLSServerName: "masque-test.invalid",
		ServerCert: serverIdentity, PeerSPKI: peerSPKI,
		LocalIPv4: netip.MustParseAddr("10.251.95.1"),
		PeerIPv4:  netip.MustParseAddr("10.251.95.2"),
	}, pipe, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Serve(ctx) }()

	connect := func(probe, timeout time.Duration) *H2Client {
		t.Helper()
		for i := 0; i < 30; i++ {
			c, err := dialH2WithLiveness(ctx, H2Config{
				Address: addr, ServerName: "masque-test.invalid", Roots: root,
				ClientCert: &clientIdentity, ExpectedIPv4: netip.MustParseAddr("10.251.95.2"),
				ConnectTimeout: time.Second,
			}, probe, timeout)
			if err == nil {
				return c
			}
			if !isDialConnectRefused(err) && !isH2NotYetReleased(err) {
				t.Fatalf("native authenticated reconnect: %v", err)
			}
			time.Sleep(15 * time.Millisecond)
		}
		t.Fatal("native MASQUE listener did not release authenticated slot")
		return nil
	}
	client := connect(30*time.Millisecond, 500*time.Millisecond)
	// More than three complete server-side idle windows. Without H2 PING,
	// the unchanged server would close this otherwise valid quiet session.
	time.Sleep(850 * time.Millisecond)
	select {
	case <-client.Done():
		t.Fatalf("quiet authenticated link disconnected: %v", client.Err())
	default:
	}
	req := testPacket()
	if err := client.SendPackets(ctx, [][]byte{req}); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-pipe.toServer:
		if !bytes.Equal(pkt, req) {
			t.Fatal("private traffic corrupted after idle")
		}
	case <-ctx.Done():
		t.Fatal("private traffic unavailable after quiet H2 probes")
	}
	_ = client.Close()

	// Emulate an authenticated but silent H2 peer. The server must not keep
	// the one permitted client slot occupied indefinitely after its final
	// application frame, even though the TLS socket remains established.
	silent := connect(5*time.Second, 3*time.Second)
	select {
	case <-silent.Done():
		if silent.Err() == nil {
			t.Fatal("silent peer closed without reason")
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("silent authenticated peer occupied server indefinitely")
	}
	_ = silent.Close()
	reconnected := connect(30*time.Millisecond, 500*time.Millisecond)
	if err := reconnected.SendPackets(ctx, [][]byte{req}); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-pipe.toServer:
		if !bytes.Equal(pkt, req) {
			t.Fatal("private packet changed after expired client reconnect")
		}
	case <-ctx.Done():
		t.Fatal("replacement client could not send private packet")
	}
	_ = reconnected.Close()
	cancel()
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("server exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server failed to stop after reconnect")
	}
}

func isH2NotYetReleased(err error) bool {
	return err != nil && (bytes.Contains([]byte(err.Error()), []byte("status 409")) ||
		bytes.Contains([]byte(err.Error()), []byte("HTTP status 409")))
}

// A half-open peer may continue to accept TCP writes into kernel buffers
// without ever reading or acknowledging H2 PINGs. The authenticated client
// must retire the session independently of the ordinary TUN packet rate.
func TestMASQUEH2ClientExpiresNonresponsiveAuthenticatedServer(t *testing.T) {
	serverCert, ca := testTLS(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"h2"}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()
		go func() { <-ctx.Done(); _ = raw.Close() }()
		if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			serverDone <- err
			return
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(raw, preface); err != nil {
			serverDone <- err
			return
		}
		if string(preface) != http2.ClientPreface {
			serverDone <- fmt.Errorf("invalid H2 client preface")
			return
		}
		fr := http2.NewFramer(raw, raw)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		seenSettings := false
		for {
			frame, err := fr.ReadFrame()
			if err != nil {
				serverDone <- err
				return
			}
			switch f := frame.(type) {
			case *http2.SettingsFrame:
				if f.IsAck() {
					continue
				}
				if !seenSettings {
					seenSettings = true
					err = fr.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
					if err != nil {
						serverDone <- err
						return
					}
				}
			case *http2.MetaHeadersFrame:
				if !seenSettings || f.PseudoValue("protocol") != "connect-ip" {
					serverDone <- fmt.Errorf("unexpected fake request")
					return
				}
				var header bytes.Buffer
				enc := hpack.NewEncoder(&header)
				if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
					serverDone <- err
					return
				}
				if err := enc.WriteField(hpack.HeaderField{Name: "capsule-protocol", Value: "?1"}); err != nil {
					serverDone <- err
					return
				}
				if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: header.Bytes(), EndHeaders: true}); err != nil {
					serverDone <- err
					return
				}
				assign := []byte{0, 4, 10, 251, 95, 2, 32}
				capsule, _ := appendVarint(nil, capsuleAddressAssign)
				capsule, _ = appendVarint(capsule, uint64(len(assign)))
				if err := fr.WriteData(1, false, append(capsule, assign...)); err != nil {
					serverDone <- err
					return
				}
				// Intentionally stop reading and responding. This is not a
				// proxy, just an in-memory authenticated H2 failure fixture.
				<-ctx.Done()
				serverDone <- nil
				return
			}
		}
	}()
	client, err := dialH2WithLiveness(ctx, H2Config{
		Address: listener.Addr().String(), ServerName: "masque-test.invalid",
		Roots: ca, Username: "test", Password: "local-fixture",
		ExpectedIPv4:   netip.MustParseAddr("10.251.95.2"),
		ConnectTimeout: time.Second,
	}, 25*time.Millisecond, 180*time.Millisecond)
	if err != nil {
		t.Fatalf("authenticated fake H2 setup: %v", err)
	}
	defer client.Close()
	select {
	case <-client.Done():
		if client.Err() == nil {
			t.Fatal("expired H2 stream returned no reason")
		}
	case <-time.After(800 * time.Millisecond):
		t.Fatal("no read deadline after authenticated server stopped responding")
	}
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("fake H2 session failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled server fixture did not exit")
	}
}
