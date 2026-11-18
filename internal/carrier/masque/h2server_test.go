package masque

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"
)

type channelPrivatePipe struct {
	toClient chan []byte
	toServer chan []byte
}

func (p *channelPrivatePipe) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case v := <-p.toClient:
		return v, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (p *channelPrivatePipe) WritePacket(ctx context.Context, v []byte) error {
	select {
	case p.toServer <- bytes.Clone(v):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func testClientIdentity(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certObj := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stl-test-client"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certObj, certObj, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return identity, leaf.RawSubjectPublicKeyInfo
}

func availableListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func TestNativeH2MASQUEServerMatchesH2Client(t *testing.T) {
	serverIdentity, root := testTLS(t)
	clientIdentity, peerSPKI := testClientIdentity(t)
	pipe := &channelPrivatePipe{toServer: make(chan []byte, 10), toClient: make(chan []byte, 10)}
	addr := availableListener(t)
	srv, err := NewH2Server(H2ListenConfig{
		ListenAddress: addr, TLSServerName: "masque-test.invalid",
		ServerCert: serverIdentity, PeerSPKI: peerSPKI,
		LocalIPv4: netip.MustParseAddr("10.251.95.1"),
		PeerIPv4:  netip.MustParseAddr("10.251.95.2"),
	}, pipe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Serve(ctx) }()
	ready := false
	for i := 0; i < 80; i++ {
		conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("MASQUE test listener did not bind")
	}
	var client *H2Client
	for i := 0; i < 3; i++ {
		client, err = DialH2(ctx, H2Config{
			Address: addr, ServerName: "masque-test.invalid",
			Roots: root, ClientCert: &clientIdentity,
			ExpectedIPv4:   netip.MustParseAddr("10.251.95.2"),
			ConnectTimeout: 2 * time.Second,
		})
		if err == nil {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if err != nil {
		select {
		case serverErr := <-serverDone:
			t.Fatalf("native H2 server already terminated: %v; dial: %v", serverErr, err)
		default:
			t.Fatal("native server/client RFC 9484 negotiation failed:", err)
		}
	}
	defer client.Close()

	request := testPacket()
	if err := client.SendPackets(ctx, [][]byte{request}); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-pipe.toServer:
		if !bytes.Equal(result, request) {
			t.Fatal("native MASQUE listener private TUN packet differs from sent request")
		}
	case <-ctx.Done():
		t.Fatal("native MASQUE listener did not deliver client private packet")
	}
	response := bytes.Clone(request)
	copy(response[12:16], []byte{10, 251, 95, 1})
	copy(response[16:20], []byte{10, 251, 95, 2})
	select {
	case pipe.toClient <- response:
	case <-ctx.Done():
		t.Fatal("could not queue server private response")
	}
	got, err := client.ReadPacket(ctx)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("private L3 server-to-client reply failed: %v", err)
	}

	cancel()
	_ = client.Close()
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal("server stop failed:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server failed to stop after context cancellation")
	}
}

func TestNativeMASQUEListenerRejectsUnpinnedPeer(t *testing.T) {
	serverIdentity, root := testTLS(t)
	_, authorizedSPKI := testClientIdentity(t)
	foreignCert, _ := testClientIdentity(t)
	pipe := &channelPrivatePipe{toServer: make(chan []byte, 1), toClient: make(chan []byte, 1)}
	addr := availableListener(t)
	srv, err := NewH2Server(H2ListenConfig{
		ListenAddress: addr, TLSServerName: "masque-test.invalid",
		ServerCert: serverIdentity, PeerSPKI: authorizedSPKI,
		LocalIPv4: netip.MustParseAddr("10.251.95.1"), PeerIPv4: netip.MustParseAddr("10.251.95.2"),
	}, pipe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	for i := 0; i < 20; i++ {
		client, dialErr := DialH2(ctx, H2Config{
			Address: addr, ServerName: "masque-test.invalid",
			Roots: root, ClientCert: &foreignCert,
			ExpectedIPv4:   netip.MustParseAddr("10.251.95.2"),
			ConnectTimeout: 2 * time.Second,
		})
		if dialErr == nil {
			client.Close()
			t.Fatal("unregistered MASQUE mTLS identity was accepted")
		}
		if isDialConnectRefused(dialErr) {
			time.Sleep(15 * time.Millisecond)
			continue
		}
		break
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("mTLS listener did not shut down")
	}
}

func isDialConnectRefused(err error) bool {
	if err == nil {
		return false
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return op.Op == "dial"
	}
	return false
}

var _ PrivatePacketIO = (*channelPrivatePipe)(nil)
