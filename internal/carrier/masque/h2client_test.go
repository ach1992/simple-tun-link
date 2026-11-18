package masque

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func testTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "masque-test.invalid"},
			DNSNames: []string{"masque-test.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "masque-test.invalid"},
			DNSNames: []string{"masque-test.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return cert, pool
}

func serverHeaders(t *testing.T, fr *http2.Framer, fields ...hpack.HeaderField) {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, field := range fields {
		if err := enc.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
}

func TestH2ConnectIPRealFramesAndPackets(t *testing.T) {
	cert, ca := testTLS(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
			done <- fmt.Errorf("invalid client preface: %w", err)
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		gotSettings, gotHeader, gotPayload := false, false, false
		var decodedCapsules capsuleStream
		for !gotPayload {
			f, err := fr.ReadFrame()
			if err != nil {
				done <- err
				return
			}
			switch v := f.(type) {
			case *http2.SettingsFrame:
				if v.IsAck() {
					continue
				}
				gotSettings = true
				if err := fr.WriteSettings(
					http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},
					http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1024 * 1024},
				); err != nil {
					done <- err
					return
				}
				if err := fr.WriteWindowUpdate(0, 1024*1024); err != nil {
					done <- err
					return
				}
			case *http2.MetaHeadersFrame:
				if !gotSettings || v.PseudoValue("method") != "CONNECT" ||
					v.PseudoValue("protocol") != "connect-ip" ||
					v.PseudoValue("path") != "/.well-known/masque/ip/" {
					done <- fmt.Errorf("invalid extended CONNECT pseudo headers: %v", v.PseudoFields())
					return
				}
				auth := ""
				for _, f := range v.RegularFields() {
					if f.Name == "proxy-authorization" {
						auth = f.Value
					}
				}
				if auth != "Basic "+base64.StdEncoding.EncodeToString([]byte("tester:secret")) {
					done <- fmt.Errorf("missing HTTPS Basic authorization")
					return
				}
				gotHeader = true
				serverHeaders(t, fr, hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "capsule-protocol", Value: "?1"})
				assign := []byte{0, 4, 10, 251, 95, 2, 32}
				var packet []byte
				packet, _ = appendVarint(packet, capsuleAddressAssign)
				packet, _ = appendVarint(packet, uint64(len(assign)))
				packet = append(packet, assign...)
				if err := fr.WriteData(1, false, packet); err != nil {
					done <- err
					return
				}
			case *http2.DataFrame:
				err = decodedCapsules.feed(v.Data(), nil, func(pkt []byte) error {
					if !bytes.Equal(pkt, testPacket()) {
						return fmt.Errorf("invalid inner IPv4 datagram")
					}
					reply := append([]byte(nil), pkt...)
					copy(reply[12:16], []byte{10, 251, 95, 1})
					copy(reply[16:20], []byte{10, 251, 95, 2})
					wire, err := datagramCapsule(reply)
					if err == nil {
						err = fr.WriteData(1, false, wire)
					}
					if err == nil {
						gotPayload = true
					}
					return err
				})
				if err != nil {
					done <- err
					return
				}
			}
		}
		if !gotHeader || !gotSettings {
			done <- fmt.Errorf("missing protocol setup")
			return
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	c, err := DialH2(ctx, H2Config{
		Address: listener.Addr().String(), ServerName: "masque-test.invalid", Roots: ca,
		Username: "tester", Password: "secret", ExpectedIPv4: netip.MustParseAddr("10.251.95.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SendPackets(ctx, [][]byte{testPacket()}); err != nil {
		t.Fatal(err)
	}
	reply, err := c.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reply[12:16], []byte{10, 251, 95, 1}) ||
		!slices.Equal(reply[16:20], []byte{10, 251, 95, 2}) {
		t.Fatalf("invalid reply private IPs: %v", reply[12:20])
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("mock MASQUE server did not receive data")
	}
}

func TestH2RejectsUntrustedAndMissingIdentity(t *testing.T) {
	cert, _ := testTLS(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = DialH2(ctx, H2Config{Address: listener.Addr().String(), ServerName: "masque-test.invalid",
		Roots: x509.NewCertPool(), Username: "test", Password: "secret", ExpectedIPv4: netip.MustParseAddr("10.251.95.2")})
	if err == nil {
		t.Fatal("accepted untrusted server certificate")
	}
	wg.Wait()
	_, err = DialH2(ctx, H2Config{Address: listener.Addr().String(), ServerName: "masque-test.invalid",
		Roots: x509.NewCertPool(), ExpectedIPv4: netip.MustParseAddr("10.251.95.2")})
	if err == nil {
		t.Fatal("accepted missing client credential")
	}
}

func TestCapsuleRecvRejectsWrongDestination(t *testing.T) {
	pkt := testPacket()
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	buf, err := datagramCapsule(pkt)
	if err != nil {
		t.Fatal(err)
	}
	var parsed capsuleStream
	if err := parsed.feed(buf, nil, func(p []byte) error {
		if !slices.Equal(p[16:20], []byte{10, 251, 95, 1}) {
			t.Fatal("unexpected test destination")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
