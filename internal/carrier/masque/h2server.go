package masque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// PrivatePacketIO supplies one Link-owned private IPv4 pair. It is deliberately
// separate from routing, TUN creation, credential storage and host ownership.
type PrivatePacketIO interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
}

type H2ListenConfig struct {
	ListenAddress string
	TLSServerName string
	ServerCert    tls.Certificate
	// Pin the exact authorized mTLS client identity to this Link.
	PeerSPKI  []byte
	LocalIPv4 netip.Addr
	PeerIPv4  netip.Addr
}

type H2Server struct {
	cfg      H2ListenConfig
	pipe     PrivatePacketIO
	activeMu sync.Mutex
	active   bool
}

func validateH2ListenConfig(c H2ListenConfig) error {
	if c.TLSServerName == "" || c.ListenAddress == "" || len(c.PeerSPKI) == 0 ||
		!c.LocalIPv4.Is4() || !c.PeerIPv4.Is4() ||
		c.LocalIPv4.IsUnspecified() || c.PeerIPv4.IsUnspecified() ||
		c.LocalIPv4 == c.PeerIPv4 {
		return errors.New("MASQUE listener identity, pinned peer or private addresses invalid")
	}
	if _, err := x509.ParsePKIXPublicKey(c.PeerSPKI); err != nil {
		return errors.New("MASQUE listener expected peer public key is invalid")
	}
	_, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return errors.New("MASQUE listener bind address is not host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("MASQUE listener port is invalid")
	}
	if len(c.ServerCert.Certificate) == 0 || c.ServerCert.PrivateKey == nil {
		return errors.New("MASQUE server TLS certificate and protected key required")
	}
	return nil
}

func NewH2Server(cfg H2ListenConfig, pipe PrivatePacketIO) (*H2Server, error) {
	if err := validateH2ListenConfig(cfg); err != nil {
		return nil, err
	}
	if pipe == nil {
		return nil, errors.New("MASQUE server private packet interface unavailable")
	}
	return &H2Server{cfg: cfg, pipe: pipe}, nil
}

func (s *H2Server) TLSConfig() *tls.Config {
	expected := append([]byte(nil), s.cfg.PeerSPKI...)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
		Certificates: []tls.Certificate{s.cfg.ServerCert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(chain [][]byte, _ [][]*x509.Certificate) error {
			if len(chain) == 0 {
				return errors.New("MASQUE peer TLS certificate identity missing")
			}
			cert, err := x509.ParseCertificate(chain[0])
			if err != nil {
				return errors.New("MASQUE peer TLS certificate cannot be parsed")
			}
			if subtle.ConstantTimeCompare(cert.RawSubjectPublicKeyInfo, expected) != 1 {
				return errors.New("MASQUE client identity does not match the authorized Link")
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("MASQUE peer certificate expired or not yet valid")
			}
			return nil
		},
	}
}

func (s *H2Server) Serve(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.cfg.ListenAddress, s.TLSConfig())
	if err != nil {
		return fmt.Errorf("MASQUE TLS listener unavailable: %w", err)
	}
	defer ln.Close()
	shutdown := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-shutdown:
		}
	}()
	defer close(shutdown)
	var workers sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			workers.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("MASQUE TLS accept failure: %w", err)
		}
		workers.Add(1)
		go func(raw net.Conn) {
			defer workers.Done()
			defer raw.Close()
			tlsConn, ok := raw.(*tls.Conn)
			if !ok {
				return
			}
			handshakeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			err := tlsConn.HandshakeContext(handshakeCtx)
			cancel()
			if err != nil || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
				return
			}
			_ = s.serveH2(ctx, tlsConn)
		}(conn)
	}
}

// Per-connection HTTP/2 codec. x/net/http2.Server intentionally disables
// RFC 8441 Extended CONNECT by default (Issue #71128). A private, bounded
// HTTP/2 Framer is used instead of a global GODEBUG compatibility setting.
// A single authenticated CONNECT-IP stream is allowed on each TLS connection.
type h2ServerConn struct {
	conn              net.Conn
	fr                *http2.Framer
	buf               *bufio.Writer
	writeMu           sync.Mutex
	sendMu            sync.Mutex
	flowMu            sync.Mutex
	peerFrameSize     int64
	connWindow        int64
	streamWindow      int64
	peerInitialWindow int64
	flowChange        chan struct{}
}

func (h *h2ServerConn) write(do func(*http2.Framer) error) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	if err := do(h.fr); err != nil {
		return err
	}
	return h.buf.Flush()
}

func (h *h2ServerConn) signalFlow() {
	close(h.flowChange)
	h.flowChange = make(chan struct{})
}

func (h *h2ServerConn) sendData(ctx context.Context, data []byte) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	for len(data) > 0 {
		h.flowMu.Lock()
		n := min(int64(len(data)), h.peerFrameSize, h.connWindow, h.streamWindow)
		if n > 0 {
			h.connWindow -= n
			h.streamWindow -= n
			h.flowMu.Unlock()
			if err := h.write(func(fr *http2.Framer) error {
				return fr.WriteData(1, false, data[:n])
			}); err != nil {
				return err
			}
			data = data[n:]
			continue
		}
		ch := h.flowChange
		h.flowMu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (h *h2ServerConn) readSetting(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	if err := f.ForeachSetting(func(s http2.Setting) error {
		h.flowMu.Lock()
		defer h.flowMu.Unlock()
		switch s.ID {
		case http2.SettingInitialWindowSize:
			if s.Val > (1<<31)-1 {
				return errors.New("MASQUE client advertised invalid stream window")
			}
			h.streamWindow += int64(s.Val) - h.peerInitialWindow
			h.peerInitialWindow = int64(s.Val)
		case http2.SettingMaxFrameSize:
			if s.Val < 16384 || s.Val > (1<<24)-1 {
				return errors.New("MASQUE client advertised invalid frame size")
			}
			h.peerFrameSize = int64(s.Val)
		}
		h.signalFlow()
		return nil
	}); err != nil {
		return err
	}
	return h.write(func(fr *http2.Framer) error { return fr.WriteSettingsAck() })
}

func (h *h2ServerConn) updateWindow(f *http2.WindowUpdateFrame) error {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	if f.Increment == 0 {
		return errors.New("MASQUE client sent invalid zero window update")
	}
	if f.StreamID == 0 {
		h.connWindow += int64(f.Increment)
	} else if f.StreamID == 1 {
		h.streamWindow += int64(f.Increment)
	}
	if h.connWindow > (1<<31)-1 || h.streamWindow > (1<<31)-1 {
		return errors.New("MASQUE peer HTTP/2 window overflow")
	}
	h.signalFlow()
	return nil
}

func (h *h2ServerConn) reply(code string, assignment []byte) error {
	var hdr bytes.Buffer
	e := hpack.NewEncoder(&hdr)
	if err := e.WriteField(hpack.HeaderField{Name: ":status", Value: code}); err != nil {
		return err
	}
	if code == "200" {
		if err := e.WriteField(hpack.HeaderField{Name: "capsule-protocol", Value: "?1"}); err != nil {
			return err
		}
	}
	if err := h.write(func(fr *http2.Framer) error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: 1, BlockFragment: hdr.Bytes(), EndHeaders: true, EndStream: code != "200",
		})
	}); err != nil {
		return err
	}
	if len(assignment) > 0 {
		return h.sendData(context.Background(), assignment)
	}
	return nil
}

func (s *H2Server) authorizeRequest(f *http2.MetaHeadersFrame) bool {
	if f.StreamID != 1 || f.Truncated || f.StreamEnded() ||
		f.PseudoValue("method") != "CONNECT" ||
		f.PseudoValue("scheme") != "https" ||
		f.PseudoValue("protocol") != "connect-ip" ||
		f.PseudoValue("path") != "/.well-known/masque/ip/" {
		return false
	}
	_, port, _ := net.SplitHostPort(s.cfg.ListenAddress)
	if f.PseudoValue("authority") != net.JoinHostPort(s.cfg.TLSServerName, port) {
		return false
	}
	for _, hdr := range f.RegularFields() {
		if hdr.Name == "capsule-protocol" && hdr.Value == "?1" {
			return true
		}
	}
	return false
}

func (s *H2Server) serveH2(parent context.Context, conn net.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	closeOnCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-closeOnCancel:
		}
	}()
	defer close(closeOnCancel)
	// Verify the preface before granting any stream or kernel packet access.
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return fmt.Errorf("MASQUE client H2 preface failed: %w", err)
	}
	if string(preface) != http2.ClientPreface {
		return errors.New("MASQUE client did not send an HTTP/2 preface")
	}
	writer := bufio.NewWriterSize(conn, 128*1024)
	fr := http2.NewFramer(writer, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 16384
	fr.SetMaxReadFrameSize(65535)
	h := &h2ServerConn{
		conn: conn, fr: fr, buf: writer,
		peerFrameSize: 16384, connWindow: 65535, streamWindow: 65535,
		peerInitialWindow: 65535, flowChange: make(chan struct{}),
	}
	if err := h.write(func(fr *http2.Framer) error {
		return fr.WriteSettings(
			http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: 8 * 1024 * 1024},
			http2.Setting{ID: http2.SettingMaxFrameSize, Val: 65535},
		)
	}); err != nil {
		return err
	}
	if err := h.write(func(fr *http2.Framer) error { return fr.WriteWindowUpdate(0, 8*1024*1024) }); err != nil {
		return err
	}
	var decoder capsuleStream
	accepted := false
	first := true
	outErrors := make(chan error, 1)
	for {
		frame, err := h.fr.ReadFrame()
		if err != nil {
			return fmt.Errorf("MASQUE client HTTP/2 receive ended: %w", err)
		}
		if first {
			if _, ok := frame.(*http2.SettingsFrame); !ok {
				return errors.New("MASQUE first client HTTP/2 frame must be SETTINGS")
			}
			first = false
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			err = h.readSetting(f)
		case *http2.WindowUpdateFrame:
			err = h.updateWindow(f)
		case *http2.MetaHeadersFrame:
			if accepted || !s.authorizeRequest(f) {
				_ = h.reply("400", nil)
				return errors.New("MASQUE unexpected CONNECT-IP stream")
			}
			s.activeMu.Lock()
			if s.active {
				s.activeMu.Unlock()
				_ = h.reply("409", nil)
				return errors.New("MASQUE Link already has an active client")
			}
			s.active = true
			s.activeMu.Unlock()
			defer func() {
				s.activeMu.Lock()
				s.active = false
				s.activeMu.Unlock()
			}()
			assignment := []byte{0, 4}
			assignment = append(assignment, s.cfg.PeerIPv4.AsSlice()...)
			assignment = append(assignment, 32)
			capsule, _ := appendVarint(nil, capsuleAddressAssign)
			capsule, _ = appendVarint(capsule, uint64(len(assignment)))
			capsule = append(capsule, assignment...)
			if err := h.reply("200", capsule); err != nil {
				return err
			}
			_ = conn.SetReadDeadline(time.Time{})
			accepted = true
			go func() {
				for {
					packet, err := s.pipe.ReadPacket(ctx)
					if err != nil {
						select {
						case outErrors <- err:
						default:
						}
						cancel()
						return
					}
					allow, err := validateOutboundIPv4Packet(packet, s.cfg.LocalIPv4, s.cfg.PeerIPv4)
					if err != nil {
						select {
						case outErrors <- err:
						default:
						}
						cancel()
						return
					}
					if !allow {
						continue
					}
					wire, err := datagramCapsule(packet)
					if err == nil {
						err = h.sendData(ctx, wire)
					}
					if err != nil {
						select {
						case outErrors <- err:
						default:
						}
						cancel()
						return
					}
				}
			}()
		case *http2.DataFrame:
			if !accepted || f.StreamID != 1 || f.StreamEnded() {
				return errors.New("MASQUE unexpected HTTP/2 data stream")
			}
			err = decoder.feed(f.Data(), func(netip.Prefix) error {
				return errors.New("MASQUE client cannot assign private Link addresses")
			}, func(p []byte) error {
				allow, reason := validateInboundIPv4Packet(p, s.cfg.PeerIPv4, s.cfg.LocalIPv4)
				if reason != nil {
					return reason
				}
				if !allow {
					return nil
				}
				return s.pipe.WritePacket(ctx, p)
			})
			if err == nil && f.Header().Length > 0 {
				err = h.write(func(fr *http2.Framer) error {
					if err := fr.WriteWindowUpdate(0, f.Header().Length); err != nil {
						return err
					}
					return fr.WriteWindowUpdate(1, f.Header().Length)
				})
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				err = h.write(func(fr *http2.Framer) error { return fr.WritePing(true, f.Data) })
			}
		case *http2.RSTStreamFrame:
			return errors.New("MASQUE client reset CONNECT-IP stream")
		case *http2.GoAwayFrame:
			return errors.New("MASQUE client sent GOAWAY")
		}
		if err != nil {
			return err
		}
		select {
		case err := <-outErrors:
			return err
		default:
		}
	}
}

// Strictly validate private IPv4 traffic crossing the RFC 9484 capsule.
// Only the agreed /32 pair is forwarded, never a global route or an arbitrary
// client-chosen source/destination.
func validateInboundIPv4Packet(packet []byte, peer, own netip.Addr) (bool, error) {
	return validateOutboundIPv4Packet(packet, peer, own)
}
