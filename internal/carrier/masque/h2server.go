package masque

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
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
	// Private default: exact mTLS peer SPKI. Public TLS: protected per-Link
	// bearer checked on the CONNECT-IP request, never on ordinary HTTP GET.
	PeerSPKI    []byte
	PublicTLS   bool
	BearerToken []byte
	LocalIPv4   netip.Addr
	PeerIPv4    netip.Addr
}

type H2Server struct {
	cfg           H2ListenConfig
	pipe          PrivatePacketIO
	activeMu      sync.Mutex
	active        bool
	peerIdleLimit time.Duration
}

// A 256-bit URL-safe secret is generated once for each public-TLS Link and
// stored only in the protected original material on both endpoints.
func ValidBearerToken(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(value))
	return err == nil && len(raw) == 32 &&
		base64.RawURLEncoding.EncodeToString(raw) == string(value)
}

func validateH2ListenConfig(c H2ListenConfig) error {
	if c.TLSServerName == "" || c.ListenAddress == "" ||
		!c.LocalIPv4.Is4() || !c.PeerIPv4.Is4() ||
		c.LocalIPv4.IsUnspecified() || c.PeerIPv4.IsUnspecified() ||
		c.LocalIPv4 == c.PeerIPv4 {
		return errors.New("MASQUE listener identity, pinned peer or private addresses invalid")
	}
	if c.PublicTLS {
		if len(c.PeerSPKI) != 0 || !ValidBearerToken(c.BearerToken) {
			return errors.New("MASQUE public TLS requires a protected 256-bit bearer and no mTLS peer identity")
		}
	} else {
		if len(c.BearerToken) != 0 || len(c.PeerSPKI) == 0 {
			return errors.New("MASQUE private TLS requires exact client certificate identity")
		}
		if _, err := x509.ParsePKIXPublicKey(c.PeerSPKI); err != nil {
			return errors.New("MASQUE listener expected peer public key is invalid")
		}
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
	return newH2ServerWithLiveness(cfg, pipe, masqueH2PeerIdleLimit)
}

func newH2ServerWithLiveness(cfg H2ListenConfig, pipe PrivatePacketIO, idleLimit time.Duration) (*H2Server, error) {
	if idleLimit <= 0 {
		return nil, errors.New("MASQUE H2 peer idle limit must be positive")
	}
	if err := validateH2ListenConfig(cfg); err != nil {
		return nil, err
	}
	if pipe == nil {
		return nil, errors.New("MASQUE server private packet interface unavailable")
	}
	return &H2Server{cfg: cfg, pipe: pipe, peerIdleLimit: idleLimit}, nil
}

func (s *H2Server) TLSConfig() *tls.Config {
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
		Certificates: []tls.Certificate{s.cfg.ServerCert},
	}
	if s.cfg.PublicTLS {
		// The server certificate is always verified by the dialer; client
		// admission moves from TLS to the authenticated CONNECT-IP request.
		return config
	}
	expected := append([]byte(nil), s.cfg.PeerSPKI...)
	config.ClientAuth = tls.RequireAnyClientCert
	config.VerifyPeerCertificate = func(chain [][]byte, _ [][]*x509.Certificate) error {
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
	}
	return config
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
			if err := s.serveH2(ctx, tlsConn); err != nil && ctx.Err() == nil &&
				!errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				// Keep the failure stage in the private service journal without
				// exposing the peer credential or capsule payload.
				log.Printf("MASQUE H2 session ended: %v", err)
			}
		}(conn)
	}
}

// The limit is per public HTTP/2 TLS connection (not a product Link-count
// or bandwidth quota). It is advertised to clients as the H2 concurrency
// setting and enforced for zero-credit pending GET bodies so anonymous peers
// cannot retain unbounded response state on a tunnel listener.
const publicH2ConcurrentStreams = 64

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
	// Ordinary public responses share connection DATA credit but use their
	// own stream windows. Only the H2 reader changes this map; zero-credit
	// replies remain pending while that reader processes WINDOW_UPDATE.
	publicMode    bool
	lastPublicID  uint32
	publicReplies map[uint32]*h2PublicReply
	// Only response streams that have positive stream credit are queued.
	// A zero-credit GET does not trigger a scan of earlier pending GETs.
	publicReady list.List
}

type h2PublicReply struct {
	body   []byte
	window int64
	ready  *list.Element
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
			delta := int64(s.Val) - h.peerInitialWindow
			if h.streamWindow+delta > (1<<31)-1 {
				return errors.New("MASQUE peer stream window overflow")
			}
			for _, reply := range h.publicReplies {
				if reply.window+delta > (1<<31)-1 {
					return errors.New("MASQUE public stream window overflow")
				}
			}
			h.streamWindow += delta
			for id, reply := range h.publicReplies {
				reply.window += delta
				h.schedulePublicReply(id, reply)
			}
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
		if h.connWindow > (1<<31)-1 {
			return errors.New("MASQUE peer HTTP/2 connection window overflow")
		}
	} else if h.publicMode {
		// WINDOW_UPDATE on a closed HTTP/2 response stream is permitted.
		// It must not add credit to unrelated streams or CONNECT-IP.
		if reply := h.publicReplies[f.StreamID]; reply != nil {
			if reply.window+int64(f.Increment) > (1<<31)-1 {
				return errors.New("MASQUE public HTTP/2 stream window overflow")
			}
			reply.window += int64(f.Increment)
			h.schedulePublicReply(f.StreamID, reply)
		}
	} else if f.StreamID == 1 {
		h.streamWindow += int64(f.Increment)
		if h.streamWindow > (1<<31)-1 {
			return errors.New("MASQUE peer HTTP/2 stream window overflow")
		}
	}
	h.signalFlow()
	return nil
}

func (h *h2ServerConn) reply(code string) error {
	return h.replyOnStream(1, code)
}

// Private CONNECT-IP always uses stream 1; ordinary public HTTP rejection
// uses the actual newly opened request stream, never an earlier closed one.
func (h *h2ServerConn) replyOnStream(streamID uint32, code string) error {
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
	return h.write(func(fr *http2.Framer) error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: streamID, BlockFragment: hdr.Bytes(), EndHeaders: true, EndStream: code != "200",
		})
	})
}

// HTTP/2 GET and HEAD are normal HTTP resources on the same public-TLS
// listener. They grant no tunnel or packet access and never disclose secrets.
// The single-connection framer completes the requested stream while
// keeping the HTTP/2 connection available for another ordinary GET/HEAD.
func (h *h2ServerConn) replyPublicHTTP(streamID uint32, method string, found bool) error {
	// Respect the advertised concurrent-stream capacity even when a peer
	// ignores SETTINGS_MAX_CONCURRENT_STREAMS. Refuse only the excess
	// request, without retaining a body or closing other valid streams.
	if method != "HEAD" && len(h.publicReplies) >= publicH2ConcurrentStreams {
		return h.write(func(fr *http2.Framer) error {
			return fr.WriteRSTStream(streamID, http2.ErrCodeRefusedStream)
		})
	}
	body := []byte("STL MASQUE HTTP/2 endpoint\n")
	code := "200"
	if !found {
		code = "404"
		body = []byte("Not Found\n")
	}
	var hdr bytes.Buffer
	e := hpack.NewEncoder(&hdr)
	for _, field := range []hpack.HeaderField{
		{Name: ":status", Value: code},
		{Name: "content-type", Value: "text/plain; charset=utf-8"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
		{Name: "cache-control", Value: "no-store"},
	} {
		if err := e.WriteField(field); err != nil {
			return err
		}
	}
	if err := h.write(func(fr *http2.Framer) error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: streamID, BlockFragment: hdr.Bytes(), EndHeaders: true,
			EndStream: method == "HEAD",
		})
	}); err != nil {
		return err
	}
	if method == "HEAD" {
		return nil
	}
	// A HEADERS frame consumes no DATA credit. The response body is small,
	// but even one byte must obey both the per-stream and connection windows.
	if h.publicReplies == nil {
		h.publicReplies = make(map[uint32]*h2PublicReply)
	}
	reply := &h2PublicReply{body: body, window: h.peerInitialWindow}
	h.publicReplies[streamID] = reply
	h.schedulePublicReply(streamID, reply)
	return h.flushPublicData()
}

// Both the map and the list belong to the single H2 reader goroutine;
// no background public-response worker or second scheduling framework is
// needed. Only streams with stream-window credit are put on the ready list.
func (h *h2ServerConn) schedulePublicReply(streamID uint32, reply *h2PublicReply) {
	if reply.window > 0 && len(reply.body) != 0 {
		if reply.ready == nil {
			reply.ready = h.publicReady.PushBack(streamID)
		}
	} else if reply.ready != nil {
		h.publicReady.Remove(reply.ready)
		reply.ready = nil
	}
}

func (h *h2ServerConn) dropPublicReply(streamID uint32) {
	if reply := h.publicReplies[streamID]; reply != nil {
		if reply.ready != nil {
			h.publicReady.Remove(reply.ready)
			reply.ready = nil
		}
		delete(h.publicReplies, streamID)
	}
}

// Work-proportional scheduling: new zero-credit GETs never scan older
// blocked requests. Connection WINDOW_UPDATE drains only the ready list;
// stream WINDOW_UPDATE queues exactly the now-creditable stream. SETTINGS
// necessarily touches active streams once to apply the window delta.
func (h *h2ServerConn) flushPublicData() error {
	for front := h.publicReady.Front(); front != nil; front = h.publicReady.Front() {
		h.flowMu.Lock()
		if h.connWindow <= 0 {
			h.flowMu.Unlock()
			return nil
		}
		streamID := front.Value.(uint32)
		reply := h.publicReplies[streamID]
		if reply == nil || reply.window <= 0 {
			h.flowMu.Unlock()
			h.publicReady.Remove(front)
			if reply != nil {
				reply.ready = nil
			}
			continue
		}
		n := min(int64(len(reply.body)), h.peerFrameSize, h.connWindow, reply.window)
		if n <= 0 {
			h.flowMu.Unlock()
			return nil
		}
		h.connWindow -= n
		reply.window -= n
		h.flowMu.Unlock()

		end := int(n) == len(reply.body)
		if err := h.write(func(fr *http2.Framer) error {
			return fr.WriteData(streamID, end, reply.body[:n])
		}); err != nil {
			return err
		}
		if end {
			h.dropPublicReply(streamID)
		} else {
			reply.body = reply.body[n:]
			if reply.window <= 0 {
				h.publicReady.Remove(front)
				reply.ready = nil
			} else {
				// Larger bodies can share available connection credit fairly.
				h.publicReady.MoveToBack(front)
			}
		}
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
	capsuleOK, capsuleCount, authOK, authCount := false, 0, false, 0
	for _, hdr := range f.RegularFields() {
		switch hdr.Name {
		case "capsule-protocol":
			capsuleCount++
			capsuleOK = capsuleProtocolTrue(hdr.Value)
		case "content-length", "content-type", "transfer-encoding":
			// RFC 9297 §3.2 forbids HTTP content fields on any Capsule
			// Protocol request, even when their values appear harmless.
			return false
		case "authorization":
			authCount++
			authOK = subtle.ConstantTimeCompare(
				[]byte(hdr.Value), append([]byte("Bearer "), s.cfg.BearerToken...)) == 1
		}
	}
	return capsuleCount == 1 && capsuleOK &&
		(!s.cfg.PublicTLS || (authCount == 1 && authOK))
}

// Only unauthenticated HTTP status resources, never a CONNECT-IP stream.
func (s *H2Server) isPublicHTTP(f *http2.MetaHeadersFrame) bool {
	if !s.cfg.PublicTLS || f.StreamID == 0 || f.StreamID%2 == 0 ||
		f.Truncated || !f.StreamEnded() ||
		f.PseudoValue("scheme") != "https" || f.PseudoValue("protocol") != "" {
		return false
	}
	method := f.PseudoValue("method")
	if method != "GET" && method != "HEAD" {
		return false
	}
	return publicHTTPAuthorityMatches(s.cfg.TLSServerName, s.cfg.ListenAddress,
		f.PseudoValue("authority"))
}

// Browsers normally omit :443 from the HTTPS authority. An ordinary H2
// GET/HEAD must work with that standard origin-form authority, while
// refusing arbitrary Host values or an unapproved external destination.
func publicHTTPAuthorityMatches(name, listenAddress, authority string) bool {
	_, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return false
	}
	full := net.JoinHostPort(name, port)
	if strings.EqualFold(authority, full) {
		return true
	}
	return port == "443" && strings.EqualFold(authority, strings.TrimSuffix(full, ":443"))
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
	settings := []http2.Setting{
		{ID: http2.SettingEnableConnectProtocol, Val: 1},
		{ID: http2.SettingInitialWindowSize, Val: 8 * 1024 * 1024},
		{ID: http2.SettingMaxFrameSize, Val: 65535},
	}
	if s.cfg.PublicTLS {
		settings = append(settings, http2.Setting{
			ID: http2.SettingMaxConcurrentStreams, Val: publicH2ConcurrentStreams,
		})
	}
	if err := h.write(func(fr *http2.Framer) error {
		return fr.WriteSettings(settings...)
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
		if err == nil {
			idleLimit := 12 * time.Second
			if accepted {
				idleLimit = s.peerIdleLimit
			}
			err = conn.SetReadDeadline(time.Now().Add(idleLimit))
		}
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
			if err == nil && h.publicMode {
				err = h.flushPublicData()
			}
		case *http2.WindowUpdateFrame:
			err = h.updateWindow(f)
			if err == nil && h.publicMode {
				err = h.flushPublicData()
			}
		case *http2.MetaHeadersFrame:
			if !accepted && s.isPublicHTTP(f) && f.StreamID > h.lastPublicID {
				h.publicMode = true
				h.lastPublicID = f.StreamID
				if err := h.replyPublicHTTP(f.StreamID, f.PseudoValue("method"), f.PseudoValue("path") == "/"); err != nil {
					return err
				}
				continue
			}
			if accepted || h.publicMode || !s.authorizeRequest(f) {
				// The client cannot reuse a completed H2 stream or open an
				// even-numbered stream. Never write HEADERS on a closed ID.
				if f.StreamID == 0 || f.StreamID%2 == 0 ||
					(h.publicMode && f.StreamID <= h.lastPublicID) {
					_ = h.write(func(fr *http2.Framer) error {
						return fr.WriteGoAway(h.lastPublicID, http2.ErrCodeProtocol, nil)
					})
					return errors.New("MASQUE invalid or reused HTTP/2 stream ID")
				}
				code := "400"
				if !accepted && s.cfg.PublicTLS && f.PseudoValue("method") == "CONNECT" {
					code = "403"
				}
				if h.publicMode && !accepted {
					// A new unsupported request has its own legal stream;
					// return a response there, then keep public HTTP reusable.
					h.lastPublicID = f.StreamID
					if err := h.replyOnStream(f.StreamID, code); err != nil {
						return err
					}
					continue
				}
				_ = h.replyOnStream(f.StreamID, code)
				return errors.New("MASQUE rejected unauthorized or unexpected HTTP/2 request")
			}
			s.activeMu.Lock()
			if s.active {
				s.activeMu.Unlock()
				_ = h.reply("409")
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
			if err := h.reply("200"); err != nil {
				return err
			}
			// Keep a bounded authenticated stream lifetime if TCP silently
			// blackholes. The dialer sends H2 PINGs even with no IP data.
			if err := conn.SetReadDeadline(time.Now().Add(s.peerIdleLimit)); err != nil {
				return fmt.Errorf("MASQUE listener idle deadline unavailable: %w", err)
			}
			accepted = true
			// Assignment MUST precede private packet DATA, but it may require
			// a client WINDOW_UPDATE (including an initially zero stream window).
			// The H2 reader therefore stays active while the single ordered
			// outbound worker sends the assignment. Never wait for flow-control
			// updates on the same goroutine that must read those updates.
			go func() {
				assignCtx, stopAssign := context.WithTimeout(ctx, 12*time.Second)
				err := h.sendData(assignCtx, capsule)
				stopAssign()
				if err != nil {
					select {
					case outErrors <- fmt.Errorf("MASQUE private address assignment failed: %w", err):
					default:
					}
					cancel()
					return
				}
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
					allow, err := validateLocalTunIPv4Packet(packet, s.cfg.LocalIPv4, s.cfg.PeerIPv4)
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
			if !accepted && h.publicMode && f.StreamID%2 == 1 &&
				f.StreamID <= h.lastPublicID {
				// An ordinary GET can be canceled without closing the peer's
				// otherwise reusable HTTP/2 connection or altering TUN state.
				h.dropPublicReply(f.StreamID)
				continue
			}
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
