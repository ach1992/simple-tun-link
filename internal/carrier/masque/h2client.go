package masque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// H2Config describes an authenticated RFC 9484 HTTP/2 CONNECT-IP dialer.
// Secrets belong to an exact protected Link credential store, not to public
// desired-state, argv, status JSON or diagnostic logs.
type H2Config struct {
	Address        string
	ServerName     string
	Roots          *x509.CertPool
	ClientCert     *tls.Certificate
	Username       string
	Password       string
	Path           string
	ExpectedIPv4   netip.Addr
	ConnectTimeout time.Duration
}

// H2Client owns one authenticated HTTP/2 stream. Read and write are
// independently driven, with explicit stream/connection flow control and
// bounded capsule decoding, not an unbounded per-packet goroutine.
type H2Client struct {
	connection net.Conn
	framer     *http2.Framer
	writer     *bufio.Writer

	writeMu sync.Mutex
	sendMu  sync.Mutex
	mu      sync.Mutex
	done    chan struct{}
	ready   chan struct{}
	packets chan []byte
	err     error

	peerExtended      bool
	peerFrameSize     int
	peerInitialWindow int64
	sendConnWin       int64
	sendStreamWin     int64
	flowUpdated       chan struct{}
	responseOK        bool
	assignedIPv4      netip.Addr
	expectedIPv4      netip.Addr
}

func validateH2Config(cfg H2Config) error {
	if cfg.Address == "" || cfg.ServerName == "" || cfg.Roots == nil ||
		!cfg.ExpectedIPv4.Is4() || cfg.ExpectedIPv4.IsUnspecified() {
		return errors.New("MASQUE requires a pinned TLS endpoint, trusted CA and expected private IPv4")
	}
	if host, port, err := net.SplitHostPort(cfg.Address); err != nil || host == "" || port == "" {
		return errors.New("MASQUE endpoint must be an explicit host:port")
	} else if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("MASQUE endpoint port is invalid")
	}
	if cfg.ClientCert == nil && (cfg.Username == "" || cfg.Password == "") {
		return errors.New("MASQUE requires client certificate or Basic authentication")
	}
	if cfg.Path != "" && (!strings.HasPrefix(cfg.Path, "/") || strings.ContainsAny(cfg.Path, "\r\n#")) {
		return errors.New("MASQUE CONNECT-IP path is invalid")
	}
	return nil
}

// DialH2 strictly verifies TLS, requires RFC 8441 extended CONNECT support,
// authenticates the request and refuses an unexpected address assignment.
// It does not create an interface or change host-wide routing.
func DialH2(ctx context.Context, cfg H2Config) (*H2Client, error) {
	if err := validateH2Config(cfg); err != nil {
		return nil, err
	}
	timeout := cfg.ConnectTimeout
	if timeout == 0 {
		timeout = 12 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var certificates []tls.Certificate
	if cfg.ClientCert != nil {
		certificates = append(certificates, *cfg.ClientCert)
	}
	raw, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(dialCtx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("MASQUE transport dial failed: %w", err)
	}
	connection := tls.Client(raw, &tls.Config{
		ServerName: cfg.ServerName, RootCAs: cfg.Roots,
		Certificates: certificates, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	if err := connection.HandshakeContext(dialCtx); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("MASQUE TLS handshake/verification failed: %w", err)
	}
	if connection.ConnectionState().NegotiatedProtocol != "h2" {
		_ = connection.Close()
		return nil, errors.New("MASQUE server did not negotiate HTTP/2")
	}
	writer := bufio.NewWriterSize(connection, 128*1024)
	framer := http2.NewFramer(writer, connection)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	framer.MaxHeaderListSize = 16384
	framer.SetMaxReadFrameSize(65535)
	c := &H2Client{
		connection: connection, writer: writer, framer: framer,
		done: make(chan struct{}), ready: make(chan struct{}),
		packets:       make(chan []byte, 128),
		peerFrameSize: 16384,
		sendConnWin:   65535, sendStreamWin: 65535, peerInitialWindow: 65535,
		flowUpdated:  make(chan struct{}),
		expectedIPv4: cfg.ExpectedIPv4,
	}
	c.writeMu.Lock()
	_, err = writer.WriteString(http2.ClientPreface)
	if err == nil {
		err = framer.WriteSettings(
			http2.Setting{ID: http2.SettingEnablePush, Val: 0},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: 8 * 1024 * 1024},
			http2.Setting{ID: http2.SettingMaxFrameSize, Val: 65535},
		)
	}
	if err == nil {
		err = framer.WriteWindowUpdate(0, 8*1024*1024)
	}
	if err == nil {
		err = writer.Flush()
	}
	c.writeMu.Unlock()
	if err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("MASQUE HTTP/2 preface failed: %w", err)
	}
	go c.readLoop()
	// RFC 8441 requires the server to advertise ENABLE_CONNECT_PROTOCOL.
	for {
		c.mu.Lock()
		enabled := c.peerExtended
		ch := c.flowUpdated
		c.mu.Unlock()
		if enabled {
			break
		}
		select {
		case <-dialCtx.Done():
			c.Close()
			return nil, fmt.Errorf("MASQUE extended CONNECT settings deadline: %w", dialCtx.Err())
		case <-c.done:
			return nil, c.failure()
		case <-ch:
		}
	}
	_, port, _ := net.SplitHostPort(cfg.Address)
	path := cfg.Path
	if path == "" {
		path = "/.well-known/masque/ip/"
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: net.JoinHostPort(cfg.ServerName, port)},
		{Name: ":path", Value: path},
		{Name: ":protocol", Value: "connect-ip"},
		{Name: "capsule-protocol", Value: "?1"},
	}
	if cfg.Username != "" {
		headers = append(headers, hpack.HeaderField{Name: "proxy-authorization",
			Value:     "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+cfg.Password)),
			Sensitive: true})
	}
	for _, header := range headers {
		if err := encoder.WriteField(header); err != nil {
			c.Close()
			return nil, fmt.Errorf("MASQUE HTTP/2 request header encoding failed")
		}
	}
	c.writeMu.Lock()
	err = c.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true,
	})
	if err == nil {
		err = c.writer.Flush()
	}
	c.writeMu.Unlock()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("MASQUE HTTP/2 CONNECT-IP request failed: %w", err)
	}
	select {
	case <-c.ready:
		return c, nil
	case <-c.done:
		return nil, c.failure()
	case <-dialCtx.Done():
		c.Close()
		return nil, fmt.Errorf("MASQUE CONNECT-IP address assignment timed out: %w", dialCtx.Err())
	}
}

func (c *H2Client) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return errors.New("MASQUE connection closed")
}

func (c *H2Client) signalFlowLocked() {
	close(c.flowUpdated)
	c.flowUpdated = make(chan struct{})
}

func (c *H2Client) fail(err error) {
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return
	default:
	}
	if err == nil {
		err = errors.New("MASQUE connection closed")
	}
	c.err = err
	close(c.done)
	c.signalFlowLocked()
	c.mu.Unlock()
	_ = c.connection.Close()
}

func (c *H2Client) Close() error {
	c.fail(errors.New("MASQUE client stopped"))
	return nil
}

func (c *H2Client) Packets() <-chan []byte { return c.packets }

func (c *H2Client) Done() <-chan struct{} { return c.done }

func (c *H2Client) Err() error { return c.failure() }

func (c *H2Client) sendControl(write func(*http2.Framer) error) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := write(c.framer); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *H2Client) readLoop() {
	defer close(c.packets)
	var parser capsuleStream
	for {
		frame, err := c.framer.ReadFrame()
		if err != nil {
			c.fail(fmt.Errorf("MASQUE HTTP/2 receive failed: %w", err))
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			err = f.ForeachSetting(func(s http2.Setting) error {
				c.mu.Lock()
				defer c.mu.Unlock()
				switch s.ID {
				case http2.SettingEnableConnectProtocol:
					if s.Val == 1 {
						c.peerExtended = true
					}
				case http2.SettingInitialWindowSize:
					delta := int64(s.Val) - c.peerInitialWindow
					c.peerInitialWindow = int64(s.Val)
					c.sendStreamWin += delta
				case http2.SettingMaxFrameSize:
					if s.Val < 16384 || s.Val > 16777215 {
						return errors.New("MASQUE server advertised invalid HTTP/2 frame size")
					}
					c.peerFrameSize = int(s.Val)
				}
				c.signalFlowLocked()
				return nil
			})
			if err == nil {
				err = c.sendControl(func(fr *http2.Framer) error { return fr.WriteSettingsAck() })
			}
		case *http2.WindowUpdateFrame:
			if f.Increment == 0 {
				err = errors.New("MASQUE invalid zero HTTP/2 window increment")
				break
			}
			c.mu.Lock()
			if f.StreamID == 0 {
				c.sendConnWin += int64(f.Increment)
			} else if f.StreamID == 1 {
				c.sendStreamWin += int64(f.Increment)
			}
			if c.sendConnWin > 1<<31-1 || c.sendStreamWin > 1<<31-1 {
				err = errors.New("MASQUE HTTP/2 flow-control overflow")
			}
			c.signalFlowLocked()
			c.mu.Unlock()
		case *http2.MetaHeadersFrame:
			if f.StreamID != 1 || f.Truncated || f.StreamEnded() || c.responseOK {
				err = errors.New("MASQUE HTTP/2 CONNECT-IP response malformed")
				break
			}
			status := f.PseudoValue("status")
			code, parseErr := strconv.Atoi(status)
			if parseErr != nil || code < 200 || code >= 300 {
				err = fmt.Errorf("MASQUE CONNECT-IP rejected (HTTP status %s)", status)
				break
			}
			capsule := false
			for _, field := range f.RegularFields() {
				if field.Name == "capsule-protocol" && field.Value == "?1" {
					capsule = true
				}
			}
			if !capsule {
				err = errors.New("MASQUE server did not enable Capsule Protocol")
				break
			}
			c.mu.Lock()
			c.responseOK = true
			c.mu.Unlock()
		case *http2.DataFrame:
			if f.StreamID != 1 || f.StreamEnded() || !c.responseOK {
				err = errors.New("MASQUE CONNECT-IP stream ended unexpectedly")
				break
			}
			err = parser.feed(f.Data(), func(ip netip.Prefix) error {
				if !ip.Addr().Is4() {
					return nil
				}
				if ip.Addr() != c.expectedIPv4 || ip.Bits() != 32 {
					return errors.New("MASQUE assigned an unexpected private IPv4 identity")
				}
				c.mu.Lock()
				if c.assignedIPv4.IsValid() && c.assignedIPv4 != ip.Addr() {
					err = errors.New("MASQUE assigned multiple IPv4 identities")
				} else {
					c.assignedIPv4 = ip.Addr()
					if c.responseOK {
						select {
						case <-c.ready:
						default:
							close(c.ready)
						}
					}
				}
				c.mu.Unlock()
				return err
			}, func(packet []byte) error {
				if len(packet) < 20 || packet[0]>>4 != 4 ||
					int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
					!bytes.Equal(packet[16:20], c.expectedIPv4.AsSlice()) {
					return errors.New("MASQUE received an invalid or misaddressed private IP packet")
				}
				copyPacket := append([]byte(nil), packet...)
				select {
				case c.packets <- copyPacket:
					return nil
				case <-c.done:
					return errors.New("MASQUE closing")
				}
			})
			if err == nil && f.Header().Length > 0 {
				err = c.sendControl(func(fr *http2.Framer) error {
					if err := fr.WriteWindowUpdate(0, f.Header().Length); err != nil {
						return err
					}
					return fr.WriteWindowUpdate(1, f.Header().Length)
				})
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				err = c.sendControl(func(fr *http2.Framer) error { return fr.WritePing(true, f.Data) })
			}
		case *http2.RSTStreamFrame:
			err = errors.New("MASQUE CONNECT-IP stream reset")
		case *http2.GoAwayFrame:
			err = errors.New("MASQUE HTTP/2 peer sent GOAWAY")
		}
		if err != nil {
			c.fail(err)
			return
		}
	}
}

// SendPackets batches several ordinary IPv4 packets into the same HTTP/2
// stream while respecting negotiated TCP/H2 flow windows. The caller retains
// backpressure authority and must not hold any Engine/host-global lock here.
func (c *H2Client) SendPackets(ctx context.Context, packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	var bytesToSend []byte
	for _, p := range packets {
		var err error
		encoded, err := datagramCapsule(p)
		if err != nil {
			return err
		}
		bytesToSend = append(bytesToSend, encoded...)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	for len(bytesToSend) != 0 {
		select {
		case <-c.done:
			return c.failure()
		default:
		}
		c.mu.Lock()
		frameSize := int64(c.peerFrameSize)
		n := min(int64(len(bytesToSend)), frameSize, c.sendConnWin, c.sendStreamWin)
		if n > 0 {
			c.sendConnWin -= n
			c.sendStreamWin -= n
			c.mu.Unlock()
			c.writeMu.Lock()
			err := c.framer.WriteData(1, false, bytesToSend[:n])
			if err == nil {
				err = c.writer.Flush()
			}
			c.writeMu.Unlock()
			if err != nil {
				c.fail(err)
				return fmt.Errorf("MASQUE HTTP/2 datagram send failed: %w", err)
			}
			bytesToSend = bytesToSend[n:]
			continue
		}
		next := c.flowUpdated
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return c.failure()
		case <-next:
		}
	}
	return nil
}

// ReadPacket waits for a single decoded IP packet, with cooperative shutdown.
func (c *H2Client) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p, ok := <-c.packets:
		if !ok {
			return nil, c.failure()
		}
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		select {
		case p := <-c.packets:
			if len(p) > 0 {
				return p, nil
			}
		default:
		}
		return nil, c.failure()
	}
}

var _ io.Closer = (*H2Client)(nil)
