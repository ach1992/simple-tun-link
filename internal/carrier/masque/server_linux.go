//go:build linux

package masque

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// ListenAgentConfig is the exact protected material for one STL-owned
// MASQUE listener. Client authorization is bound to a pinned SPKI and
// private Link pair, not a general CONNECT proxy or a shared wildcard CA.
type ListenAgentConfig struct {
	SchemaVersion  int           `json:"schema_version"`
	LinkID         domain.LinkID `json:"link_id"`
	Interface      string        `json:"interface"`
	PrivateIPv4    string        `json:"private_ipv4"`
	PeerIPv4       string        `json:"peer_ipv4"`
	MTU            int           `json:"mtu"`
	ListenAddress  string        `json:"listen_address"`
	TLSServerName  string        `json:"tls_server_name"`
	ServerCertFile string        `json:"server_cert_file"`
	ServerKeyFile  string        `json:"server_key_file"`
	PeerSPKIBase64 string        `json:"peer_spki_base64,omitempty"`
	PublicTLS      bool          `json:"public_tls,omitempty"`
	BearerFile     string        `json:"bearer_file,omitempty"`
}

func (c ListenAgentConfig) Validate() (netip.Addr, netip.Addr, error) {
	if c.SchemaVersion != 1 || c.LinkID.Validate() != nil {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid MASQUE listener schema or owner Link")
	}
	name, _ := AgentInterfaceName(c.LinkID)
	if c.Interface != name {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener interface does not match Link owner")
	}
	own, err := netip.ParseAddr(c.PrivateIPv4)
	if err != nil || !own.Is4() || own.IsUnspecified() {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener local private IPv4 invalid")
	}
	peer, err := netip.ParseAddr(c.PeerIPv4)
	if err != nil || !peer.Is4() || peer.IsUnspecified() || own == peer {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener peer private IPv4 invalid")
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener TUN MTU is invalid")
	}
	if c.ListenAddress == "" || c.TLSServerName == "" || c.ServerCertFile == "" || c.ServerKeyFile == "" {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener TLS identity incomplete")
	}
	if c.PublicTLS {
		if c.BearerFile == "" || c.PeerSPKIBase64 != "" {
			return netip.Addr{}, netip.Addr{}, errors.New("MASQUE public TLS listener requires a protected request bearer without mTLS identity")
		}
	} else {
		if c.BearerFile != "" || c.PeerSPKIBase64 == "" || len(c.PeerSPKIBase64) > 8192 {
			return netip.Addr{}, netip.Addr{}, errors.New("MASQUE private listener peer key missing or oversized")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(c.PeerSPKIBase64)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener peer public key encoding invalid")
		}
		if _, err = x509.ParsePKIXPublicKey(key); err != nil {
			return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener peer public key material invalid")
		}
	}

	_, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener must specify host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE listener port invalid")
	}

	return own, peer, nil
}

func ReadProtectedListenConfig(path string) (ListenAgentConfig, error) {
	raw, err := readPrivateFile(path, 32768)
	if err != nil {
		return ListenAgentConfig{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var cfg ListenAgentConfig
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid protected MASQUE listener configuration")
	}
	var remaining any
	if decoder.Decode(&remaining) != io.EOF {
		return cfg, errors.New("trailing MASQUE listener configuration data")
	}
	if _, _, err := cfg.Validate(); err != nil {
		return ListenAgentConfig{}, err
	}
	return cfg, nil
}

type kernelTun struct {
	fd  int
	mtu int
	mu  sync.Mutex
}

func (t *kernelTun) ReadPacket(ctx context.Context) ([]byte, error) {
	fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := unix.Poll(fds, 30)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("MASQUE TUN poll read failed: %w", err)
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, errors.New("MASQUE TUN read interface unavailable")
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		p := make([]byte, t.mtu+64)
		size, err := unix.Read(t.fd, p)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("MASQUE TUN read failed: %w", err)
		}
		return p[:size], nil
	}
}

func (t *kernelTun) WritePacket(ctx context.Context, packet []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLOUT}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Write(t.fd, packet)
		if err == unix.EAGAIN {
			if _, pollErr := unix.Poll(fds, 30); pollErr != nil && pollErr != unix.EINTR {
				return fmt.Errorf("MASQUE TUN poll write failed: %w", pollErr)
			}
			continue
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != len(packet) {
			return fmt.Errorf("MASQUE TUN packet write incomplete: bytes=%d: %w", n, err)
		}
		return nil
	}
}

// RunListenAgent has no shared daemon, second Engine, or foreign-resource
// adoption. The exact one-Link authenticated TUN is automatically removed
// when the helper exits and its kernel descriptor closes.
func RunListenAgent(ctx context.Context, cfg ListenAgentConfig) error {
	own, peer, err := cfg.Validate()
	if err != nil {
		return err
	}
	cert, err := readPrivateFile(cfg.ServerCertFile, 1<<20)
	if err != nil {
		return err
	}
	key, err := readPrivateFile(cfg.ServerKeyFile, 1<<20)
	if err != nil {
		return err
	}
	identity, err := tls.X509KeyPair(cert, key)
	clear(key)
	if err != nil {
		return errors.New("MASQUE listener protected TLS material invalid")
	}
	serverLeaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil || serverLeaf.VerifyHostname(cfg.TLSServerName) != nil {
		return errors.New("MASQUE listener certificate does not match configured TLS name")
	}
	pin, _ := base64.StdEncoding.DecodeString(cfg.PeerSPKIBase64)
	var bearer []byte
	if cfg.PublicTLS {
		bearer, err = readPrivateFile(cfg.BearerFile, 128)
		if err != nil {
			return err
		}
		defer clear(bearer)
		if !ValidBearerToken(bearer) {
			return errors.New("MASQUE protected listener request bearer invalid")
		}
	}
	tun, err := createPrivateTun(cfg.Interface, cfg.MTU, own, peer, cfg.LinkID)
	if err != nil {
		return err
	}
	defer tun.Close()
	server, err := NewH2Server(H2ListenConfig{
		ListenAddress: cfg.ListenAddress, TLSServerName: cfg.TLSServerName,
		ServerCert: identity, PeerSPKI: pin, PublicTLS: cfg.PublicTLS,
		BearerToken: bearer, LocalIPv4: own, PeerIPv4: peer,
	}, &kernelTun{fd: int(tun.Fd()), mtu: cfg.MTU})
	if err != nil {
		return err
	}
	return server.Serve(ctx)
}

var _ PrivatePacketIO = (*kernelTun)(nil)
