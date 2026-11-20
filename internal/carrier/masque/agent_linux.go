//go:build linux

package masque

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"golang.org/x/sys/unix"
)

// DialAgentConfig is a protected per-Link helper configuration, not public
// desired state. It must only be installed through the canonical Engine's
// owned provisioning transaction, or by a deliberately isolated test.
type DialAgentConfig struct {
	SchemaVersion  int           `json:"schema_version"`
	LinkID         domain.LinkID `json:"link_id"`
	Interface      string        `json:"interface"`
	PrivateIPv4    string        `json:"private_ipv4"`
	PeerIPv4       string        `json:"peer_ipv4"`
	MTU            int           `json:"mtu"`
	Address        string        `json:"server_address"`
	ServerName     string        `json:"tls_server_name"`
	RequestPath    string        `json:"request_path,omitempty"`
	CACertFile     string        `json:"ca_file"`
	ClientCertFile string        `json:"client_cert_file,omitempty"`
	ClientKeyFile  string        `json:"client_key_file,omitempty"`
	PublicTLS      bool          `json:"public_tls,omitempty"`
	BearerFile     string        `json:"bearer_file,omitempty"`
	User           string        `json:"username,omitempty"`
	PasswordFile   string        `json:"password_file,omitempty"`
}

func AgentInterfaceName(id domain.LinkID) (string, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	return "stlm" + string(id)[4:15], nil
}

func (cfg DialAgentConfig) Validate() (netip.Addr, netip.Addr, error) {
	if cfg.SchemaVersion != 1 || cfg.LinkID.Validate() != nil {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid MASQUE helper schema or Link identity")
	}
	name, _ := AgentInterfaceName(cfg.LinkID)
	if cfg.Interface != name {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE TUN name does not match Link ID")
	}
	own, err := netip.ParseAddr(cfg.PrivateIPv4)
	if err != nil || !own.Is4() || own.IsUnspecified() {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid MASQUE client private IPv4")
	}
	peer, err := netip.ParseAddr(cfg.PeerIPv4)
	if err != nil || !peer.Is4() || peer.IsUnspecified() || own == peer {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid MASQUE peer private IPv4")
	}
	if cfg.MTU < 576 || cfg.MTU > 9000 {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE TUN MTU is outside kernel IPv4 range")
	}
	if cfg.CACertFile == "" || cfg.Address == "" || cfg.ServerName == "" {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE helper TLS identity is incomplete")
	}
	if (cfg.ClientCertFile == "") != (cfg.ClientKeyFile == "") {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE client certificate and key must be specified together")
	}
	if cfg.PublicTLS {
		if cfg.BearerFile == "" || cfg.ClientCertFile != "" || cfg.ClientKeyFile != "" ||
			cfg.User != "" || cfg.PasswordFile != "" {
			return netip.Addr{}, netip.Addr{}, errors.New("MASQUE public TLS requires a protected request bearer only")
		}
	} else if cfg.BearerFile != "" || (cfg.PasswordFile == "" && cfg.ClientCertFile == "") {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE private TLS requires a client certificate or existing Basic credentials")
	}
	if (cfg.User == "") != (cfg.PasswordFile == "") {
		return netip.Addr{}, netip.Addr{}, errors.New("MASQUE Basic credential requires username and password file")
	}
	return own, peer, nil
}

// ReadProtectedAgentConfig never follows the final symlink and requires an
// owner-only regular file. Exact authorization of its parent directory and
// credential generation remains the provisioning backend's responsibility.
func ReadProtectedAgentConfig(path string) (DialAgentConfig, error) {
	raw, err := readPrivateFile(path, 32768)
	if err != nil {
		return DialAgentConfig{}, err
	}
	var cfg DialAgentConfig
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return DialAgentConfig{}, errors.New("invalid protected MASQUE helper configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return DialAgentConfig{}, errors.New("trailing MASQUE helper configuration data")
	}
	if _, _, err := cfg.Validate(); err != nil {
		return DialAgentConfig{}, err
	}
	return cfg, nil
}

func readPrivateFile(path string, maxBytes int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("MASQUE credential file path must be absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open protected MASQUE file: %w", err)
	}
	file := os.NewFile(uintptr(fd), "masque-protected-file")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > maxBytes {
		return nil, errors.New("MASQUE credential file is not a protected regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(raw)) > maxBytes {
		return nil, errors.New("could not read bounded MASQUE protected file")
	}
	return raw, nil
}

func createPrivateTun(name string, mtu int, own, peer netip.Addr, owner domain.LinkID) (*os.File, error) {
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, errors.New("MASQUE owned interface already exists")
	} else if !errors.Is(err, net.ErrClosed) {
		// InterfaceByName reports an OS-specific missing-interface error.
		if _, ok := err.(*net.OpError); !ok && !strings.Contains(err.Error(), "no such network interface") {
			return nil, fmt.Errorf("cannot inspect MASQUE interface collision: %w", err)
		}
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("MASQUE TUN access unavailable: %w", err)
	}
	file := os.NewFile(uintptr(fd), "masque-"+name)
	ifreq, err := unix.NewIfreq(name)
	if err == nil {
		ifreq.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL))
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifreq)
	}
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("MASQUE exclusive TUN creation failed: %w", err)
	}
	runIP := func(args ...string) error {
		c, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		output, err := exec.CommandContext(c, "ip", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("MASQUE owned TUN setup (%s) failed: %w: %s", args[0], err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	for _, args := range [][]string{
		{"link", "set", "dev", name, "mtu", fmt.Sprint(mtu)},
		{"link", "set", "dev", name, "alias", "stl:masque:" + string(owner)},
		{"addr", "add", own.String() + "/32", "dev", name},
		{"link", "set", "dev", name, "up"},
		{"route", "add", peer.String() + "/32", "dev", name, "scope", "link", "src", own.String()},
	} {
		if err := runIP(args...); err != nil {
			file.Close() // non-persistent TUN teardown reverts owned route
			return nil, err
		}
	}
	return file, nil
}

// RunDialAgent is the per-Link helper datapath. It is not an alternate Link
// Engine: the only persistent owner is the STL Engine which provisions and
// supervises the exact per-Link service/config. No default route, nft rule,
// forwarding policy or unrelated interface is changed.
func RunDialAgent(ctx context.Context, cfg DialAgentConfig) error {
	own, peer, err := cfg.Validate()
	if err != nil {
		return err
	}
	pemCA, err := readPrivateFile(cfg.CACertFile, 1<<20)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemCA) {
		return errors.New("MASQUE server trust certificate is invalid")
	}
	var clientCert *tls.Certificate
	if cfg.ClientCertFile != "" {
		certPEM, err := readPrivateFile(cfg.ClientCertFile, 1<<20)
		if err != nil {
			return err
		}
		keyPEM, err := readPrivateFile(cfg.ClientKeyFile, 1<<20)
		if err != nil {
			return err
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		clear(keyPEM)
		if err != nil {
			return errors.New("invalid protected MASQUE client TLS identity")
		}
		clientCert = &pair
	}
	var bearer string
	if cfg.PublicTLS {
		raw, readErr := readPrivateFile(cfg.BearerFile, 128)
		if readErr != nil {
			return readErr
		}
		if !ValidBearerToken(raw) {
			clear(raw)
			return errors.New("MASQUE protected request bearer invalid")
		}
		bearer = string(raw)
		clear(raw)
	}
	var secret string
	if cfg.PasswordFile != "" {
		raw, err := readPrivateFile(cfg.PasswordFile, 16384)
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(raw))
		clear(raw)
	}
	// A committed STL Link must exist locally even if its remote listener is
	// down or the underlay is temporarily unavailable. Create exactly one
	// exclusive TUN first, then reconnect the authenticated capsule stream
	// without destroying the local route or misreporting peer connectivity.
	file, err := createPrivateTun(cfg.Interface, cfg.MTU, own, peer, cfg.LinkID)
	if err != nil {
		return err
	}
	defer file.Close()
	backoff := time.Second
	for ctx.Err() == nil {
		client, connectErr := DialH2(ctx, H2Config{
			Address: cfg.Address, ServerName: cfg.ServerName, Roots: roots,
			ClientCert: clientCert, Username: cfg.User, Password: secret,
			BearerToken: bearer, ExpectedIPv4: own, Path: cfg.RequestPath,
		})
		if connectErr == nil {
			backoff = time.Second
			log.Printf("MASQUE Link %s authenticated CONNECT-IP stream established", cfg.LinkID)
			connectErr = runDialSession(ctx, int(file.Fd()), cfg.MTU, own, peer, client)
			_ = client.Close()
		}
		if ctx.Err() != nil {
			break
		}
		// Failed or expired sessions remain distinguished from a locally
		// owned running TUN. systemd supervises local process health; this
		// backoff handles peer loss without a new Link identity or route.
		log.Printf("MASQUE Link %s disconnected: %v; reconnecting", cfg.LinkID, connectErr)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
	return nil
}

func runDialSession(ctx context.Context, fd, mtu int, own, peer netip.Addr, client *H2Client) error {
	session, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		failures <- forwardTunToH2(session, fd, mtu, own, peer, client)
	}()
	go func() {
		defer workers.Done()
		for {
			pkt, err := client.ReadPacket(session)
			if err != nil {
				failures <- err
				return
			}
			if len(pkt) < 20 || pkt[0]>>4 != 4 {
				failures <- errors.New("MASQUE private response IP version mismatch")
				return
			}
			var src [4]byte
			copy(src[:], pkt[12:16])
			if netip.AddrFrom4(src) != peer {
				failures <- errors.New("MASQUE private peer source mismatch")
				return
			}
			for len(pkt) != 0 {
				n, err := unix.Write(fd, pkt)
				if err == unix.EINTR {
					continue
				}
				if err == unix.EAGAIN {
					select {
					case <-session.Done():
						failures <- session.Err()
						return
					case <-time.After(time.Millisecond):
					}
					continue
				}
				if err != nil || n == 0 {
					failures <- fmt.Errorf("MASQUE private TUN write failed: %w", err)
					return
				}
				pkt = pkt[n:]
			}
		}
	}()
	var result error
	select {
	case result = <-failures:
	case <-client.Done():
		result = client.Err()
	case <-ctx.Done():
		result = ctx.Err()
	}
	cancel()
	_ = client.Close()
	workers.Wait()
	return result
}

func forwardTunToH2(ctx context.Context, fd, mtu int, own, peer netip.Addr, client *H2Client) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-client.Done():
			return client.Err()
		default:
		}
		n, err := unix.Poll(fds, 25)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("MASQUE private TUN poll failed")
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		packets := make([][]byte, 0, 64)
		for i := 0; i < cap(packets); i++ {
			p := make([]byte, mtu+64)
			read, err := unix.Read(fd, p)
			if err == unix.EAGAIN {
				break
			}
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return fmt.Errorf("MASQUE TUN read failed: %w", err)
			}
			p = p[:read]
			accept, err := validateLocalTunIPv4Packet(p, own, peer)
			if err != nil {
				return err
			}
			if !accept {
				continue // Kernel may originate IPv6 router solicitations on an IPv4-only TUN.
			}
			packets = append(packets, p)
		}
		if err := client.SendPackets(ctx, packets); err != nil {
			return err
		}
	}
}

// validateLocalTunIPv4Packet drops valid locally generated IPv4 multicast
// control traffic (e.g. IGMP or LLMNR) before it reaches CONNECT-IP. Linux
// emits these packets even on a /32 point-to-point TUN. They are neither peer
// traffic nor a reason to tear down an otherwise authenticated session.
// Malformed and wrong-source packets still use the strict admission below.
// Only local TUN reads use this filter; received peer capsules never do.
func validateLocalTunIPv4Packet(p []byte, own, peer netip.Addr) (bool, error) {
	if len(p) >= 20 && p[0]>>4 == 4 && p[0]&0x0f >= 5 &&
		int(p[0]&0x0f)*4 <= len(p) &&
		int(binary.BigEndian.Uint16(p[2:4])) == len(p) {
		var src, dst [4]byte
		copy(src[:], p[12:16])
		copy(dst[:], p[16:20])
		if netip.AddrFrom4(src) == own && netip.AddrFrom4(dst).IsMulticast() {
			return false, nil
		}
	}
	return validateOutboundIPv4Packet(p, own, peer)
}

// validateOutboundIPv4Packet accepts only the Link's own exact IPv4 pair.
// Unrelated non-IPv4 interface control traffic is ignored, not treated as
// a tunnel failure. A malformed or misaddressed IPv4 packet is rejected.
func validateOutboundIPv4Packet(p []byte, own, peer netip.Addr) (bool, error) {
	if len(p) == 0 || p[0]>>4 != 4 {
		return false, nil
	}
	if len(p) < 20 || p[0]&0x0f < 5 ||
		int(p[0]&0x0f)*4 > len(p) ||
		int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
		return false, errors.New("MASQUE malformed private IPv4 packet")
	}
	var src, dst [4]byte
	copy(src[:], p[12:16])
	copy(dst[:], p[16:20])
	if netip.AddrFrom4(src) != own || netip.AddrFrom4(dst) != peer {
		return false, errors.New("MASQUE TUN attempted non-peer private routing")
	}
	return true, nil
}
