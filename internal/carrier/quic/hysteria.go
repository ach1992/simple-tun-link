// Package quic renders and protects the narrowly scoped UDP-over-QUIC carrier
// material used by the canonical managed WireGuard/QUIC Engine composition.
// These pure plans and file primitives do not independently authorize kernel,
// firewall or systemd effects; the managed backend owns those transactions.
package quic

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// HysteriaVersion is the precisely investigated upstream helper release.
// Runtime admission must compare the installed executable against a
// separately pinned architecture-specific official release SHA-256.
const HysteriaVersion = "v2.13.0"

type Role string

const (
	Dial   Role = "dial"
	Listen Role = "listen"
)

// Plan contains one Link's pre-admitted, typed public topology. Nothing here
// establishes a Link or authorizes a daemon. Underlay is the physical
// client-dialed or server-listened UDP address, NOT a private Link address.
// TLSName is the exact certificate SAN expected by the dialer/listener.
// The Plan is public topology only. A sensitive authorization token must
// be supplied separately by the owning per-Link credential lifecycle.
type Plan struct {
	LinkID              domain.LinkID
	Role                Role
	Underlay            netip.AddrPort
	TLSName             string
	LocalForwardUDPPort uint16 // Dial-side loopback socket; zero on Listen.
	PeerWGUDPPort       uint16 // Dial-side destination: listening peer's WG UDP port.
	LocalWGUDPPort      uint16 // Listen-side destination: its own kernel WG UDP port.
	// Only PlanFromLink selects the versioned managed lifecycle policy. Old
	// source-only Plan literals retain their byte-identical configuration.
	managed bool
}

// Command has only public process arguments. The config contains live
// credential material but is intentionally unexported; only the caller
// owning the verified protected 0600 file may consume ProtectedConfigBytes.
// Do NOT log the returned bytes or let a generic config writer follow links.
type Command struct {
	Binary          string
	Args            []string
	ConfigPath      string
	sensitiveConfig []byte
}

// ProtectedConfigBytes returns a separate mutable copy of secret-bearing JSON.
// The owner must write it atomically into a checked 0600 protected file,
// clear the copy, and enforce exact helper/credential identity before startup.
// A Command with live secret-bearing contents has one owner: do not copy it.
func (c Command) ProtectedConfigBytes() []byte {
	return append([]byte(nil), c.sensitiveConfig...)
}

// Clear explicitly erases the original secret-bearing builder buffer after
// staging, regardless of the lifetime of separately returned caller copies.
// Like CredentialBundle, copied Command values can alias this backing array:
// preserve single-owner semantics until Engine integration provides the
// verified protected staging boundary.
func (c *Command) Clear() {
	if c == nil {
		return
	}
	clear(c.sensitiveConfig)
	c.sensitiveConfig = nil
}

// String and GoString keep routine accidental formatting from exposing the
// private QUIC authorization token, even under %#v.
func (c Command) String() string {
	return fmt.Sprintf("quic helper config=%q [REDACTED]", c.ConfigPath)
}
func (c Command) GoString() string { return c.String() }

type tlsServer struct {
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	SNIGuard string `json:"sniGuard"`
	ClientCA string `json:"clientCA"`
}
type tlsClient struct {
	SNI               string `json:"sni"`
	Insecure          bool   `json:"insecure"`
	CA                string `json:"ca"`
	ClientCertificate string `json:"clientCertificate"`
	ClientKey         string `json:"clientKey"`
}
type serverAuth struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}
type serverACL struct {
	Inline []string `json:"inline"`
}
type udpForward struct {
	Listen  string `json:"listen"`
	Remote  string `json:"remote"`
	Timeout string `json:"timeout"`
}
type serverConfig struct {
	Listen     string     `json:"listen"`
	TLS        tlsServer  `json:"tls"`
	Auth       serverAuth `json:"auth"`
	ACL        serverACL  `json:"acl"`
	DisableUDP bool       `json:"disableUDP"`
}
type clientConfig struct {
	Server        string       `json:"server"`
	Auth          string       `json:"auth"`
	TLS           tlsClient    `json:"tls"`
	UDPForwarding []udpForward `json:"udpForwarding"`
	Lazy          bool         `json:"lazy,omitempty"`
}

// Build generates only data, not an executable or install operation. The
// exact Hysteria app/v2.13.0 server ACL admits only the verified kernel-WG
// local UDP port, then rejects ALL other TCP/UDP destinations. This prevents
// the optional Hysteria helper becoming a general-purpose authenticated
// network proxy. TLS1.3 server authentication, client-CA mTLS and an
// independent per-Link bearer are mandatory; config/secret material must
// never appear in argv, environment, status, or public diagnostics.
func Build(plan Plan, binary, privateRoot, authorizationToken string) (Command, error) {
	if err := plan.LinkID.Validate(); err != nil {
		return Command{}, errors.New("QUIC requires a valid exact Link owner")
	}
	if !safePath(binary) || !safePath(privateRoot) || privateRoot == "/" {
		return Command{}, errors.New("QUIC requires clean absolute executable and protected-storage paths")
	}
	if !plan.Underlay.IsValid() || !plan.Underlay.Addr().Is4() ||
		plan.Underlay.Addr().IsUnspecified() || plan.Underlay.Addr().IsMulticast() ||
		plan.Underlay.Port() == 0 {
		return Command{}, errors.New("QUIC requires a concrete IPv4 UDP endpoint and physical port")
	}
	if !validToken(authorizationToken) {
		return Command{}, errors.New("QUIC requires an independently generated 256-bit per-Link authorization token")
	}
	if !validTLSName(plan.TLSName, plan.Underlay.Addr()) {
		return Command{}, errors.New("QUIC requires the exact physical IP SAN or canonical DNS TLS identity")
	}
	if err := plan.validateRolePorts(); err != nil {
		return Command{}, err
	}
	root := filepath.Join(privateRoot, "credentials", "quic", string(plan.LinkID))
	ca := filepath.Join(root, "server-ca.pem")
	clientCA := filepath.Join(root, "client-ca.pem")
	clientCert := filepath.Join(root, "client-cert.pem")
	clientKey := filepath.Join(root, "client-key.pem")
	serverCert := filepath.Join(root, "server-cert.pem")
	serverKey := filepath.Join(root, "server-key.pem")
	configPath := filepath.Join(root, "helper.json")
	result := Command{Binary: binary, ConfigPath: configPath,
		Args: []string{"--disable-update-check", "--log-level", "info", "-c", configPath}}
	if plan.managed {
		result.Args = []string{"--disable-update-check", "--log-level", "info", "--log-format", "json", "-c", configPath}
	}
	var config any
	switch plan.Role {
	case Dial:
		config = clientConfig{
			Server: plan.Underlay.String(),
			Auth:   authorizationToken,
			// A managed dialer must bind its local forwarding socket even if
			// its peer has not imported the handoff yet. Pinned Hysteria retries
			// connection on later UDP calls; readiness here proves no peer auth.
			// https://github.com/apernet/hysteria/blob/ca8fbd874fd6ca82413948de6dc5924405e103e1/core/client/reconnect.go
			Lazy: plan.managed,
			TLS: tlsClient{SNI: plan.TLSName, Insecure: false, CA: ca,
				ClientCertificate: clientCert, ClientKey: clientKey},
			UDPForwarding: []udpForward{{
				Listen:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), plan.LocalForwardUDPPort).String(),
				Remote:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), plan.PeerWGUDPPort).String(),
				Timeout: "20s",
			}},
		}
		result.Args = append(result.Args, "client")
	case Listen:
		sniGuard := "strict"
		if _, err := netip.ParseAddr(plan.TLSName); err == nil {
			// IP-literal clients do not necessarily send an SNI hostname; their
			// pinned CA + exact IP SAN verification still authenticates the server.
			sniGuard = "dns-san"
		}
		config = serverConfig{
			Listen: plan.Underlay.String(),
			TLS:    tlsServer{Cert: serverCert, Key: serverKey, SNIGuard: sniGuard, ClientCA: clientCA},
			Auth:   serverAuth{Type: "password", Password: authorizationToken},
			ACL: serverACL{Inline: []string{
				"direct(127.0.0.1, udp/" + strconv.Itoa(int(plan.LocalWGUDPPort)) + ")",
				"reject(all)",
			}},
			DisableUDP: false,
		}
		result.Args = append(result.Args, "server")
	default:
		return Command{}, errors.New("QUIC role must be dial or listen")
	}
	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return Command{}, errors.New("QUIC helper configuration could not be serialized")
	}
	result.sensitiveConfig = append(contents, '\n')
	return result, nil
}

func safePath(s string) bool {
	return s != "" && filepath.IsAbs(s) && filepath.Clean(s) == s &&
		!strings.ContainsAny(s, "\x00\r\n")
}

func validToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, ch := range s {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func validTLSName(name string, peer netip.Addr) bool {
	return composition.ValidQUICTLSName(name, peer)
}
