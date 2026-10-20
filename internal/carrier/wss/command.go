// Package wss renders the first evidence-backed carrier's restricted
// executable invocation. A server policy includes a sensitive per-Link
// bearer token, but secret bytes are never placed in process arguments.
// It does NOT spawn a daemon, provision TLS material, enforce the firewall,
// or authorize an STL Link: the existing Engine
// must own those transitions before this may be wired into the live backend.
package wss

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

// safeWstunnelLogLevel must remain explicit: upstream v11 DEBUG/TRACE
// can print bearer-bearing restriction rules and HTTP upgrade requests.
// An explicit clap --log-lvl wins over inherited RUST_LOG on both roles.
const safeWstunnelLogLevel = "INFO"

// Command is an argv/env specification, never a shell fragment. The caller
// must first validate exact owner, executable hash, binary path, root-owned
// credential directory, certificate chain/SAN/CN and restrictive mode.
type Command struct {
	Binary string
	Args   []string
	Env    []string
	// ServerRestrictions CONTAINS A LIVE SECRET when present. It must
	// remain in a protected 0600 owner-controlled path, never in logs or
	// public output, and be cleared from memory when no longer needed.
	// It is absent on the dial side; the client reads its header from a
	// separate protected file (never argv/env secret material).
	ServerRestrictions []byte
}

// Build constructs a v11.0.0 mTLS invocation with a second, independent
// high-entropy per-Link bearer credential. Upstream v11 skips CN-to-path
// matching when the client certificate has no extractable CN, so PathPrefix
// alone is NOT authorization. A TLS-trusted client must ALSO know the
// per-Link token; this is the enforced authorization identity, with CN/path
// matching a secondary defense when CN is present. A client missing CN but
// possessing the bearer is not distinguishable by upstream v11: issuance,
// rotation/revocation and secret protection must account for that.
//
// The token must originate from a cryptographically secure 32-byte random
// secret generated out of band and securely provisioned to BOTH endpoints.
// This rendering function does no provisioning, validation of installed
// credentials, executable verification or process launch. The returned
// server restriction is SECRET and must not be logged or stored unprotected.
func Build(link domain.Link, carrier composition.Carrier, binary, privateRoot, authorizationToken string) (Command, error) {
	path, err := composition.Build(link, carrier)
	if err != nil {
		return Command{}, err
	}
	if path.Kind != composition.WSS || path.CredentialOwner.Validate() != nil {
		return Command{}, fmt.Errorf("WSS command requires a validated WSS Carrier and Link owner")
	}
	if !validAuthorizationToken(authorizationToken) {
		return Command{}, fmt.Errorf("WSS requires a valid private per-Link authorization token")
	}
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || !filepath.IsAbs(privateRoot) ||
		filepath.Clean(privateRoot) != privateRoot || privateRoot == "/" {
		return Command{}, fmt.Errorf("WSS executable and protected storage require clean absolute paths")
	}
	if strings.ContainsAny(binary, "\n\r\x00") || strings.ContainsAny(privateRoot, "\n\r\x00") {
		return Command{}, fmt.Errorf("invalid WSS resource path")
	}
	root := filepath.Join(privateRoot, "credentials", "wss", string(path.CredentialOwner))
	ca := filepath.Join(root, "server-ca.pem")
	clientCA := filepath.Join(root, "client-ca.pem")
	clientCert := filepath.Join(root, "client-cert.pem")
	clientKey := filepath.Join(root, "client-key.pem")
	serverCert := filepath.Join(root, "server-cert.pem")
	serverKey := filepath.Join(root, "server-key.pem")
	restrict := filepath.Join(root, "restrictions.yaml")
	authorizationHeaders := filepath.Join(root, "authorization-headers")
	command := Command{Binary: binary}
	switch path.Role {
	case composition.Dial:
		if !path.WSSPeerTCP.IsValid() || !path.WSSLocalUDP.IsValid() ||
			path.WGPeerEndpoint != path.WSSLocalUDP || !path.WSSLocalUDP.Addr().IsLoopback() ||
			path.WSSRemoteWGUDPPort == 0 || path.TLSName == "" {
			return Command{}, fmt.Errorf("invalid WSS dial topology")
		}
		local := net.JoinHostPort(path.WSSLocalUDP.Addr().String(), strconv.Itoa(int(path.WSSLocalUDP.Port())))
		remote := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(path.WSSRemoteWGUDPPort)))
		forward := "udp://" + local + ":" + remote + "?timeout_sec=0"
		uri := url.URL{Scheme: "wss", Host: path.WSSPeerTCP.String()}
		// Use the actual verified peer certificate DNS SAN; a physical IP
		// underlay must not be misrepresented as a DNS address.
		command.Args = []string{"client", "--log-lvl", safeWstunnelLogLevel, "--tls-verify-certificate",
			"--tls-certificate", clientCert, "--tls-private-key", clientKey}
		if path.TLSName != path.WSSPeerTCP.Addr().String() {
			// Only override SNI/peer hostname for an explicitly selected
			// DNS SAN. The default uses verified physical peer IP identity.
			command.Args = append(command.Args, "--tls-sni-override", path.TLSName)
		}
		command.Args = append(command.Args, "--http-headers-file", authorizationHeaders,
			"-L", forward, uri.String())
		command.Env = []string{"SSL_CERT_FILE=" + ca}
	case composition.Listen:
		if !path.WSSLocalTCP.IsValid() || path.WSSPeerTCP.IsValid() ||
			path.WSSLocalUDP.IsValid() || path.WGPeerEndpoint.IsValid() ||
			path.WSSRemoteWGUDPPort == 0 {
			return Command{}, fmt.Errorf("invalid WSS listener topology")
		}
		uri := url.URL{Scheme: "wss", Host: path.WSSLocalTCP.String()}
		command.Args = []string{"server", "--log-lvl", safeWstunnelLogLevel, "--tls-certificate", serverCert,
			"--tls-private-key", serverKey,
			"--tls-client-ca-certs", clientCA,
			"--restrict-config", restrict, uri.String()}
		command.ServerRestrictions = restrictedServerPolicy(path.CredentialOwner, path.WSSRemoteWGUDPPort, authorizationToken)
	default:
		return Command{}, fmt.Errorf("unknown WSS role")
	}
	return command, nil
}

func clientCN(id domain.LinkID) string {
	// Exactly 32 hex chars from a validated LinkID; no regex or YAML
	// injection into wstunnel's client-cert CN/path matching.
	return "stl" + string(id)[4:]
}

// validAuthorizationToken accepts one unambiguous 256-bit random value.
// This also prohibits regex/YAML metacharacters and log/header injection.
func validAuthorizationToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for _, ch := range token {
		if !((ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9')) {
			return false
		}
	}
	return true
}

// restrictedServerPolicy requires BOTH an exact requested Link path and a
// strong per-Link bearer token, plus mTLS enforced by wstunnel itself.
// PathPrefix is NOT proof of CN identity in wstunnel v11 when CN extraction
// fails. No reverse tunnel, TCP, SOCKS, foreign port or foreign host allowed.
// This output contains the bearer secret; treat as private credential bytes.
func restrictedServerPolicy(id domain.LinkID, udp uint16, token string) []byte {
	return []byte(fmt.Sprintf(
		"restrictions:\n  - name: \"STL private Link authorization\"\n"+
			"    match:\n      - !PathPrefix \"^%s$\"\n"+
			"      - !Authorization \"^Bearer %s$\"\n"+
			"    allow:\n      - !Tunnel\n"+
			"        protocol:\n          - Udp\n"+
			"        port:\n          - %d\n"+
			"        host: \"^127\\\\.0\\\\.0\\\\.1$\"\n"+
			"        cidr:\n          - 127.0.0.1/32\n",
		clientCN(id), token, udp))
}
