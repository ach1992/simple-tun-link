// Package wss renders the first evidence-backed carrier's restricted,
// secret-free executable invocation. It does NOT spawn a daemon, provision TLS
// material, enforce the firewall, or authorize an STL Link: the existing Engine
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

// Command is an argv/env specification, never a shell fragment. The caller
// must first validate exact owner, executable hash, binary path, root-owned
// credential directory, certificate chain/SAN/CN and restrictive mode.
type Command struct {
	Binary string
	Args   []string
	Env    []string
	// ServerRestrictions must be durably materialized in a verified private
	// per-Link path before launching the server; absent on the dial side.
	ServerRestrictions []byte
}

// Build constructs an explicit wstunnel v11.0.0 mTLS invocation from a validated
// composition path. The producer of TLS keys/certificates MUST issue the dial
// side's client certificate CN equal to clientCN(link ID) and validate this
// against its trusted issuer. The server restriction uses that exact CN.
// This function is deliberately NOT a credential or executable trust verifier.
func Build(link domain.Link, carrier composition.Carrier, binary, privateRoot string) (Command, error) {
	path, err := composition.Build(link, carrier)
	if err != nil {
		return Command{}, err
	}
	if path.Kind != composition.WSS || path.CredentialOwner.Validate() != nil {
		return Command{}, fmt.Errorf("WSS command requires a validated WSS Carrier and Link owner")
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
		command.Args = []string{"client", "--tls-verify-certificate",
			"--tls-certificate", clientCert, "--tls-private-key", clientKey}
		if path.TLSName != path.WSSPeerTCP.Addr().String() {
			// Only override SNI/peer hostname for an explicitly selected
			// DNS SAN. The default uses verified physical peer IP identity.
			command.Args = append(command.Args, "--tls-sni-override", path.TLSName)
		}
		command.Args = append(command.Args, "-L", forward, uri.String())
		command.Env = []string{"SSL_CERT_FILE=" + ca}
	case composition.Listen:
		if !path.WSSLocalTCP.IsValid() || path.WSSPeerTCP.IsValid() ||
			path.WSSLocalUDP.IsValid() || path.WGPeerEndpoint.IsValid() ||
			path.WSSRemoteWGUDPPort == 0 {
			return Command{}, fmt.Errorf("invalid WSS listener topology")
		}
		uri := url.URL{Scheme: "wss", Host: path.WSSLocalTCP.String()}
		command.Args = []string{"server", "--tls-certificate", serverCert,
			"--tls-private-key", serverKey,
			"--tls-client-ca-certs", clientCA,
			"--restrict-config", restrict, uri.String()}
		command.ServerRestrictions = restrictedServerPolicy(path.CredentialOwner, path.WSSRemoteWGUDPPort)
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

// restrictedServerPolicy allows a single certificate CN upgrade prefix and
// ONLY a UDP forward to this exact Link's loopback WG port. No reverse
// tunnel, TCP forwarding, SOCKS, wildcards or foreign per-Link UDP target.
func restrictedServerPolicy(id domain.LinkID, udp uint16) []byte {
	return []byte(fmt.Sprintf(
		"restrictions:\n  - name: \"STL exact Link\"\n"+
			"    match:\n      - !PathPrefix \"^%s$\"\n"+
			"    allow:\n      - !Tunnel\n"+
			"        protocol:\n          - Udp\n"+
			"        port:\n          - %d\n"+
			"        host: \"^127\\\\.0\\\\.0\\\\.1$\"\n"+
			"        cidr:\n          - 127.0.0.1/32\n",
		clientCN(id), udp))
}
