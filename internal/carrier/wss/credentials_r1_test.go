package wss

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/composition"
	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestR1GeneratedPerLinkMTLSAndBearer(t *testing.T) {
	server := wssTestLink()
	server.Backend = domain.BackendWireGuardWSS
	server.WSS = domain.WSSOptions{Role: "listen", TCPPort: 59443, TLSServerName: "198.51.100.21"}
	client := server
	client.WSS = domain.WSSOptions{Role: "dial", TCPPort: 59443, ForwardUDPPort: 53001, TLSServerName: "198.51.100.21"}
	client.Underlay.Local, client.Underlay.Peer = server.Underlay.Peer, server.Underlay.Local
	client.Addresses.Local, client.Addresses.Peer = server.Addresses.Peer, server.Addresses.Local
	client.WireGuard.ListenPort, client.WireGuard.PeerPort = server.WireGuard.PeerPort, server.WireGuard.ListenPort
	client.WireGuard.LocalPublicKey, client.WireGuard.PeerPublicKey = server.WireGuard.PeerPublicKey, server.WireGuard.LocalPublicKey
	listen, dial, err := GeneratePair(server.ID, "198.51.100.21")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	if bytes.Equal(listen["server-key.pem"], dial["client-key.pem"]) {
		t.Fatal("mTLS peers share private signing material")
	}
	for _, tc := range []struct {
		link  domain.Link
		files PrivateBundle
	}{{server, listen}, {client, dial}} {
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := Stage(root, tc.link, tc.files); err != nil {
			t.Fatalf("stage: %v", err)
		}
		fp, err := InspectCredentials(tc.link, composition.CarrierForLink(tc.link), root)
		if err != nil || fp.CertificateSHA256 == "" || fp.AuthorizationSHA256 == "" {
			t.Fatalf("inspect: %+v / %v", fp, err)
		}
		if err := Stage(root, tc.link, tc.files); err != nil {
			t.Fatalf("idempotent staging: %v", err)
		}
		secretPath := filepath.Join(root, "credentials", "wss", string(tc.link.ID))
		name := "client-key.pem"
		if tc.link.WSS.Role == "listen" {
			name = "server-key.pem"
		}
		if err := os.Chmod(filepath.Join(secretPath, name), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectCredentials(tc.link, composition.CarrierForLink(tc.link), root); err == nil {
			t.Fatal("accepted publicly readable WSS private key")
		}
	}
}

func TestR1PrivateNoReplaceRejectsClobber(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "config")
	if err := WritePrivateNoReplace(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateNoReplace(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateNoReplace(p, []byte("different")); err == nil {
		t.Fatal("overwrote protected credential")
	}
	original, err := os.ReadFile(p)
	if err != nil || string(original) != "one" {
		t.Fatalf("credential mutated: %v", err)
	}
	_ = context.Background()
}
