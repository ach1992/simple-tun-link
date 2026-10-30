package quic

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/credentials"
)

func TestQUICImportCredentialBundleBindsRoleAndOwnsCopies(t *testing.T) {
	listen, dial, err := GeneratePair(domainTestLinkID(), "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	for _, tc := range []struct {
		role   Role
		source CredentialBundle
	}{{Listen, listen}, {Dial, dial}} {
		t.Run(string(tc.role), func(t *testing.T) {
			files := tc.source.ProtectedFiles()
			defer clearRoleFiles(files)
			got, err := ImportCredentialBundle(materialPlan(domainTestLinkID(), tc.role), files)
			if err != nil {
				t.Fatal(err)
			}
			defer got.Clear()
			token := append([]byte(nil), files["authorization-token"]...)
			defer clear(token)
			files["authorization-token"][0] ^= 1
			exported := got.ProtectedFiles()
			defer clearRoleFiles(exported)
			if !bytes.Equal(exported["authorization-token"], token) {
				t.Fatal("input aliases imported secret")
			}
			exported["authorization-token"][1] ^= 1
			again := got.ProtectedFiles()
			defer clearRoleFiles(again)
			if !bytes.Equal(again["authorization-token"], token) {
				t.Fatal("export aliases imported secret")
			}
			if strings.Contains(fmt.Sprintf("%v %#v", got, got), string(token[:64])) {
				t.Fatal("bundle formatting exposed token")
			}
		})
	}
}

func TestQUICImportCredentialBundleRejectsForeignAndMalformedPayload(t *testing.T) {
	server, client, err := GeneratePair(domainTestLinkID(), "quic-probe.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Clear()
	defer client.Clear()
	for _, tc := range []struct {
		name   string
		change func(map[string][]byte)
	}{
		{"extra", func(f map[string][]byte) { f["helper.json"] = []byte("{}") }},
		{"missing", func(f map[string][]byte) { clear(f["client-ca.pem"]); delete(f, "client-ca.pem") }},
		{"oversized", func(f map[string][]byte) {
			clear(f["server-key.pem"])
			f["server-key.pem"] = bytes.Repeat([]byte{'x'}, credentials.MaxPrivateFileBytes+1)
		}},
		{"invalid-token", func(f map[string][]byte) { f["authorization-token"][0] = 'G' }},
		{"wrong-key", func(f map[string][]byte) {
			clear(f["server-key.pem"])
			f["server-key.pem"] = []byte("invalid private key")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := server.ProtectedFiles()
			defer clearRoleFiles(files)
			tc.change(files)
			got, err := ImportCredentialBundle(materialPlan(domainTestLinkID(), Listen), files)
			defer got.Clear()
			if err == nil || len(got.files) != 0 {
				t.Fatal("malformed import returned usable credentials")
			}
		})
	}
	files := client.ProtectedFiles()
	defer clearRoleFiles(files)
	if got, err := ImportCredentialBundle(materialPlan(domainTestLinkID(), Listen), files); err == nil {
		got.Clear()
		t.Fatal("opposite role accepted")
	}
	plan := materialPlan("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Dial)
	if got, err := ImportCredentialBundle(plan, files); err == nil {
		got.Clear()
		t.Fatal("another Link identity accepted")
	}
}
