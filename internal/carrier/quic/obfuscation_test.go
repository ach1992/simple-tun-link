package quic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestQUICSalamanderIssuesDistinctProtectedSecretAndSemanticIdentity(t *testing.T) {
	listen, dial, err := GeneratePairWithObfuscation(domainTestLinkID(), "quic-probe.invalid", domain.QUICObfuscationSalamander)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	a, b := listen.ProtectedFiles(), dial.ProtectedFiles()
	defer clearProtectedCopies(a)
	defer clearProtectedCopies(b)
	secret := a[obfuscationSecretFile]
	if len(a) != 5 || len(b) != 5 || len(secret) != 65 || secret[64] != '\n' || !validToken(string(secret[:64])) ||
		!bytes.Equal(secret, b[obfuscationSecretFile]) || bytes.Equal(secret, a["authorization-token"]) {
		t.Fatal("Salamander must add exactly one distinct 256-bit shared protected secret")
	}
	digest := sha256.Sum256(secret[:64])
	for _, tc := range []struct {
		role   Role
		bundle CredentialBundle
	}{{Listen, listen}, {Dial, dial}} {
		plan := materialPlan(domainTestLinkID(), tc.role)
		plan.Obfuscation = domain.QUICObfuscationSalamander
		root := privateStateRoot(t)
		identity, err := StageCredentials(root, plan, tc.bundle)
		if err != nil {
			t.Fatal(err)
		}
		if identity.ObfuscationSHA256 != hex.EncodeToString(digest[:]) || identity.ObfuscationSHA256 == identity.AuthorizationSHA256 {
			t.Fatal("protected obfuscation identity does not bind the newline-free secret")
		}
		if got, err := InspectCredentials(root, plan); err != nil || got != identity {
			t.Fatalf("mode-specific protected readback failed: %v", err)
		}
		plain := plan
		plain.Obfuscation = domain.QUICObfuscationPlain
		if _, err := InspectCredentials(root, plain); err == nil {
			t.Fatal("plain reader accepted an extra protected obfuscation secret")
		}
		if info, err := os.Stat(filepath.Join(root, "credentials", "quic", string(plan.LinkID), obfuscationSecretFile)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("obfuscation secret is not private: %v", err)
		}
	}
	other, peer, err := GeneratePairWithObfuscation(domainTestLinkID(), "quic-probe.invalid", domain.QUICObfuscationSalamander)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Clear()
	defer peer.Clear()
	fresh := other.ProtectedFiles()
	defer clearProtectedCopies(fresh)
	if bytes.Equal(secret, fresh[obfuscationSecretFile]) {
		t.Fatal("a new credential generation reused the obfuscation secret")
	}
}

func TestQUICSalamanderRejectsIncompleteExtraOrReusedMaterialBeforeEffects(t *testing.T) {
	listen, dial, err := GeneratePairWithObfuscation(domainTestLinkID(), "quic-probe.invalid", domain.QUICObfuscationSalamander)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Clear()
	defer dial.Clear()
	for _, tc := range []struct {
		name string
		mode string
		edit func(map[string][]byte)
	}{
		{"missing", domain.QUICObfuscationSalamander, func(m map[string][]byte) { clear(m[obfuscationSecretFile]); delete(m, obfuscationSecretFile) }},
		{"short", domain.QUICObfuscationSalamander, func(m map[string][]byte) { m[obfuscationSecretFile] = []byte("short\n") }},
		{"uppercase", domain.QUICObfuscationSalamander, func(m map[string][]byte) { m[obfuscationSecretFile] = []byte(strings.Repeat("A", 64) + "\n") }},
		{"missing-newline", domain.QUICObfuscationSalamander, func(m map[string][]byte) { m[obfuscationSecretFile] = m[obfuscationSecretFile][:64] }},
		{"reused-bearer", domain.QUICObfuscationSalamander, func(m map[string][]byte) { m[obfuscationSecretFile] = append([]byte(nil), m["authorization-token"]...) }},
		{"extra-file", domain.QUICObfuscationSalamander, func(m map[string][]byte) { m["extra-secret"] = []byte("extra") }},
		{"plain-with-secret", domain.QUICObfuscationPlain, func(map[string][]byte) {}},
		{"unknown-mode", "automatic", func(map[string][]byte) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := dial.ProtectedFiles()
			defer clearProtectedCopies(files)
			tc.edit(files)
			plan := materialPlan(domainTestLinkID(), Dial)
			plan.Obfuscation = tc.mode
			root := privateStateRoot(t)
			if _, err := StageCredentials(root, plan, CredentialBundle{files: files}); err == nil {
				t.Fatal("invalid obfuscation material was admitted")
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("rejected material created protected State storage")
			}
		})
	}
	if a, b, err := GeneratePairWithObfuscation(domainTestLinkID(), "quic-probe.invalid", "plain"); err == nil {
		a.Clear()
		b.Clear()
		t.Fatal("internal issuer accepted a noncanonical mode spelling")
	}
}

func TestQUICSalamanderRendererAddsOnlyTypedPrivateObfsBlock(t *testing.T) {
	const secret = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, role := range []Role{Dial, Listen} {
		plain, _ := helperConfigPlan(domainTestLinkID(), role)
		old, err := Build(plain, fixtureHysteriaPath, "/var/lib/simple-tun-link", fixtureToken)
		if err != nil {
			t.Fatal(err)
		}
		defer old.Clear()
		plan := plain
		plan.Obfuscation = domain.QUICObfuscationSalamander
		cmd, err := BuildWithObfuscation(plan, fixtureHysteriaPath, "/var/lib/simple-tun-link", fixtureToken, secret)
		if err != nil {
			t.Fatal(err)
		}
		defer cmd.Clear()
		before, after := unwrap(t, old), unwrap(t, cmd)
		var block obfuscationConfig
		if err := json.Unmarshal(after["obfs"], &block); err != nil || block.Type != "salamander" || block.Salamander.Password != secret {
			t.Fatal("renderer did not emit the exact upstream Salamander shape")
		}
		delete(after, "obfs")
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(old.Args, cmd.Args) {
			t.Fatal("Salamander changed TLS, authentication, forwarding, ACL or helper arguments")
		}
		if strings.Contains(fmt.Sprintf("%+v %#v %v", cmd, cmd, cmd.Args), secret) {
			t.Fatal("obfuscation secret leaked outside protected configuration")
		}
		for _, invalid := range []struct {
			plan   Plan
			secret string
		}{
			{plain, secret}, {plan, ""}, {plan, fixtureToken}, {plan, "malformed"},
		} {
			if got, err := BuildWithObfuscation(invalid.plan, fixtureHysteriaPath, "/var/lib/simple-tun-link", fixtureToken, invalid.secret); err == nil {
				got.Clear()
				t.Fatal("renderer accepted missing, extra or reused mode material")
			}
		}
		if got, err := Build(plan, fixtureHysteriaPath, "/var/lib/simple-tun-link", fixtureToken); err == nil {
			got.Clear()
			t.Fatal("legacy Build silently downgraded a Salamander plan")
		}
	}
}

// Frozen pre-obfuscation JSON protects existing config hashes and source-only
// Plan journals. Adding Salamander must not rewrite admitted Plain bytes.
func TestQUICPlainConfigAndPlanBytesRemainCompatible(t *testing.T) {
	const root = "/var/lib/simple-tun-link/credentials/quic/lnk_0123456789abcdef0123456789abcdef"
	for _, role := range []Role{Dial, Listen} {
		plan := fixturePlan(role)
		var config, publicPlan string
		if role == Dial {
			plan.LocalForwardUDPPort, plan.PeerWGUDPPort = 52211, 51821
			config = `{"server":"203.0.113.45:443","auth":"` + fixtureToken + `","tls":{"sni":"quic-probe.invalid","insecure":false,"ca":"` + root + `/server-ca.pem","clientCertificate":"` + root + `/client-cert.pem","clientKey":"` + root + `/client-key.pem"},"udpForwarding":[{"listen":"127.0.0.1:52211","remote":"127.0.0.1:51821","timeout":"20s"}]}`
			publicPlan = `{"LinkID":"lnk_0123456789abcdef0123456789abcdef","Role":"dial","Underlay":"203.0.113.45:443","TLSName":"quic-probe.invalid","LocalForwardUDPPort":52211,"PeerWGUDPPort":51821,"LocalWGUDPPort":0}`
		} else {
			plan.LocalWGUDPPort = 51820
			config = `{"listen":"203.0.113.45:443","tls":{"cert":"` + root + `/server-cert.pem","key":"` + root + `/server-key.pem","sniGuard":"strict","clientCA":"` + root + `/client-ca.pem"},"auth":{"type":"password","password":"` + fixtureToken + `"},"acl":{"inline":["direct(127.0.0.1, udp/51820)","reject(all)"]},"disableUDP":false}`
			publicPlan = `{"LinkID":"lnk_0123456789abcdef0123456789abcdef","Role":"listen","Underlay":"203.0.113.45:443","TLSName":"quic-probe.invalid","LocalForwardUDPPort":0,"PeerWGUDPPort":0,"LocalWGUDPPort":51820}`
		}
		cmd, err := Build(plan, fixtureHysteriaPath, "/var/lib/simple-tun-link", fixtureToken)
		if err != nil {
			t.Fatal(err)
		}
		defer cmd.Clear()
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, []byte(config), "", "  "); err != nil {
			t.Fatal(err)
		}
		formatted.WriteByte('\n')
		actual := cmd.ProtectedConfigBytes()
		defer clear(actual)
		if !bytes.Equal(actual, formatted.Bytes()) {
			t.Fatal("pre-obfuscation Plain helper bytes changed")
		}
		encoded, err := json.Marshal(plan)
		if err != nil || string(encoded) != publicPlan {
			t.Fatal("pre-obfuscation Plain Plan bytes changed")
		}
	}
	identity := CredentialIdentity{CertificateSHA256: "leaf", TrustCASHA256: "ca", AuthorizationSHA256: "bearer"}
	encoded, err := json.Marshal(identity)
	if err != nil || string(encoded) != `{"CertificateSHA256":"leaf","TrustCASHA256":"ca","AuthorizationSHA256":"bearer"}` {
		t.Fatal("pre-obfuscation Plain receipt credential identity bytes changed")
	}
}

func TestQUICSalamanderGenerationPinsSecretAndRetiresExactInventory(t *testing.T) {
	for _, role := range []Role{Listen, Dial} {
		for _, change := range []string{"partial-retirement", "secret-replaced", "mode-changed", "digest-changed"} {
			t.Run(string(role)+"/"+change, func(t *testing.T) {
				ctx := context.Background()
				root, plan, port, expected, nonce, dir := stageInspectionFixtureWithObfuscation(t, role, domain.QUICObfuscationSalamander)
				pin, err := openPinnedGeneration(ctx, root, plan, port, fixtureHysteriaPath, nonce, expected, fixtureHysteriaAdmission)
				if err != nil {
					t.Fatal(err)
				}
				defer pin.Close()
				identity := pin.Identity()
				if identity.ObfuscationSHA256 == "" || identity.ObfuscationSHA256 != expected.Credentials.ObfuscationSHA256 {
					t.Fatal("generation pin lost the independent secret identity")
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 7 {
					t.Fatalf("unexpected Salamander generation inventory: %v", err)
				}
				switch change {
				case "partial-retirement":
					pin.Close()
					if err := os.Remove(filepath.Join(dir, obfuscationSecretFile)); err != nil {
						t.Fatal(err)
					}
					if err := RetireOwnedGeneration(ctx, root, plan, nonce, expected, identity); err != nil {
						t.Fatal(err)
					}
					if absent, err := GenerationAbsent(root, plan.LinkID); err != nil || !absent {
						t.Fatal("partial retirement did not consume the exact original generation")
					}
					return
				case "secret-replaced":
					path := filepath.Join(dir, obfuscationSecretFile)
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					defer clear(raw)
					if err := os.Rename(path, filepath.Join(root, "original-obfs-secret")); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := pin.Verify(ctx); err == nil {
						t.Fatal("same-byte replacement obfuscation inode passed the pin")
					}
				case "mode-changed":
					plan.Obfuscation = domain.QUICObfuscationPlain
				case "digest-changed":
					expected.Credentials.ObfuscationSHA256 = strings.Repeat("9", 64)
				}
				if err := InspectGenerationReceipt(root, plan, nonce, expected); err == nil {
					t.Fatal("changed obfuscation identity passed the original receipt")
				}
				if err := RetireOwnedGeneration(ctx, root, plan, nonce, expected, identity); err == nil {
					t.Fatal("changed obfuscation identity gained retirement authority")
				}
				for _, name := range []string{"authorization-token", "helper.json", generationReceiptName} {
					if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
						t.Fatal("failed retirement removed original material")
					}
				}
			})
		}
	}
}
