package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedMirrorPublisherGeneratesAuthenticatedStaticFilesOnly(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "mirror")
	tag := "v0.1.26"
	if err := os.MkdirAll(filepath.Join(root, "releases", tag), 0700); err != nil {
		t.Fatal(err)
	}
	boot := []byte("#!/bin/bash\nset -e\n# fully staged and previously verified\n")
	if err := os.WriteFile(filepath.Join(root, "install.sh"), boot, 0644); err != nil {
		t.Fatal(err)
	}
	sums := []byte(strings.Repeat("a", 64) + "  BUILD-MANIFEST.txt\n")
	if err := os.WriteFile(filepath.Join(root, "releases", tag, "SHA256SUMS"), sums, 0644); err != nil {
		t.Fatal(err)
	}
	manifest := []byte("project=simple-tun-link\nversion=" + tag + "\ncommit=" + strings.Repeat("b", 40) +
		"\nmode=tag\nsource=https://github.com/ach1992/simple-tun-link\n")
	if err := os.WriteFile(filepath.Join(root, "releases", tag, "BUILD-MANIFEST.txt"), manifest, 0644); err != nil {
		t.Fatal(err)
	}
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	privateFile := filepath.Join(parent, "private.pem")
	if err := os.WriteFile(privateFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(sums)
	trusted := hex.EncodeToString(hash[:])
	trustedBoot := sha256.Sum256(boot)
	msg, err := signRelease(root, tag, privateFile, trusted, hex.EncodeToString(trustedBoot[:]), 1)
	if err != nil {
		t.Fatal(err)
	}
	pub := pk.Public().(ed25519.PublicKey)
	pfp := sha256.Sum256(pub)
	if !strings.Contains(msg, hex.EncodeToString(pfp[:])) {
		t.Fatal("publisher fingerprint missing")
	}
	raw, err := os.ReadFile(filepath.Join(root, "release.json"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "release.sig"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"release.json", "release.sig"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil || info.Mode().Perm() != 0644 {
			t.Fatalf("signed metadata must be public/read-only for web-server: %s mode=%v err=%v", name, info, err)
		}
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || !ed25519.Verify(pub, raw, sig) {
		t.Fatal("offline signed metadata cannot be verified")
	}
	var meta release
	if json.Unmarshal(raw, &meta) != nil || meta.Purpose != purpose || meta.Version != tag ||
		meta.Sequence != 1 || meta.Commit != strings.Repeat("b", 40) {
		t.Fatalf("unexpected signed metadata: %+v", meta)
	}
	bootSum := sha256.Sum256(boot)
	if meta.BootstrapSHA256 != hex.EncodeToString(bootSum[:]) {
		t.Fatal("bootstrap checksum incorrect")
	}
	if _, err := signRelease(root, tag, privateFile, trusted, hex.EncodeToString(trustedBoot[:]), 2); err == nil {
		t.Fatal("a second signing attempt overwrote existing publication")
	}
	os.Remove(filepath.Join(root, "release.json"))
	os.Remove(filepath.Join(root, "release.sig"))
	if _, err := signRelease(root, tag, privateFile, strings.Repeat("c", 64), hex.EncodeToString(trustedBoot[:]), 2); err == nil {
		t.Fatal("untrusted release-wide sums were signed")
	}
	if _, err := signRelease(root, tag, privateFile, trusted, strings.Repeat("f", 64), 2); err == nil {
		t.Fatal("modified bootstrap code was authenticated using only release-wide sums")
	}
	if err := os.Chmod(privateFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := signRelease(root, tag, privateFile, trusted, hex.EncodeToString(trustedBoot[:]), 2); err == nil {
		t.Fatal("insecure private key file was accepted")
	}
}

func TestSignedMirrorPublisherRejectsUntrustedInput(t *testing.T) {
	if _, err := readManifestCommit([]byte("version=v0.1.26\ncommit="+strings.Repeat("a", 40)+"\n"), "v0.1.26"); err == nil {
		t.Fatal("unverified manifest source was accepted")
	}
	if _, err := readManifestCommit([]byte("project=simple-tun-link\nversion=v0.1.26\ncommit="+strings.Repeat("a", 40)+
		"\nmode=tag\nsource=https://github.com/ach1992/simple-tun-link\ncommit="+strings.Repeat("a", 40)+"\n"), "v0.1.26"); err == nil {
		t.Fatal("duplicate manifest commit accepted")
	}
}
