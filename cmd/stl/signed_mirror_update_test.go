package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleSignedMirror(t *testing.T) (mirrorPublisherTrust, ed25519.PrivateKey, mirrorSignedRelease, []byte, []byte) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := mirrorPublisherTrust{SchemaVersion: 1, PublicKey: base64.StdEncoding.EncodeToString(pub),
		Fingerprint: publisherKeyFingerprint(pub), Sequence: 8, LastVersion: "v0.1.25"}
	meta := mirrorSignedRelease{Purpose: mirrorReleasePurpose, Sequence: 9, Version: "v0.1.26",
		Commit: strings.Repeat("a", 40), BootstrapSHA256: strings.Repeat("b", 64), KeyFingerprint: trust.Fingerprint}
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	return trust, private, meta, raw, ed25519.Sign(private, raw)
}

func TestSignedMirrorPublisherIdentityReplayAndReleaseControls(t *testing.T) {
	state, key, meta, raw, sig := sampleSignedMirror(t)
	pub, err := validatedPublisherTrust(state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyMirrorSignedRelease(raw, sig, pub, state, "v0.1.25")
	if err != nil || got != meta {
		t.Fatalf("authentic newer metadata rejected: %+v %v", got, err)
	}
	cases := []struct {
		name   string
		change func(*mirrorSignedRelease)
	}{
		{"replay sequence", func(m *mirrorSignedRelease) { m.Sequence = 8 }},
		{"old tag", func(m *mirrorSignedRelease) { m.Version = "v0.1.24" }},
		{"different release line", func(m *mirrorSignedRelease) { m.Version = "v0.2.0" }},
		{"incompatible key", func(m *mirrorSignedRelease) { m.KeyFingerprint = strings.Repeat("f", 64) }},
		{"changed executable digest", func(m *mirrorSignedRelease) { m.BootstrapSHA256 = "" }},
		{"unsigned schema", func(m *mirrorSignedRelease) { m.Purpose = "different-protocol" }},
		{"missing release commit", func(m *mirrorSignedRelease) { m.Commit = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := meta
			tc.change(&bad)
			content, _ := json.Marshal(bad)
			signed := ed25519.Sign(key, content)
			if _, err := verifyMirrorSignedRelease(content, signed, pub, state, "v0.1.25"); err == nil {
				t.Fatal("authenticated but ineligible mirror release admitted")
			}
		})
	}
	for _, tc := range []struct {
		name               string
		content, signature []byte
	}{
		{"body substituted", append(append([]byte{}, raw...), ' '), sig},
		{"wrong signature", raw, bytes.Repeat([]byte{0}, 64)},
		{"incomplete signature", raw, sig[:31]},
		{"too much control data", bytes.Repeat([]byte("x"), mirrorReleaseMetadataBytes+1), sig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyMirrorSignedRelease(tc.content, tc.signature, pub, state, "v0.1.25"); err == nil {
				t.Fatal("unauthenticated mirror metadata admitted")
			}
		})
	}
	otherPub, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := verifyMirrorSignedRelease(raw, ed25519.Sign(otherPrivate, raw), otherPub, state, "v0.1.25"); err == nil {
		t.Fatal("a different publisher signed metadata and was accepted")
	}
}

func TestPublisherTrustPrivateAtomicStorageAndNoForeignIdentity(t *testing.T) {
	state, _, _, _, _ := sampleSignedMirror(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	// Test ownership is the invoking user, never a privileged production path.
	uid := uint32(os.Geteuid())
	if err := writePublisherTrust(root, uid, state); err != nil {
		t.Fatal(err)
	}
	got, err := readPublisherTrust(root, uid)
	if err != nil || got.Fingerprint != state.Fingerprint || got.Sequence != state.Sequence {
		t.Fatalf("trust readback failed: %+v %v", got, err)
	}
	lock, err := lockPublisherTrust(root, uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	state.Sequence = 11
	state.LastVersion = "v0.1.27"
	if err := writePublisherTrust(root, uid, state); err != nil {
		t.Fatal(err)
	}
	got, err = readPublisherTrust(root, uid)
	if err != nil || got.Sequence != 11 || got.LastVersion != "v0.1.27" {
		t.Fatalf("atomic trust update: %+v %v", got, err)
	}
	path := filepath.Join(root, publisherTrustFile)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublisherTrust(root, uid); err == nil {
		t.Fatal("world-readable trust was admitted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, publisherTrustLockFile), path); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublisherTrust(root, uid); err == nil {
		t.Fatal("symlink trust was admitted")
	}
}

func TestSignedMirrorUsesExactHTTPSOriginAndIndependentPubKey(t *testing.T) {
	state, key, meta, raw, _ := sampleSignedMirror(t)
	_ = meta
	pub, err := validatedPublisherTrust(state)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, raw)
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/release.json":
			w.Write(raw)
		case "/release.sig":
			w.Write([]byte(base64.StdEncoding.EncodeToString(sig) + "\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	got, err := fetchVerifiedSignedMirror(context.Background(), server.Client(), server.URL+"/install.sh", pub, state, "v0.1.25")
	if err != nil || got.Sequence != 9 || strings.Join(requests, ",") != "/release.json,/release.sig" {
		t.Fatalf("same-origin signed lookup failed: %+v %v %v", got, err, requests)
	}
	if _, err := fetchVerifiedSignedMirror(context.Background(), server.Client(), server.URL+"/install.sh?x=1", pub, state, "v0.1.25"); err == nil {
		t.Fatal("query-bearing bootstrap origin admitted")
	}
	// The HTTP client must not silently follow a redirect into a different
	// origin and accept a valid signature fetched through another host.
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL+"/release.json", http.StatusFound)
	}))
	defer redirect.Close()
	client := redirect.Client()
	client.CheckRedirect = verifiedUpdateHTTPClient().CheckRedirect
	if _, err := fetchVerifiedSignedMirror(context.Background(), client, redirect.URL+"/install.sh", pub, state, "v0.1.25"); err == nil {
		t.Fatal("signed mirror metadata followed a redirect")
	}
}

func TestPublisherKeyFingerprintMatchesRawEd25519(t *testing.T) {
	state, _, _, _, _ := sampleSignedMirror(t)
	pub, _ := base64.StdEncoding.DecodeString(state.PublicKey)
	h := sha256.Sum256(pub)
	if hex.EncodeToString(h[:]) != state.Fingerprint {
		t.Fatal("key fingerprint is not SHA256 of raw Ed25519 key")
	}
}

// The detached publisher signature authenticates the hash of the exact
// bootstrap bytes ultimately handed to the canonical installer. HTTPS/TLS
// transport alone is never a substitute for either signature or hash.
func TestSignedMirrorFirstHopEndToEndBeforeRootExecution(t *testing.T) {
	state, key, meta, _, _ := sampleSignedMirror(t)
	bootstrap := []byte("#!/usr/bin/env bash\nprintf 'never execute in this verification test'\n")
	h := sha256.Sum256(bootstrap)
	meta.BootstrapSHA256 = hex.EncodeToString(h[:])
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, raw)
	var substitute bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release.json":
			_, _ = w.Write(raw)
		case "/release.sig":
			_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(sig) + "\n"))
		case "/install.sh":
			if substitute {
				_, _ = w.Write([]byte("#!/bin/bash\nexit 0 # SUBSTITUTED\n"))
			} else {
				_, _ = w.Write(bootstrap)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	pub, err := validatedPublisherTrust(state)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := fetchVerifiedSignedMirror(context.Background(),
		server.Client(), server.URL+"/install.sh", pub, state, "v0.1.25")
	if err != nil || approved.BootstrapSHA256 != meta.BootstrapSHA256 {
		t.Fatalf("authentic metadata: %+v err=%v", approved, err)
	}
	root := t.TempDir()
	owner := uint32(os.Geteuid())
	dir, snapshot, err := verifiedMirrorSnapshot(context.Background(), server.URL+"/install.sh",
		approved.BootstrapSHA256, root, owner, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(snapshot)
	if err != nil || !bytes.Equal(actual, bootstrap) {
		t.Fatal("privileged updater snapshot not exactly authenticated by publisher")
	}
	os.RemoveAll(dir)
	substitute = true
	if _, _, err := verifiedMirrorSnapshot(context.Background(), server.URL+"/install.sh",
		approved.BootstrapSHA256, root, owner, server.Client()); err == nil {
		t.Fatal("mirror substituted script despite valid previously signed metadata")
	}
}
