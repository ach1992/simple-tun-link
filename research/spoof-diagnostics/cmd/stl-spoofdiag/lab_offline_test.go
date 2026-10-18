package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineChallengeSignatureAndPacket(t *testing.T) {
	dir, ca := testLabCredentials(t)
	file := testSourcesFile(t, "10.90.3.100")
	o := testOpts(dir, ca, file, "A", "B")
	signed, err := newOfflineChallenge(o)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := challengeSignerCertificate(signed, roots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sender, err := tls.LoadX509KeyPair(filepath.Join(dir, "A.crt"), filepath.Join(dir, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	key := sender.PrivateKey.(ed25519.PrivateKey)
	p, err := makeOfflinePacket(signed.Challenge, signed.Challenge.Samples[0], key)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	if _, ok := verifyOfflinePacket(p, signed.Challenge, cert.PublicKey.(ed25519.PublicKey), seen); !ok {
		t.Fatal("signed packet rejected")
	}
	if _, ok := verifyOfflinePacket(p, signed.Challenge, cert.PublicKey.(ed25519.PublicKey), seen); ok {
		t.Fatal("signed packet replay admitted")
	}
	for _, index := range []int{0, 10, 25, 34, 60, len(p) - 1} {
		changed := append([]byte(nil), p...)
		changed[index] ^= 1
		if _, ok := verifyOfflinePacket(changed, signed.Challenge, cert.PublicKey.(ed25519.PublicKey), map[int]bool{}); ok {
			t.Fatalf("signed packet tampering admitted at %d", index)
		}
	}
	tampered := signed
	tampered.Challenge.Samples = append([]labSample(nil), signed.Challenge.Samples...)
	tampered.Challenge.Samples[0].Candidate.IP = "10.90.3.250"
	if _, err := challengeSignerCertificate(tampered, roots, time.Now()); err == nil {
		t.Fatal("tampered challenge accepted")
	}
	tampered = signed
	tampered.SignatureHex = "aaaaaaaa"
	if _, err := challengeSignerCertificate(tampered, roots, time.Now()); err == nil {
		t.Fatal("invalid challenge signature accepted")
	}
	tampered = signed
	tampered.Challenge.ExpiresUnix = time.Now().Add(-time.Second).Unix()
	if _, err := challengeSignerCertificate(tampered, roots, time.Now()); err == nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestOfflineEvidenceWithoutControlChannel(t *testing.T) {
	dir, ca := testLabCredentials(t)
	file := testSourcesFile(t, "10.90.3.100")
	base := t.TempDir()
	sender := testOpts(dir, ca, file, "A", "B")
	signed, err := newOfflineChallenge(sender)
	if err != nil {
		t.Fatal(err)
	}
	challengePath := filepath.Join(base, "challenge.json")
	if err := saveNewJSON(challengePath, signed); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	receiver := testOpts(dir, ca, file, "A", "B")
	receiver.Cert = filepath.Join(dir, "B.crt")
	receiver.Key = filepath.Join(dir, "B.key")
	receiver.Output = filepath.Join(base, "receipt.json")
	state := filepath.Join(base, "replay-ledger")
	ready := make(chan labReady, 1)
	done := make(chan error, 1)
	go func() { done <- offlineListen(ctx, receiver, challengePath, state, 3*time.Second, ready) }()
	var r labReady
	select {
	case r = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	sender.DataPort = r.DataPort
	gotRun, err := offlineSend(ctx, sender, challengePath)
	if err != nil {
		t.Fatal(err)
	}
	if gotRun != signed.Challenge.RunID {
		t.Fatal("wrong offline run ID")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	result, err := verifyOfflinePair(challengePath, receiver.Output, ca)
	if err != nil {
		t.Fatal(err)
	}
	if result["authenticated_peer_observations"] != 1 {
		t.Fatalf("wrong observed count: %+v", result)
	}
	if err := offlineListen(ctx, receiver, challengePath, state, time.Second, nil); err == nil {
		t.Fatal("offline run ledger failed to reject replay")
	}
	// Even a signed receipt is not accepted against a different independently signed challenge.
	wrong := signed
	wrong.Challenge.RunID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	identity, err := tls.LoadX509KeyPair(filepath.Join(dir, "A.crt"), filepath.Join(dir, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err = signedChallengeFor(wrong.Challenge, identity)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(base, "wrong.json")
	if err := saveNewJSON(wrongPath, wrong); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOfflinePair(wrongPath, receiver.Output, ca); err == nil {
		t.Fatal("mismatched challenge accepted")
	}
	b, err := os.ReadFile(receiver.Output)
	if err != nil {
		t.Fatal(err)
	}
	var rec labEnvelope
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Receipt.Observations[0].PolicyEpoch = "tampered"
	bad := filepath.Join(base, "receipt-bad.json")
	if err := saveNewJSON(bad, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOfflinePair(challengePath, bad, ca); err == nil {
		t.Fatal("tampered receipt accepted")
	}
}

func TestOfflineMissingObservationRemainsInconclusive(t *testing.T) {
	dir, ca := testLabCredentials(t)
	file := testSourcesFile(t, "10.90.3.100")
	base := t.TempDir()
	sender := testOpts(dir, ca, file, "A", "B")
	challenge, err := newOfflineChallenge(sender)
	if err != nil {
		t.Fatal(err)
	}
	challengePath := filepath.Join(base, "challenge.json")
	if err := saveNewJSON(challengePath, challenge); err != nil {
		t.Fatal(err)
	}
	server := testOpts(dir, ca, file, "A", "B")
	server.Cert = filepath.Join(dir, "B.crt")
	server.Key = filepath.Join(dir, "B.key")
	server.Output = filepath.Join(base, "receipt.json")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	r := make(chan labReady, 1)
	done := make(chan error, 1)
	go func() {
		done <- offlineListen(ctx, server, challengePath, filepath.Join(base, "ledger"), time.Second, r)
	}()
	select {
	case <-r:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	summary, err := verifyOfflinePair(challengePath, server.Output, ca)
	if err != nil {
		t.Fatal(err)
	}
	if summary["authenticated_peer_observations"] != 0 {
		t.Fatal("missing peer observation mislabeled as delivery")
	}
}
