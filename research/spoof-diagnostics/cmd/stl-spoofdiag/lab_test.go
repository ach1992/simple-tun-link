package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSample(index int) labSample {
	return labSample{Index: index, Candidate: Candidate{
		IP: "10.90.3.100", Direction: "A_TO_B", Sender: "A", Receiver: "B",
	}, Size: 192, Epoch: "test-epoch"}
}

func testBegin(samples []labSample) labBegin {
	return labBegin{
		Type: "begin", SchemaVersion: schema,
		RunID: strings.Repeat("a", 32), Key: strings.Repeat("b", 64),
		ExpiresUnix: time.Now().Add(time.Minute).Unix(), Samples: samples,
	}
}

func TestLabPacketAuthenticationAndReplay(t *testing.T) {
	begin := testBegin([]labSample{testSample(0)})
	p, err := makeLabPacket(begin, begin.Samples[0])
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	if _, ok := verifyLabPacket(p, begin, seen); !ok {
		t.Fatal("valid packet rejected")
	}
	if _, ok := verifyLabPacket(p, begin, seen); ok {
		t.Fatal("replayed packet accepted")
	}
	for _, offset := range []int{0, 8, 20, 24, 29, 70, len(p) - 1} {
		mod := append([]byte(nil), p...)
		mod[offset] ^= 0x01
		if _, ok := verifyLabPacket(mod, begin, map[int]bool{}); ok {
			t.Fatalf("tamper admitted at byte %d", offset)
		}
	}
	foreign := begin
	foreign.RunID = strings.Repeat("c", 32)
	if _, ok := verifyLabPacket(p, foreign, map[int]bool{}); ok {
		t.Fatal("wrong run accepted")
	}
	foreign = begin
	foreign.Samples[0].Size = 128
	if _, ok := verifyLabPacket(p, foreign, map[int]bool{}); ok {
		t.Fatal("wrong size accepted")
	}
}

func TestLabBeginBoundaries(t *testing.T) {
	allowed := CandidateFile{SchemaVersion: schema, Mode: "private_lab", Candidates: []Candidate{testSample(0).Candidate}}
	b := testBegin([]labSample{testSample(0)})
	if err := validateLabBegin(b, allowed, "A", "B", time.Now()); err != nil {
		t.Fatal(err)
	}
	var negatives = []struct {
		name   string
		mutate func(*labBegin)
	}{
		{"wrong run", func(b *labBegin) { b.RunID = "bad" }},
		{"expired", func(b *labBegin) { b.ExpiresUnix = time.Now().Add(-time.Second).Unix() }},
		{"long ttl", func(b *labBegin) { b.ExpiresUnix = time.Now().Add(time.Hour).Unix() }},
		{"bad packet size", func(b *labBegin) { b.Samples[0].Size = 1400 }},
		{"unapproved source", func(b *labBegin) { b.Samples[0].Candidate.IP = "10.90.3.250" }},
		{"wrong direction", func(b *labBegin) { b.Samples[0].Candidate.Direction = "B_TO_A" }},
		{"reindex", func(b *labBegin) { b.Samples[0].Index = 1 }},
		{"no samples", func(b *labBegin) { b.Samples = nil }},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			test := testBegin([]labSample{testSample(0)})
			tc.mutate(&test)
			if err := validateLabBegin(test, allowed, "A", "B", time.Now()); err == nil {
				t.Fatal("invalid begin admitted")
			}
		})
	}
}

func testLabCredentials(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "identity")
	if err := createLabIdentity(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "A.key"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private key permissions unsafe")
	}
	return dir, filepath.Join(dir, "ca.crt")
}

func testReceipt(run, observer string) labReceipt {
	return labReceipt{
		SchemaVersion: schema, Environment: "loopback_transport", RunID: run, Observer: observer,
		CreatedUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: 1, EgressStatus: "NOT_TESTED",
		CandidateAdmission: "NOT_TESTED", ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
		Observations: []labSeen{{
			Index: 0, SourceCandidate: "10.90.3.100", ActualPacketSource: "127.0.0.1",
			PacketSize: 192, Direction: "A_TO_B", PolicyEpoch: "epoch", Authenticated: true,
		}},
	}
}

func TestSignedLabReceiptAuthentication(t *testing.T) {
	dir, ca := testLabCredentials(t)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "B.crt"), filepath.Join(dir, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		t.Fatal(err)
	}
	run := strings.Repeat("a", 32)
	sign := func(r labReceipt) labEnvelope {
		t.Helper()
		e, err := signLabReceipt(r, cert)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	base := testReceipt(run, "spoofdiag-b.local")
	env := sign(base)
	now := time.Now()
	if err := verifyLabReceipt(env, roots, "spoofdiag-b.local", run, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*labEnvelope)
	}{
		{"changed count", func(e *labEnvelope) { e.Receipt.ExpectedSamples = 2 }},
		{"changed epoch", func(e *labEnvelope) { e.Receipt.Observations[0].PolicyEpoch = "evil" }},
		{"changed source", func(e *labEnvelope) { e.Receipt.Observations[0].SourceCandidate = "10.90.3.101" }},
		{"changed observer", func(e *labEnvelope) { e.Receipt.Observer = "spoofdiag-a.local" }},
		{"signature", func(e *labEnvelope) { e.SignatureHex = strings.Repeat("0", 128) }},
		{"injected egress claim", func(e *labEnvelope) { e.Receipt.EgressStatus = "PASS" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := sign(testReceipt(run, "spoofdiag-b.local"))
			tc.mutate(&copy)
			if err := verifyLabReceipt(copy, roots, "spoofdiag-b.local", run, now); err == nil {
				t.Fatal("tampered report verified")
			}
		})
	}
	if err := verifyLabReceipt(env, roots, "spoofdiag-a.local", run, now); err == nil {
		t.Fatal("wrong observer accepted")
	}
	if err := verifyLabReceipt(env, roots, "spoofdiag-b.local", strings.Repeat("f", 32), now); err == nil {
		t.Fatal("wrong run accepted")
	}
	if err := verifyLabReceipt(env, roots, "spoofdiag-b.local", run, now.Add(3*time.Hour)); err == nil {
		t.Fatal("stale receipt accepted")
	}
	wrong := base
	wrong.Observations = append(wrong.Observations, wrong.Observations[0])
	wrong.ExpectedSamples = 2
	if err := verifyLabReceipt(sign(wrong), roots, "spoofdiag-b.local", run, now); err == nil {
		t.Fatal("signed duplicate admitted")
	}
	if err := createLabIdentity(dir); err == nil {
		t.Fatal("overwrote keys in existing identity directory")
	}
}

func testSourcesFile(t *testing.T, ip string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sources.json")
	src := CandidateFile{SchemaVersion: schema, Mode: "private_lab", Candidates: []Candidate{
		{IP: ip, Direction: "A_TO_B", Sender: "A", Receiver: "B"},
		{IP: "10.90.3.101", Direction: "B_TO_A", Sender: "B", Receiver: "A"},
	}}
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func testOpts(dir, ca, file, sender, receiver string) labOptions {
	return labOptions{File: file, Cert: filepath.Join(dir, sender+".crt"),
		Key: filepath.Join(dir, sender+".key"), CA: ca,
		Sender: sender, Receiver: receiver, PacketSize: 192, Epoch: "loopback-test"}
}

func TestLabActualTwoAgentLoopback(t *testing.T) {
	dir, ca := testLabCredentials(t)
	file := testSourcesFile(t, "10.90.3.100")
	for _, roles := range [][2]string{{"A", "B"}, {"B", "A"}} {
		t.Run(roles[0]+"_to_"+roles[1], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			recv := testOpts(dir, ca, file, roles[0], roles[1])
			// Receiving node owns the listener certificate and private key.
			recv.Cert = filepath.Join(dir, roles[1]+".crt")
			recv.Key = filepath.Join(dir, roles[1]+".key")
			ready := make(chan labReady, 1)
			done := make(chan error, 1)
			go func() { done <- serveLab(ctx, recv, ready) }()
			var announcement labReady
			select {
			case announcement = <-ready:
			case err := <-done:
				t.Fatalf("listener failed: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			client := testOpts(dir, ca, file, roles[0], roles[1])
			client.ControlPort = announcement.ControlPort
			client.Output = filepath.Join(t.TempDir(), "receipt.json")
			env, err := runLab(ctx, client)
			if err != nil {
				t.Fatal(err)
			}
			if len(env.Receipt.Observations) != 1 || env.Receipt.Observations[0].SourceCandidate == env.Receipt.Observations[0].ActualPacketSource {
				t.Fatalf("loopback must be observed but NOT fake-source admitted: %+v", env.Receipt)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(client.Output); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWrongClientIdentityRejected(t *testing.T) {
	dir, ca := testLabCredentials(t)
	file := testSourcesFile(t, "10.90.3.100")
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	server := testOpts(dir, ca, file, "A", "B")
	server.Cert = filepath.Join(dir, "B.crt")
	server.Key = filepath.Join(dir, "B.key")
	ready := make(chan labReady, 1)
	done := make(chan error, 1)
	go func() { done <- serveLab(ctx, server, ready) }()
	var r labReady
	select {
	case r = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	client := testOpts(dir, ca, file, "A", "B")
	client.ControlPort = r.ControlPort
	client.Cert = filepath.Join(dir, "B.crt")
	client.Key = filepath.Join(dir, "B.key")
	if _, err := runLab(ctx, client); err == nil {
		t.Fatal("B certificate authenticated as A")
	}
	if err := <-done; err == nil {
		t.Fatal("server did not reject incorrect client identity")
	}
}

func TestReceiverAllowlistRejectsCandidate(t *testing.T) {
	dir, ca := testLabCredentials(t)
	serverFile := testSourcesFile(t, "10.90.3.100")
	clientFile := testSourcesFile(t, "10.90.3.200")
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	server := testOpts(dir, ca, serverFile, "A", "B")
	server.Cert = filepath.Join(dir, "B.crt")
	server.Key = filepath.Join(dir, "B.key")
	ready := make(chan labReady, 1)
	done := make(chan error, 1)
	go func() { done <- serveLab(ctx, server, ready) }()
	var r labReady
	select {
	case r = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	client := testOpts(dir, ca, clientFile, "A", "B")
	client.ControlPort = r.ControlPort
	if _, err := runLab(ctx, client); err == nil {
		t.Fatal("unapproved source was admitted by receiver")
	}
	if err := <-done; err == nil {
		t.Fatal("server did not enforce source allowlist")
	}
}

func TestInvalidReceiptJSON(t *testing.T) {
	var env labEnvelope
	if err := strictJSON([]byte(`{"receipt":{"schema_version":1},"signature_hex":"abc"} garbage`), &env); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := hex.DecodeString("gg"); err == nil {
		t.Fatal("bad hex decoder expectation")
	}
}
