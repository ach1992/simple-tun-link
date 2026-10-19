package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Automated Field protocol regression checks. These verify offline invariants,
// not public-network source admission or real two-host reachability.
func TestFieldSignedPlanGrantAndPacket(t *testing.T) {
	base := t.TempDir()
	identity := filepath.Join(base, "credentials")
	if err := createFieldIdentity(identity); err != nil {
		t.Fatal(err)
	}
	inv := CandidateFile{SchemaVersion: schema, Mode: "field_candidates",
		Candidates: []Candidate{{IP: "10.40.0.7", Direction: "A_TO_B", Sender: "A", Receiver: "B"}}}
	file := filepath.Join(base, "sources.json")
	if err := writeCandidateInventory(file, inv); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(identity, "ca.crt")
	plan, err := newFieldChallenge(fieldOptions{File: file, Cert: filepath.Join(identity, "A.crt"),
		Key: filepath.Join(identity, "A.key"), CA: ca, Sender: "A", Receiver: "B", Transport: "field_raw_ipv4",
		DestinationIP: "10.40.0.8", DataPort: 24572, PacketSize: 192, Epoch: "test", TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	challenge := filepath.Join(base, "challenge.json")
	if err := saveNewJSON(challenge, plan); err != nil {
		t.Fatal(err)
	}
	granted, err := newFieldGrantWithDestinationOwnership(fieldOptions{File: file, Cert: filepath.Join(identity, "B.crt"),
		Key: filepath.Join(identity, "B.key"), CA: ca, Sender: "A", Receiver: "B", Challenge: challenge}, func(ip string) error {
		if ip != "10.40.0.8" {
			return errors.New("destination is not on the test-owned allowlist")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFieldGrant(granted, plan.Challenge, roots, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	senderCert, err := loadFieldCredential(filepath.Join(identity, "A.crt"), filepath.Join(identity, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := makeFieldPacket(plan.Challenge, plan.Challenge.Samples[0], senderCert.PrivateKey.(ed25519.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(senderCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := verifyFieldPacket(packet, plan.Challenge, leaf.PublicKey.(ed25519.PublicKey), map[int]bool{}); !ok {
		t.Fatal("signed field packet rejected")
	}
	packet[42] ^= 1
	if _, ok := verifyFieldPacket(packet, plan.Challenge, leaf.PublicKey.(ed25519.PublicKey), map[int]bool{}); ok {
		t.Fatal("tampered field packet admitted")
	}
}

func TestFieldRawIPv4PacketIsBoundedToSelectedAddressAndPeer(t *testing.T) {
	payload := make([]byte, 192)
	packet, addr, err := makeRawFieldIPv4Packet("10.40.0.7", "10.40.0.8", 24572, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 220 || packet[0] != 0x45 || packet[9] != 17 ||
		!net.IP(packet[12:16]).Equal(net.ParseIP("10.40.0.7").To4()) ||
		!net.IP(packet[16:20]).Equal(net.ParseIP("10.40.0.8").To4()) ||
		binary.BigEndian.Uint16(packet[22:24]) != 24572 || addr.Port != 0 {
		t.Fatal("raw field packet shape or signed destination mismatch")
	}
	if _, _, err := makeRawFieldIPv4Packet("203.0.113.1", "10.40.0.8", 24572, payload); err == nil {
		t.Fatal("documentation-only address accepted")
	}
}

func TestFieldRunReplayLedgerRejectsDuplicate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-state")
	if err := fieldRunLedger(dir, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := fieldRunLedger(dir, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("replayed run admitted")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("state directory not private")
	}
}
