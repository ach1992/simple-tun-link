//go:build linux

package main

import (
	"crypto/tls"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsolatedIPv6RouteRejectAndEgress(t *testing.T) {
	zero := strings.Repeat("0", 32)
	safe := zero + " 00 " + zero + " 00 " + zero + " ffffffff 00000001 00000000 00200200 lo"
	if err := validateIsolatedIPv6Routes(safe); err != nil {
		t.Fatal("kernel reject default wrongly classified as egress:", err)
	}
	for _, bad := range []string{
		zero + " 00 " + zero + " 00 " + zero + " 00000064 00000000 00000000 00000003 sdgb0",
		zero + " 00 " + zero + " 00 " + zero + " ffffffff 00000001 00000000 00200200 sdgb0",
		zero + " 00 " + zero + " 00 " + zero + " ffffffff 00000001 00000000 00000000 lo",
	} {
		if err := validateIsolatedIPv6Routes(bad); err == nil {
			t.Fatal("real/default IPv6 route allowed", bad)
		}
	}
}

func TestRawPrivatePacketHeader(t *testing.T) {
	src := netip.MustParseAddr("10.91.1.77")
	dst := netip.MustParseAddr("10.91.2.2")
	payload := make([]byte, 192)
	packet, err := makeRawIPv4UDPPacket(src, dst, 24572, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 220 || packet[0] != 0x45 || packet[9] != 17 || binary.BigEndian.Uint16(packet[2:4]) != 220 {
		t.Fatal("incorrect signed UDP IPv4 frame layout")
	}
	if string(netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}).String()) != src.String() {
		t.Fatal("source differs from exactly planned private IP")
	}
	if binary.BigEndian.Uint16(packet[22:24]) != 24572 || binary.BigEndian.Uint16(packet[24:26]) != 200 {
		t.Fatal("incorrect destination port or UDP length")
	}
	for _, c := range []struct {
		src, dst   string
		port, size int
	}{
		{"8.8.8.8", "10.91.2.2", 24572, 192},
		{"10.91.1.77", "1.1.1.1", 24572, 192},
		{"10.91.1.77", "10.91.2.2", 53, 192},
		{"10.91.1.77", "10.91.2.2", 24572, 2000},
	} {
		if _, err := makeRawIPv4UDPPacket(netip.MustParseAddr(c.src), netip.MustParseAddr(c.dst), c.port, make([]byte, c.size)); err == nil {
			t.Fatalf("unsafe network packet accepted: %+v", c)
		}
	}
}

func TestNetnsRawRefusesHostNetworkNamespace(t *testing.T) {
	// This test creates NO socket or kernel network resources.
	if err := requireIsolatedPrivateNamespace("sdga0", "10.91.2.2"); err == nil {
		t.Fatal("isolated raw adapter unexpectedly passed in ordinary host namespace")
	}
	if err := requireIsolatedPrivateNamespace("eth0", "10.91.2.2"); err == nil {
		t.Fatal("non-lab interface allowed")
	}
	if err := requireIsolatedPrivateNamespace("sdga0", "9.9.9.9"); err == nil {
		t.Fatal("public destination allowed")
	}
}

func TestSignedPrivateRawEvidenceSourceBinding(t *testing.T) {
	dir, ca := testLabCredentials(t)
	allowed := testSourcesFile(t, "10.91.1.77")
	o := testOpts(dir, ca, allowed, "A", "B")
	o.Transport = "isolated_private_raw"
	o.DestinationIP = "10.91.2.2"
	signed, err := newOfflineChallenge(o)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Challenge.Environment != "isolated_private_raw" || signed.Challenge.DestinationIP != o.DestinationIP {
		t.Fatal("private raw plan is not bound to peer destination")
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := challengeSignerCertificate(signed, roots, time.Now()); err != nil {
		t.Fatal(err)
	}
	signed.Challenge.DestinationIP = "10.91.2.3"
	if _, err := challengeSignerCertificate(signed, roots, time.Now()); err == nil {
		t.Fatal("signed destination was modified without detection")
	}
	signed, err = newOfflineChallenge(o)
	if err != nil {
		t.Fatal(err)
	}
	bCert, err := tls.LoadX509KeyPair(filepath.Join(dir, "B.crt"), filepath.Join(dir, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	r := labReceipt{
		SchemaVersion: schema, Environment: "isolated_private_raw", RunID: signed.Challenge.RunID,
		Observer: "spoofdiag-b.local", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: 1, ChallengeDigest: offlineChallengeDigest(signed.Challenge),
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED", ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
		Observations: []labSeen{{Index: 0, SourceCandidate: "10.91.1.77", ActualPacketSource: "10.91.1.77", PacketSize: 192, PolicyEpoch: "loopback-test", Direction: "A_TO_B", Authenticated: true}},
	}
	env, err := signLabReceipt(r, bCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLabReceipt(env, roots, "spoofdiag-b.local", signed.Challenge.RunID, time.Now()); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	ch := filepath.Join(tmp, "signed-challenge.json")
	receipt := filepath.Join(tmp, "signed-receipt.json")
	if err := saveNewJSON(ch, signed); err != nil {
		t.Fatal(err)
	}
	if err := saveNewJSON(receipt, env); err != nil {
		t.Fatal(err)
	}
	answer, err := verifyOfflinePair(ch, receipt, ca)
	if err != nil {
		t.Fatal(err)
	}
	if answer["result"] != "AUTHENTICATED_PRIVATE_NETNS_PEER_INGRESS_OBSERVED" {
		t.Fatalf("incorrect raw lab classification: %+v", answer)
	}
	r.Observations[0].ActualPacketSource = "10.91.1.2"
	env, err = signLabReceipt(r, bCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLabReceipt(env, roots, "spoofdiag-b.local", signed.Challenge.RunID, time.Now()); err == nil {
		t.Fatal("signed packet from different actual source accepted as forged-IP admission")
	}
	r.Observations[0].ActualPacketSource = "10.91.1.77"
	r.Environment = "approved_field"
	env, err = signLabReceipt(r, bCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLabReceipt(env, roots, "spoofdiag-b.local", signed.Challenge.RunID, time.Now()); err == nil {
		t.Fatal("receipt attempted to overclaim field provenance")
	}
	if err := os.Chmod(filepath.Join(dir, "A.key"), 0600); err != nil {
		t.Fatal(err)
	}
}
