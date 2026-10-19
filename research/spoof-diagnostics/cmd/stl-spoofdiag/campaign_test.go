package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests perform cryptographic, filesystem, fault and campaign checks
// ONLY. No interfaces, sockets, raw packets, network namespaces or peers run.
func testCampaignIdentity(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "identity")
	if err := createFieldIdentity(dir); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, "ca.crt")
}

func testCandidateInventory(t *testing.T, count int, dest string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "owned-ip-list.json")
	cfg := CandidateFile{SchemaVersion: schema, Mode: "field_candidates"}
	for i := 0; i < count; i++ {
		cfg.Candidates = append(cfg.Candidates, Candidate{
			IP: fmt.Sprintf("10.91.%d.%d", i/250, i%250+1), Direction: "A_TO_B", Sender: "A", Receiver: "B",
		})
	}
	if err := writeCandidateInventory(file, cfg); err != nil {
		t.Fatal(err)
	}
	return file
}

func testCampaignSettings() campaignManifest {
	return campaignManifest{Direction: "A_TO_B", DestinationIP: "10.99.0.2",
		Transport: "field_raw_ipv4", DataPort: 24572, PacketSize: 192,
		BatchSize: 32, SamplesPerSource: 5, TTLSeconds: 600, Epoch: "unit-owned"}
}

func TestCampaignThousandsOfExactIPsPartitionOffline(t *testing.T) {
	source := testCandidateInventory(t, 1536, "10.99.0.2")
	dir := filepath.Join(t.TempDir(), "campaign")
	m, err := createCampaign(source, dir, testCampaignSettings())
	if err != nil {
		t.Fatal(err)
	}
	if m.SourceCount != 1536 || len(m.Batches) != 48 {
		t.Fatalf("unexpected batches %+v", m)
	}
	got, err := readCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.CampaignID != m.CampaignID || got.SourceDigest != m.SourceDigest {
		t.Fatal("campaign integrity not preserved")
	}
	for _, batch := range got.Batches {
		if batch.Count != 32 {
			t.Fatalf("unbounded or underfilled batch: %+v", batch)
		}
	}
	if _, err := createCampaign(source, dir, testCampaignSettings()); err == nil {
		t.Fatal("existing campaign overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "runs", "batch-00001")); !os.IsNotExist(err) {
		t.Fatal("offline preparation created a network run")
	}
}

func TestCampaignNextNeedsIndependentReceiptAndResumesOffline(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	source := testCandidateInventory(t, 65, "10.99.0.2")
	dir := filepath.Join(t.TempDir(), "campaign")
	m, err := createCampaign(source, dir, testCampaignSettings())
	if err != nil {
		t.Fatal(err)
	}
	aCert := filepath.Join(ids, "A.crt")
	aKey := filepath.Join(ids, "A.key")
	first, err := campaignNext(dir, aCert, aKey, ca, false)
	if err != nil {
		t.Fatal(err)
	}
	if first["status"] != "AWAITING_INDEPENDENT_RECEIVER_GRANT" || first["batch"] != 1 {
		t.Fatalf("first batch not prepared: %+v", first)
	}
	same, err := campaignNext(dir, aCert, aKey, ca, true)
	if err != nil {
		t.Fatal(err)
	}
	if same["attempt"] != 1 {
		t.Fatalf("unexpired run was silently retried: %+v", same)
	}
	challengePath := filepath.Join(campaignAttemptDir(dir, 1, 1), "challenge.json")
	plan, err := readSignedFieldChallenge(challengePath)
	if err != nil || len(plan.Challenge.Samples) != 160 {
		t.Fatalf("not a bounded, freshly signed batch: %v", err)
	}
	batchFile := filepath.Join(dir, m.Batches[0].File)
	g, err := newFieldGrantWithDestinationOwnership(fieldOptions{
		File: batchFile, Challenge: challengePath, Cert: filepath.Join(ids, "B.crt"),
		Key: filepath.Join(ids, "B.key"), CA: ca, Sender: "A", Receiver: "B",
	}, func(ip string) error {
		if ip != "10.99.0.2" {
			return errors.New("wrong fixture destination")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	grantPath := filepath.Join(campaignAttemptDir(dir, 1, 1), "grant.json")
	if err := saveNewJSON(grantPath, g); err != nil {
		t.Fatal(err)
	}
	b, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	firstSample := plan.Challenge.Samples[0]
	receipt := fieldReceipt{SchemaVersion: schema, Environment: plan.Challenge.Environment,
		RunID: plan.Challenge.RunID, Observer: roleName("B"), Status: "COMPLETE",
		CreatedUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: len(plan.Challenge.Samples), ChallengeDigest: fieldChallengeDigest(plan.Challenge),
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
		Observations: []fieldSeen{{Index: firstSample.Index, SourceCandidate: firstSample.Candidate.IP,
			ActualPacketSource: firstSample.Candidate.IP, PacketSize: firstSample.Size,
			Direction: firstSample.Candidate.Direction, PolicyEpoch: firstSample.Epoch,
			Authenticated: true, SourceMatched: true}},
	}
	env, err := signFieldReceipt(receipt, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveNewJSON(filepath.Join(campaignAttemptDir(dir, 1, 1), "receipt.json"), env); err != nil {
		t.Fatal(err)
	}
	// B's signed receipt alone must NOT advance an unattempted campaign.
	pending, err := campaignNext(dir, aCert, aKey, ca, false)
	if err != nil || pending["batch"] != 1 {
		t.Fatalf("receipt without sender proof skipped an unattempted batch: %+v %v", pending, err)
	}
	// Offline/injected sender evidence, never a network syscall.
	senderCert, err := loadFieldCredential(aCert, aKey)
	if err != nil {
		t.Fatal(err)
	}
	senderPath := filepath.Join(campaignAttemptDir(dir, 1, 1), "sender.json")
	senderEvidence := newSenderEvidence(plan.Challenge)
	if err := signedSenderSnapshot(senderPath, senderEvidence, senderCert, false); err != nil {
		t.Fatal(err)
	}
	if _, err := submitFieldRun(plan.Challenge, &senderEvidence, senderCert, senderPath,
		func(fieldSample, []byte) error { return nil }, func() error { return nil }); err != nil {
		t.Fatalf("offline sender evidence failed: %v", err)
	}
	next, err := campaignNext(dir, aCert, aKey, ca, false)
	if err != nil {
		t.Fatal(err)
	}
	if next["batch"] != 2 || next["attempt"] != 1 {
		t.Fatalf("did not advance only after both signatures: %+v", next)
	}
	report, err := campaignReport(dir, ca)
	if err != nil {
		t.Fatal(err)
	}
	if report["completed_batches"] != 1 || report["pending_batches"] != 2 ||
		report["source_count"] != 65 || report["return_path"] != "NOT_TESTED" {
		t.Fatalf("report confuses partial observation with completed network: %+v", report)
	}
	batchBytes, err := os.ReadFile(batchFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(batchFile, append(batchBytes, 'x'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := campaignReport(dir, ca); err == nil {
		t.Fatal("modified immutable campaign batch accepted")
	}
}

func TestSenderPartialSignedEvidenceSurvivesInjectedFailure(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	sources := testCandidateInventory(t, 3, "10.99.0.2")
	ch, err := newFieldChallenge(fieldOptions{File: sources,
		Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"),
		CA: ca, Sender: "A", Receiver: "B", DestinationIP: "10.99.0.2",
		DataPort: 24572, PacketSize: 192, SamplesPerSource: 1, TTLSeconds: 600,
		Transport: "field_raw_ipv4", Epoch: "unit-owned"})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := loadFieldCredential(filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sender.json")
	ev := newSenderEvidence(ch.Challenge)
	if err := signedSenderSnapshot(path, ev, cred, false); err != nil {
		t.Fatal(err)
	}
	sends := 0
	n, err := submitFieldRun(ch.Challenge, &ev, cred, path, func(sample fieldSample, pkt []byte) error {
		sends++
		if sample.Index == 2 {
			return errors.New("INJECTED_FAILURE")
		}
		if len(pkt) != sample.Size {
			t.Fatal("sample corrupted")
		}
		return nil
	}, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "INJECTED_FAILURE") || n != 2 || sends != 3 {
		t.Fatalf("wrong partial run error and count: n=%d sends=%d err=%v", n, sends, err)
	}
	summary, err := verifySenderEvidence(path, ch.Challenge, ca)
	if err != nil {
		t.Fatal(err)
	}
	if summary["status"] != "PARTIAL" || summary["syscalls_succeeded"] != 2 ||
		summary["failed"] != 1 || summary["not_attempted"] != 0 {
		t.Fatalf("partial evidence lost or overclaims: %+v", summary)
	}
	if err := signedSenderSnapshot(path, ev, cred, false); err == nil {
		t.Fatal("another run overwrote the first signed sender report")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(contents, []byte("PARTIAL"), []byte("COMPLETE"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySenderEvidence(path, ch.Challenge, ca); err == nil {
		t.Fatal("altered sender evidence accepted")
	}
}

func TestSenderSuccessOfflineWithoutNetworkSyscall(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	sources := testCandidateInventory(t, 2, "")
	ch, err := newFieldChallenge(fieldOptions{File: sources,
		Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"),
		CA: ca, Sender: "A", Receiver: "B", DestinationIP: "10.99.0.2",
		DataPort: 24572, PacketSize: 192, SamplesPerSource: 2, TTLSeconds: 600,
		Transport: "field_raw_ipv4", Epoch: "unit-owned"})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := loadFieldCredential(filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "success.json")
	ev := newSenderEvidence(ch.Challenge)
	if err := signedSenderSnapshot(path, ev, cred, false); err != nil {
		t.Fatal(err)
	}
	var indices []int
	n, err := submitFieldRun(ch.Challenge, &ev, cred, path, func(s fieldSample, b []byte) error {
		indices = append(indices, s.Index)
		return nil
	}, func() error { return nil })
	if err != nil || n != 4 || !reflect.DeepEqual(indices, []int{0, 1, 2, 3}) {
		t.Fatalf("offline success mismatch: n=%d err=%v indices=%v", n, err, indices)
	}
	result, err := verifySenderEvidence(path, ch.Challenge, ca)
	if err != nil || result["status"] != "COMPLETE" || result["syscalls_succeeded"] != 4 {
		t.Fatalf("completion not verifiable: result=%+v err=%v", result, err)
	}
}

func TestForwardedReceiverConsentSignedBoundIP(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	sources := testCandidateInventory(t, 1, "")
	ch, err := newFieldChallenge(fieldOptions{File: sources,
		Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"), CA: ca,
		Sender: "A", Receiver: "B", DestinationIP: "10.99.0.2",
		DataPort: 24572, PacketSize: 192, TTLSeconds: 600,
		Transport: "field_udp_bound", Epoch: "unit"})
	if err != nil {
		t.Fatal(err)
	}
	chPath := filepath.Join(t.TempDir(), "challenge.json")
	if err := saveNewJSON(chPath, ch); err != nil {
		t.Fatal(err)
	}
	o := fieldOptions{File: sources, Cert: filepath.Join(ids, "B.crt"),
		Key: filepath.Join(ids, "B.key"), CA: ca, Challenge: chPath,
		Sender: "A", Receiver: "B", BindIP: "10.95.0.3"}
	localOwned := func(ip string) error {
		if ip != "10.95.0.3" {
			return errors.New("not assigned")
		}
		return nil
	}
	if _, err := newFieldGrantWithDestinationOwnership(o, localOwned); err == nil {
		t.Fatal("forwarded destination without explicit receiver consent accepted")
	}
	o.ForwardedDestination = true
	grant, err := newFieldGrantWithDestinationOwnership(o, localOwned)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Grant.BindIP != "10.95.0.3" {
		t.Fatal("receiver-local NAT bind not signed")
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFieldGrant(grant, ch.Challenge, roots, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	grant.Grant.BindIP = "10.95.0.4"
	if err := checkFieldGrant(grant, ch.Challenge, roots, time.Now(), true); err == nil {
		t.Fatal("tampered receiver bind IP accepted")
	}
}

func TestReceiverSnapshotDurabilityOffline(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	sources := testCandidateInventory(t, 1, "")
	ch, err := newFieldChallenge(fieldOptions{File: sources,
		Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"), CA: ca,
		Sender: "A", Receiver: "B", DestinationIP: "10.99.0.2",
		DataPort: 24572, PacketSize: 192, TTLSeconds: 600, Transport: "field_raw_ipv4", Epoch: "unit"})
	if err != nil {
		t.Fatal(err)
	}
	gPath := filepath.Join(t.TempDir(), "grant.json")
	chPath := filepath.Join(t.TempDir(), "challenge.json")
	if err := saveNewJSON(chPath, ch); err != nil {
		t.Fatal(err)
	}
	grant, err := newFieldGrantWithDestinationOwnership(fieldOptions{
		File: sources, Cert: filepath.Join(ids, "B.crt"), Key: filepath.Join(ids, "B.key"),
		CA: ca, Sender: "A", Receiver: "B", Challenge: chPath,
	}, func(ip string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := saveNewJSON(gPath, grant); err != nil {
		t.Fatal(err)
	}
	b, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := fieldReceipt{SchemaVersion: schema, Environment: ch.Challenge.Environment,
		RunID: ch.Challenge.RunID, Observer: roleName("B"), Status: "IN_PROGRESS",
		CreatedUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: len(ch.Challenge.Samples), ChallengeDigest: fieldChallengeDigest(ch.Challenge),
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED"}
	path := filepath.Join(t.TempDir(), "receipt.json")
	publish := func(replace bool) {
		t.Helper()
		receipt.CreatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		env, err := signFieldReceipt(receipt, b)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeStagedJSON(path, env, replace); err != nil {
			t.Fatal(err)
		}
	}
	publish(false)
	result, err := verifyFieldPair(chPath, gPath, path, ca)
	if err != nil || result["receiver_status"] != "IN_PROGRESS" {
		t.Fatalf("bad initial signed snapshot: %v %+v", err, result)
	}
	sample := ch.Challenge.Samples[0]
	receipt.Observations = append(receipt.Observations, fieldSeen{
		Index: 0, SourceCandidate: sample.Candidate.IP, ActualPacketSource: sample.Candidate.IP,
		PacketSize: sample.Size, Direction: sample.Candidate.Direction, PolicyEpoch: sample.Epoch,
		Authenticated: true, SourceMatched: true})
	publish(true)
	result, err = verifyFieldPair(chPath, gPath, path, ca)
	if err != nil || result["peer_authenticated_received"] != 1 || result["receiver_status"] != "IN_PROGRESS" {
		t.Fatalf("durable partial receipt vanished: %v %+v", err, result)
	}
	receipt.Status = "COMPLETE"
	publish(true)
	result, err = verifyFieldPair(chPath, gPath, path, ca)
	if err != nil || result["receiver_status"] != "COMPLETE" {
		t.Fatal(err)
	}
	// No unverified details are promoted into NIC egress, provider or return proof.
	if result["return_to_sender"] != "NOT_TESTED" {
		t.Fatal("false return proof")
	}
}

func TestJSONEvidenceStagedExclusiveAndRestricted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.json")
	v := map[string]any{"schema": schema}
	if err := saveNewJSON(path, v); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("artifact not private")
	}
	if err := saveNewJSON(path, v); err == nil {
		t.Fatal("duplicate artifact replaced")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := writeStagedJSON(link, v, true); err == nil {
		t.Fatal("symlink target overwritten")
	}
	if err := writeStagedJSON(path, map[string]any{"changed": true}, true); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded["changed"] != true {
		t.Fatal("atomic evidence mismatch")
	}
}

// Ensure the sender evidence signature is tied to a real grant identity
// under the same CA; sender records never claim independent network proof.
func TestSenderEvidenceWrongSignerRejected(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	sources := testCandidateInventory(t, 1, "")
	ch, err := newFieldChallenge(fieldOptions{File: sources, Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"),
		CA: ca, Sender: "A", Receiver: "B", Transport: "field_raw_ipv4", DestinationIP: "10.99.0.2",
		DataPort: 24572, PacketSize: 192, TTLSeconds: 600, Epoch: "unit"})
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := signSenderEvidence(newSenderEvidence(ch.Challenge), wrong)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wrong.json")
	if err := saveNewJSON(path, env); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySenderEvidence(path, ch.Challenge, ca); err == nil {
		t.Fatal("wrong sender identity accepted")
	}
}

func TestRawIPv4UDPChecksumMatchesSignedSource(t *testing.T) {
	for _, size := range []int{128, 193, 1200} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		packet, _, err := makeRawFieldIPv4Packet("10.93.7.2", "10.95.3.8", 24572, payload)
		if err != nil {
			t.Fatal(err)
		}
		if packet[26] == 0 && packet[27] == 0 {
			t.Fatal("raw IPv4 UDP checksum missing")
		}
		if got := ipv4UDPChecksum(packet[12:16], packet[16:20], packet[20:]); got != 0xffff {
			t.Fatalf("size %d invalid on-wire checksum: %x", size, got)
		}
		packet[len(packet)-1] ^= 0x30
		if got := ipv4UDPChecksum(packet[12:16], packet[16:20], packet[20:]); got == 0xffff {
			t.Fatalf("size %d altered raw payload still passes checksum", size)
		}
	}
}

func TestCampaignExpiredRunRequiresExplicitFreshGrant(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	src := testCandidateInventory(t, 1, "")
	dir := filepath.Join(t.TempDir(), "campaign")
	if _, err := createCampaign(src, dir, testCampaignSettings()); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(ids, "A.crt")
	keyPath := filepath.Join(ids, "A.key")
	first, err := campaignNext(dir, certPath, keyPath, ca, false)
	if err != nil || first["attempt"] != 1 {
		t.Fatalf("first attempt: %v %+v", err, first)
	}
	path := filepath.Join(campaignAttemptDir(dir, 1, 1), "challenge.json")
	signed, err := readSignedFieldChallenge(path)
	if err != nil {
		t.Fatal(err)
	}
	oldRun := signed.Challenge.RunID
	now := time.Now().UTC()
	signed.Challenge.CreatedUTC = now.Add(-3 * time.Minute).Format(time.RFC3339Nano)
	signed.Challenge.ExpiresUnix = now.Add(-2 * time.Minute).Unix()
	cred, err := loadFieldCredential(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pem, signature, err := signatureFromCredential(signed.Challenge, cred)
	if err != nil {
		t.Fatal(err)
	}
	signed.SenderCertificatePEM, signed.SignatureHex = pem, signature
	if err := writeStagedJSON(path, signed, true); err != nil {
		t.Fatal(err)
	}
	pending, err := campaignNext(dir, certPath, keyPath, ca, false)
	if err != nil || pending["status"] != "EXPIRED_REVIEW_EVIDENCE_THEN_RETRY_EXPLICITLY" {
		t.Fatalf("expired campaign silently resumed or incorrectly described: %v %+v", err, pending)
	}
	again, err := campaignNext(dir, certPath, keyPath, ca, true)
	if err != nil || again["attempt"] != 2 {
		t.Fatalf("fresh attempt was not created: %v %+v", err, again)
	}
	fresh, err := readSignedFieldChallenge(filepath.Join(campaignAttemptDir(dir, 1, 2), "challenge.json"))
	if err != nil || fresh.Challenge.RunID == oldRun {
		t.Fatal("new attempt reused consumed/expired run")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("old signed challenge was erased")
	}
}

func TestCampaignExplicitSendCannotSkipReceiverGrant(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	source := testCandidateInventory(t, 36, "")
	dir := filepath.Join(t.TempDir(), "campaign")
	if _, err := createCampaign(source, dir, testCampaignSettings()); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key")
	if _, err := campaignNext(dir, certPath, keyPath, ca, false); err != nil {
		t.Fatal(err)
	}
	status, err := campaignSend(context.Background(), dir, certPath, keyPath, ca, "synthetic-no-socket", true)
	if err != nil || status["status"] != "WAITING_FOR_RECEIVER_SIGNED_GRANT" {
		t.Fatalf("unconsented raw batch not held: %+v %v", status, err)
	}
	if _, err := os.Lstat(filepath.Join(campaignAttemptDir(dir, 1, 1), "sender.json")); !os.IsNotExist(err) {
		t.Fatal("a sender report or syscall was started without B's grant")
	}
	// Presence of the B signed grant does not waive separate provider rights.
	chPath := filepath.Join(campaignAttemptDir(dir, 1, 1), "challenge.json")
	grant, err := newFieldGrantWithDestinationOwnership(fieldOptions{
		File: filepath.Join(dir, "batches", "batch-00001.json"), Challenge: chPath,
		Cert: filepath.Join(ids, "B.crt"), Key: filepath.Join(ids, "B.key"),
		CA: ca, Sender: "A", Receiver: "B",
	}, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := saveNewJSON(filepath.Join(campaignAttemptDir(dir, 1, 1), "grant.json"), grant); err != nil {
		t.Fatal(err)
	}
	// A signed grant is insufficient until B's post-bind readiness is supplied.
	pending, err := campaignSend(context.Background(), dir, certPath, keyPath, ca, "synthetic-no-socket", true)
	if err != nil || pending["status"] != "WAITING_FOR_SIGNED_RECEIVER_READY" {
		t.Fatalf("missing signed readiness was not fail-closed: %+v %v", pending, err)
	}
	ch, err := readSignedFieldChallenge(chPath)
	if err != nil {
		t.Fatal(err)
	}
	bCert, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	// Pure signed-data fixture only: NO socket bind/packet/network test.
	ready, err := newSignedFieldReady(ch.Challenge, grant.Grant, ch.Challenge.DestinationIP,
		time.Now().Add(80*time.Second), bCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveNewJSON(filepath.Join(campaignAttemptDir(dir, 1, 1), "ready.json"), ready); err != nil {
		t.Fatal(err)
	}
	if _, err := campaignSend(context.Background(), dir, certPath, keyPath, ca, "", false); err == nil {
		t.Fatal("raw source test was admitted without authorization acknowledgement")
	}
	if _, err := os.Lstat(filepath.Join(campaignAttemptDir(dir, 1, 1), "sender.json")); !os.IsNotExist(err) {
		t.Fatal("unapproved source attempted")
	}
}

func TestCampaignNextSerializesConcurrentMutations(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	dir := filepath.Join(t.TempDir(), "campaign")
	src := testCandidateInventory(t, 2, "")
	if _, err := createCampaign(src, dir, testCampaignSettings()); err != nil {
		t.Fatal(err)
	}
	lock, err := os.Open(filepath.Join(dir, "campaign.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, err := campaignNext(dir, filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"), ca, false); err == nil {
		t.Fatal("campaign mutated while an existing exclusive lock was held")
	}
	if _, err := os.Lstat(filepath.Join(dir, "runs", "batch-00001")); !os.IsNotExist(err) {
		t.Fatal("concurrent campaign action created a partial run")
	}
}

// Offline cryptographic negative controls for the new B post-bind readiness
// artifact. It is never coupled to an actual listener or socket in these tests.
func TestSignedReceiverReadinessRejectsTamperingExpiryAndWrongSigner(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	sources := testCandidateInventory(t, 1, "")
	ch, err := newFieldChallenge(fieldOptions{File: sources,
		Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"), CA: ca,
		Sender: "A", Receiver: "B", DestinationIP: "10.99.0.2", DataPort: 24572,
		Transport: "field_udp_bound", PacketSize: 192, TTLSeconds: 600, Epoch: "unit"})
	if err != nil {
		t.Fatal(err)
	}
	chPath := filepath.Join(t.TempDir(), "challenge.json")
	if err := saveNewJSON(chPath, ch); err != nil {
		t.Fatal(err)
	}
	grant, err := newFieldGrantWithDestinationOwnership(fieldOptions{
		File: sources, Challenge: chPath, Cert: filepath.Join(ids, "B.crt"),
		Key: filepath.Join(ids, "B.key"), CA: ca, Sender: "A", Receiver: "B",
	}, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	ready, err := newSignedFieldReady(ch.Challenge, grant.Grant, ch.Challenge.DestinationIP,
		time.Now().Add(90*time.Second), b)
	if err != nil {
		t.Fatal(err)
	}
	save := func(label string, obj signedFieldReady) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), label+".json")
		if err := saveNewJSON(path, obj); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := save("ready", ready)
	if _, err := verifySignedFieldReady(valid, ch.Challenge, grant, ca, time.Now()); err != nil {
		t.Fatal(err)
	}
	tampered := ready
	tampered.Ready.BindIP = "10.99.0.123"
	if _, err := verifySignedFieldReady(save("tamper", tampered), ch.Challenge, grant, ca, time.Now()); err == nil {
		t.Fatal("modified receiver bind accepted without signature")
	}
	expired := ready
	expired.Ready.ExpiresUnix = time.Now().Add(-time.Second).Unix()
	pem, sig, err := signatureFromCredential(expired.Ready, b)
	if err != nil {
		t.Fatal(err)
	}
	expired.ReceiverCertificatePEM, expired.SignatureHex = pem, sig
	if _, err := verifySignedFieldReady(save("expired", expired), ch.Challenge, grant, ca, time.Now()); err == nil {
		t.Fatal("expired but properly signed receiver readiness accepted")
	}
	a, err := loadFieldCredential(filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := ready
	pem, sig, err = signatureFromCredential(wrong.Ready, a)
	if err != nil {
		t.Fatal(err)
	}
	wrong.ReceiverCertificatePEM, wrong.SignatureHex = pem, sig
	if _, err := verifySignedFieldReady(save("wrong", wrong), ch.Challenge, grant, ca, time.Now()); err == nil {
		t.Fatal("sender-signed artifact impersonated receiver readiness")
	}
}
