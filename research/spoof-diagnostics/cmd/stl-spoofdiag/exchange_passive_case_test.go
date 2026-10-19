package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Stage-3 tests use only synthetic signed evidence. No sockets/packets.
func signedPassiveFixture(t *testing.T, ids, ca, dir, destination, sourceIP string) (string, string, string) {
	t.Helper()
	sender, receiver := "A", "B"
	if dir == "B_TO_A" {
		sender, receiver = "B", "A"
	}
	base := t.TempDir()
	source := filepath.Join(base, "source.json")
	inv := CandidateFile{SchemaVersion: schema, Mode: "field_candidates", Candidates: []Candidate{
		{IP: sourceIP, Direction: dir, Sender: sender, Receiver: receiver},
	}}
	if err := writeCandidateInventory(source, inv); err != nil {
		t.Fatal(err)
	}
	ch, err := newFieldChallenge(fieldOptions{
		File: source, Sender: sender, Receiver: receiver,
		Cert: filepath.Join(ids, sender+".crt"),
		Key:  filepath.Join(ids, sender+".key"), CA: ca,
		DestinationIP: destination, DataPort: 24572,
		SamplesPerSource: 2, PacketSize: 192, Transport: "field_udp_bound",
		Epoch: "synthetic-stage3", TTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(base, "challenge.json")
	if err := saveNewJSON(plan, ch); err != nil {
		t.Fatal(err)
	}
	cred, err := loadFieldCredential(filepath.Join(ids, sender+".crt"), filepath.Join(ids, sender+".key"))
	if err != nil {
		t.Fatal(err)
	}
	ev := newSenderEvidence(ch.Challenge)
	senderFile := filepath.Join(base, "sender.json")
	if err := signedSenderSnapshot(senderFile, ev, cred, false); err != nil {
		t.Fatal(err)
	}
	if _, err := submitFieldRun(ch.Challenge, &ev, cred, senderFile,
		func(fieldSample, []byte) error { return nil },
		func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	cap, err := newPassiveCapture(receiver, destination, 24572, 120, 16)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range ch.Challenge.Samples {
		packet, err := makeFieldPacket(ch.Challenge, sample, cred.PrivateKey.(ed25519.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		if yes, err := passiveAppend(&cap, packet, sourceIP, time.Now()); err != nil || !yes {
			t.Fatal(err)
		}
	}
	cap.Status = "COMPLETE"
	cap.StopReason = "WINDOW_ENDED"
	cap.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := loadFieldCredential(filepath.Join(ids, receiver+".crt"), filepath.Join(ids, receiver+".key"))
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(base, "passive.json")
	if err := passiveSnapshot(capture, cap, b, false); err != nil {
		t.Fatal(err)
	}
	return plan, senderFile, capture
}

func TestPassiveCaseStage3FullReportAndNoReturnOverclaim(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	ap, as, ac := signedPassiveFixture(t, ids, ca, "A_TO_B", "10.40.0.8", "10.91.0.1")
	bp, bs, bc := signedPassiveFixture(t, ids, ca, "B_TO_A", "10.40.0.9", "10.91.0.2")
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caseID := "0123456789abcdef0123456789abcdef"
	report, err := passiveCaseAnalyze(caseID, ca, dir, ap, as, ac, bp, bs, bc)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "TWO_SIGNED_ONE_WAY_RUNS_NOT_RETURN_PATH_PROOF" ||
		len(report.Inputs) != 4 || len(report.PassiveInputFiles) != 6 || len(report.Directions) != 2 {
		t.Fatalf("invalid signed Case result: %+v", report)
	}
	for _, d := range report.Directions {
		if d.Status != "SIGNED_BOUNDED_RUN_NOT_CONNECTIVITY_PROOF" ||
			d.Runs[0].Observed != 2 || d.Runs[0].Submitted != 2 ||
			d.Sources[0].SourceMatched != 2 {
			t.Fatalf("unexpected directional result %+v", d)
		}
	}
	for _, ending := range []string{"-final.html", "-results.csv", "-verified.json"} {
		if _, err := os.Stat(filepath.Join(dir, "SDX-"+caseID+ending)); err != nil {
			t.Fatal(err)
		}
	}
	html, err := os.ReadFile(filepath.Join(dir, "SDX-"+caseID+"-final.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "TWO_SIGNED_ONE_WAY_RUNS_NOT_RETURN_PATH_PROOF") {
		t.Fatal("HTML final report overclaims or omitted status")
	}
	// Deterministic offline replay produces same validated reports.
	if _, err := passiveCaseAnalyze(caseID, ca, dir, ap, as, ac, bp, bs, bc); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveCaseIncompleteDirectionalInputsRefused(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	ap, as, ac := signedPassiveFixture(t, ids, ca, "A_TO_B", "10.40.0.8", "10.91.0.1")
	bp, bs, bc := signedPassiveFixture(t, ids, ca, "B_TO_A", "10.40.0.9", "10.91.0.2")
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := passiveCaseAnalyze("0123456789abcdef0123456789abcdef",
		ca, dir, ap, as, ac, bp, "", bc); err == nil {
		t.Fatal("missing B signed sender evidence created a complete case")
	}
	if _, err := passiveCaseAnalyze("0123456789abcdef0123456789abcdef",
		ca, dir, ap, as, ac, ap, bs, bc); err == nil {
		t.Fatal("wrong B_to_A role was accepted")
	}
	_ = bp
}
