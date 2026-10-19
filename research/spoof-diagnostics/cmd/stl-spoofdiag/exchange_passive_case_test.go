package main

import (
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
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

func TestPassiveCaseConflictingSourcesPreservedInFinalReports(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	abPlan, abSender, abCapture := signedPassiveFixture(t, ids, ca, "A_TO_B", "10.40.0.8", "10.91.0.1")
	baPlan, baSender, baCapture := signedPassiveFixture(t, ids, ca, "B_TO_A", "10.40.0.9", "10.91.0.2")
	capture, err := readAndVerifyPassive(abCapture, ca, "B")
	if err != nil {
		t.Fatal(err)
	}
	if capture.Status != "COMPLETE" {
		t.Fatalf("fixture receiver not COMPLETE: %s", capture.Status)
	}
	signedSenderRaw, err := readSmallRegular(abSender, fieldMaxControl)
	if err != nil {
		t.Fatal(err)
	}
	var signedSender signedFieldSenderEvidence
	if err := strictJSON(signedSenderRaw, &signedSender); err != nil {
		t.Fatal(err)
	}
	if signedSender.Evidence.Status != "COMPLETE" {
		t.Fatalf("fixture sender not COMPLETE: %s", signedSender.Evidence.Status)
	}
	// The same authenticated SDF2 sample was signed by the receiver as
	// observed from two different actual UDP source addresses.
	secondClaim := capture.Observations[0]
	secondClaim.Sequence = len(capture.Observations)
	secondClaim.ActualPacketSource = "10.88.0.17"
	secondClaim.ReceivedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	capture.Observations = append(capture.Observations, secondClaim)
	capture.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	receiver, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := passiveSnapshot(abCapture, capture, receiver, true); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id := "abcddcba0123456789abcdef01234567"
	// Exercise the actual CLI path, not only an internal reduction helper.
	if err := exchangePassiveCLI(id, ca, dir, abPlan, abSender, abCapture, baPlan, baSender, baCapture); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "SDX-"+id)
	data, err := os.ReadFile(path + "-verified.json")
	if err != nil {
		t.Fatal(err)
	}
	var report exchangeCaseReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.Status, "AMBIGUOUS") {
		t.Fatalf("Case status concealed authenticated contradiction: %s", report.Status)
	}
	if len(report.Directions) != 2 {
		t.Fatalf("expected both directions: %+v", report.Directions)
	}
	ab := report.Directions[0]
	if ab.Direction != "A_TO_B" || !strings.Contains(ab.Status, "AMBIGUOUS") {
		t.Fatalf("directional status failed to qualify conflicting evidence: %+v", ab)
	}
	if len(ab.Runs) != 1 || ab.Runs[0].Sender != "COMPLETE" || ab.Runs[0].Receiver != "COMPLETE" {
		t.Fatalf("signed complete source evidence unexpectedly missing: %+v", ab.Runs)
	}
	run := ab.Runs[0]
	if run.ConflictingObservations != 1 || run.Observed != 1 || run.Submitted != 2 ||
		!strings.Contains(run.Status, "AMBIGUOUS") {
		t.Fatalf("run concealed conflict or counted it as success: %+v", run)
	}
	if len(run.Samples) != 2 || !strings.Contains(run.Samples[0].ReceiverState, "AMBIGUOUS") ||
		run.Samples[0].ActualSource != "" || run.Samples[0].SourceMatched ||
		run.Samples[1].ReceiverState != "AUTHENTICATED_OBSERVED" {
		t.Fatalf("per-sample signed source ambiguity lost: %+v", run.Samples)
	}
	if len(run.Samples[0].ConflictingActualSources) != 2 ||
		run.Samples[0].ConflictingActualSources[0] != "10.88.0.17" ||
		run.Samples[0].ConflictingActualSources[1] != "10.91.0.1" {
		t.Fatalf("actual conflicting sources omitted from sample: %+v", run.Samples[0])
	}
	if len(ab.Sources) != 1 || ab.Sources[0].Ambiguous != 1 ||
		ab.Sources[0].Observed != 1 || ab.Sources[0].SourceMatched != 1 ||
		ab.Sources[0].ObservedWithSubmitted != 1 {
		t.Fatalf("per-source contradiction omitted or over-counted: %+v", ab.Sources)
	}
	if report.Directions[1].Status != "SIGNED_BOUNDED_RUN_NOT_CONNECTIVITY_PROOF" {
		t.Fatalf("healthy reverse direction incorrectly downgraded: %+v", report.Directions[1])
	}
	rawCSV, err := os.Open(path + "-results.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer rawCSV.Close()
	rows, err := csv.NewReader(rawCSV).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0][11] != "ambiguous_observations" ||
		rows[1][0] != "A_TO_B" || rows[1][7] != "1" || rows[1][11] != "1" ||
		rows[2][0] != "B_TO_A" || rows[2][7] != "2" || rows[2][11] != "0" {
		t.Fatalf("CSV failed to preserve exact source discrepancy: %+v", rows)
	}
	page, err := os.ReadFile(path + "-final.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), report.Status) ||
		!strings.Contains(string(page), ab.Status) ||
		!strings.Contains(string(page), run.Status) ||
		!strings.Contains(string(page), "Ambiguous") ||
		!strings.Contains(string(page), "10.88.0.17") ||
		!strings.Contains(string(page), "10.91.0.1") {
		t.Fatal("HTML concealed signed conflicting observation")
	}
	// The case report must be reproducible on byte-identical evidence.
	if _, err := passiveCaseAnalyze(id, ca, dir, abPlan, abSender, abCapture, baPlan, baSender, baCapture); err != nil {
		t.Fatalf("offline report on identical inputs changed: %v", err)
	}
}
