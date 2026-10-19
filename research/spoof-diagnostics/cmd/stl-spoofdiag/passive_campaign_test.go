package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type offlineCampaignFixture struct {
	Dir         string
	CaptureDir  string
	Manifest    campaignManifest
	Capture     passiveCapture
	SenderFiles []string
}

func makeOfflineCampaignFixture(t *testing.T, ids, ca, direction string, ipCount, batchSize, activeBatches int) offlineCampaignFixture {
	t.Helper()
	sender, receiver := "A", "B"
	destination := "10.40.0.8"
	if direction == "B_TO_A" {
		sender, receiver = "B", "A"
		destination = "10.40.0.9"
	}
	base := t.TempDir()
	source := filepath.Join(base, "source.json")
	candidates := CandidateFile{SchemaVersion: schema, Mode: "field_candidates"}
	for i := 0; i < ipCount; i++ {
		candidates.Candidates = append(candidates.Candidates, Candidate{
			IP:        "10.91.0." + string(rune('1'+i)),
			Direction: direction, Sender: sender, Receiver: receiver,
		})
	}
	if err := writeCandidateInventory(source, candidates); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "campaign")
	m, err := createCampaign(source, dir, campaignManifest{
		Direction: direction, DestinationIP: destination, Transport: "field_udp_bound",
		BatchSize: batchSize, DataPort: 24572, PacketSize: 192, SamplesPerSource: 2,
		TTLSeconds: 600, Epoch: "offline-fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	captureDir := filepath.Join(base, "captures")
	if err := os.Mkdir(captureDir, 0700); err != nil {
		t.Fatal(err)
	}
	cap, err := newPassiveCapture(receiver, destination, 24572, 120, 128)
	if err != nil {
		t.Fatal(err)
	}
	senderCert := filepath.Join(ids, sender+".crt")
	senderKey := filepath.Join(ids, sender+".key")
	senderCred, err := loadFieldCredential(senderCert, senderKey)
	if err != nil {
		t.Fatal(err)
	}
	var senderFiles []string
	for i := 0; i < activeBatches; i++ {
		b := m.Batches[i]
		if _, err := campaignNewAttempt(dir, m, b, 1, senderCert, senderKey, ca); err != nil {
			t.Fatal(err)
		}
		runDir := campaignAttemptDir(dir, b.Number, 1)
		env, err := readSignedFieldChallenge(filepath.Join(runDir, "challenge.json"))
		if err != nil {
			t.Fatal(err)
		}
		evidence := newSenderEvidence(env.Challenge)
		senderFile := filepath.Join(runDir, "sender.json")
		if err := signedSenderSnapshot(senderFile, evidence, senderCred, false); err != nil {
			t.Fatal(err)
		}
		if _, err := submitFieldRun(env.Challenge, &evidence, senderCred, senderFile,
			func(fieldSample, []byte) error { return nil }, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		senderFiles = append(senderFiles, senderFile)
		for _, sample := range env.Challenge.Samples {
			frame, err := makeFieldPacket(env.Challenge, sample, senderCred.PrivateKey.(ed25519.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			yes, err := passiveAppend(&cap, frame, sample.Candidate.IP, time.Now())
			if err != nil || !yes {
				t.Fatal(err)
			}
		}
	}
	if activeBatches > 0 {
		cap.Status = "COMPLETE"
		cap.StopReason = "WINDOW_ENDED"
		cap.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		recvCred, err := loadFieldCredential(filepath.Join(ids, receiver+".crt"), filepath.Join(ids, receiver+".key"))
		if err != nil {
			t.Fatal(err)
		}
		if err := passiveSnapshot(filepath.Join(captureDir, "capture.json"), cap, recvCred, false); err != nil {
			t.Fatal(err)
		}
	}
	return offlineCampaignFixture{Dir: dir, CaptureDir: captureDir, Manifest: m, Capture: cap, SenderFiles: senderFiles}
}

func TestOfflineMultiBatchEvidenceAndNotTestedCoverage(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	ab := makeOfflineCampaignFixture(t, ids, ca, "A_TO_B", 3, 2, 1)
	ba := makeOfflineCampaignFixture(t, ids, ca, "B_TO_A", 3, 2, 2)
	localStatus, err := campaignControlStatus(ab.Dir, ca)
	if err != nil {
		t.Fatal(err)
	}
	if localStatus["locally_complete_verified_batches"] != 1 {
		t.Fatalf("verified sender-only campaign status lost signed progress: %+v", localStatus)
	}
	preview, err := passiveCampaignPreview(ab.Dir, ab.CaptureDir, ca)
	if err != nil {
		t.Fatal(err)
	}
	if preview["status"] != "PROVISIONAL_OFFLINE_CHECKPOINT_ONLY" {
		t.Fatal("preview mislabeled final", preview)
	}
	coverage := preview["batches"].([]passiveBatchCoverage)
	if len(coverage) != 2 || coverage[0].Submitted != 4 || coverage[0].Observed != 4 ||
		coverage[1].State != "NOT_TESTED" || coverage[1].NotTested != 2 {
		t.Fatalf("stage-2 coverage incorrectly counted: %+v", coverage)
	}
	reportDir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(reportDir, 0700); err != nil {
		t.Fatal(err)
	}
	id := "aabbccddeeff00112233445566778899"
	result, err := passiveCampaignCase(id, ca, reportDir, ab.Dir, ab.CaptureDir, ba.Dir, ba.CaptureDir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "PARTIAL_OR_EARLY_STOP_WITH_UNTESTED_COVERAGE" ||
		len(result.Directions) != 2 || len(result.Directions[0].Runs) != 1 ||
		len(result.Directions[1].Runs) != 2 || len(result.PassiveBatchCoverage) != 4 {
		t.Fatalf("incorrect final multi-batch case: %+v", result)
	}
	sources := result.Directions[0].Sources
	if len(sources) != 3 || sources[2].NotTested != 2 || sources[2].Submitted != 0 {
		t.Fatalf("not-tested source incorrectly labeled: %+v", sources)
	}
	if len(result.Directions[1].Runs) != 2 || result.Directions[1].Runs[0].Observed != 4 ||
		result.Directions[1].Runs[1].Observed != 2 {
		t.Fatalf("multi-run shared capture lost observations: %+v", result.Directions[1].Runs)
	}
	if _, err := passiveCampaignCase(id, ca, reportDir, ab.Dir, ab.CaptureDir, ba.Dir, ba.CaptureDir); err != nil {
		t.Fatalf("reproducible report not idempotent: %v", err)
	}
	html, err := os.ReadFile(filepath.Join(reportDir, "SDX-"+id+"-final.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Not tested") || !strings.Contains(string(html), "Batch coverage") {
		t.Fatal("report omitted untested coverage explanation")
	}
}

func TestOfflinePassiveEvidenceRejectsTamperedAndDuplicateCaptures(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	ab := makeOfflineCampaignFixture(t, ids, ca, "A_TO_B", 1, 1, 1)
	file := filepath.Join(ab.CaptureDir, "capture.json")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ab.CaptureDir, "duplicate.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, inputs, err := offlineCampaignDirection(ab.Dir, ab.CaptureDir, ca, "A_TO_B")
	if err != nil {
		t.Fatal(err)
	}
	if countPassiveInputKind(inputs, "signed_passive_receiver_capture") != 1 {
		t.Fatal("exact duplicate signed capture counted twice")
	}
	recv, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	changed := ab.Capture
	changed.Observations = append([]passivePacket(nil), changed.Observations...)
	changed.Observations[0].ActualPacketSource = "10.88.0.1"
	if err := passiveSnapshot(filepath.Join(ab.CaptureDir, "conflict.json"), changed, recv, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := offlineCampaignDirection(ab.Dir, ab.CaptureDir, ca, "A_TO_B"); err == nil {
		t.Fatal("two different signed captures reused same Capture ID")
	}
}

func TestOfflineCampaignRequiresTrustedDirectionAndExplicitInputs(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	ab := makeOfflineCampaignFixture(t, ids, ca, "A_TO_B", 1, 1, 1)
	ba := makeOfflineCampaignFixture(t, ids, ca, "B_TO_A", 1, 1, 1)
	if _, _, _, err := offlineCampaignDirection(ab.Dir, ba.CaptureDir, ca, "A_TO_B"); err == nil {
		t.Fatal("B_TO_A receiver evidence reused as A_TO_B")
	}
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := passiveCampaignCase("11223344556677889900aabbccddeeff", ca, dir,
		ab.Dir, ab.CaptureDir, ab.Dir, ab.CaptureDir); err == nil {
		t.Fatal("same Campaign ID reused for independent reverse direction")
	}
}

func TestOfflineCaptureSnapshotsKeepLatestPrefixWithoutDoubleCounting(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	f := makeOfflineCampaignFixture(t, ids, ca, "A_TO_B", 1, 1, 1)
	older := f.Capture
	older.Observations = append([]passivePacket(nil), f.Capture.Observations[:1]...)
	older.Status = "IN_PROGRESS"
	older.StopReason = ""
	older.UpdatedUTC = f.Capture.StartedUTC
	cred, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := passiveSnapshot(filepath.Join(f.CaptureDir, "older.json"), older, cred, false); err != nil {
		t.Fatal(err)
	}
	caps, proofs, err := validatedCapturePaths(f.CaptureDir, ca, f.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 1 || len(proofs) != 2 {
		t.Fatalf("incremental captures not deduped by signed ID: caps=%v proofs=%d", caps, len(proofs))
	}
	result, _, _, err := offlineCampaignDirection(f.Dir, f.CaptureDir, ca, "A_TO_B")
	if err != nil {
		t.Fatal(err)
	}
	if result.Runs[0].Observed != 2 || result.Runs[0].DuplicateObservations != 0 {
		t.Fatalf("older snapshot counted twice: %+v", result.Runs[0])
	}
}

func TestOfflineDistinctCapturesPerBatchAndConflictingSources(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	f := makeOfflineCampaignFixture(t, ids, ca, "B_TO_A", 3, 2, 2)
	first := f.Capture.Observations[:4]
	second := f.Capture.Observations[4:]
	cred, err := loadFieldCredential(filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	// Replace synthetic test-only shared snapshot with two independent receiver
	// windows. These are signed fixture bytes, not actual network observations.
	if err := os.Remove(filepath.Join(f.CaptureDir, "capture.json")); err != nil {
		t.Fatal(err)
	}
	for i, subset := range [][]passivePacket{first, second} {
		c, err := newPassiveCapture("A", f.Manifest.DestinationIP, f.Manifest.DataPort, 120, 32)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range subset {
			copyP := p
			copyP.Sequence = len(c.Observations)
			c.Observations = append(c.Observations, copyP)
		}
		c.Status = "COMPLETE"
		c.StopReason = "WINDOW_ENDED"
		c.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		if err := passiveSnapshot(filepath.Join(f.CaptureDir, fmt.Sprintf("part-%d.json", i)), c, cred, false); err != nil {
			t.Fatal(err)
		}
	}
	d, _, _, err := offlineCampaignDirection(f.Dir, f.CaptureDir, ca, "B_TO_A")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Runs) != 2 || d.Runs[0].Observed != 4 || d.Runs[1].Observed != 2 {
		t.Fatalf("split windows did not correlate independent Runs: %+v", d.Runs)
	}
	// A second, distinct signed capture observing a previously seen frame
	// must not increase the unique-sample count.
	repeat, err := newPassiveCapture("A", f.Manifest.DestinationIP, f.Manifest.DataPort, 120, 8)
	if err != nil {
		t.Fatal(err)
	}
	copyPacket := first[0]
	copyPacket.Sequence = 0
	repeat.Observations = []passivePacket{copyPacket}
	repeat.Status = "COMPLETE"
	repeat.StopReason = "WINDOW_ENDED"
	repeat.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	repeatFile := filepath.Join(f.CaptureDir, "repeat.json")
	if err := passiveSnapshot(repeatFile, repeat, cred, false); err != nil {
		t.Fatal(err)
	}
	d, _, _, err = offlineCampaignDirection(f.Dir, f.CaptureDir, ca, "B_TO_A")
	if err != nil {
		t.Fatal(err)
	}
	if d.Runs[0].Observed != 4 || d.Runs[0].DuplicateObservations != 1 {
		t.Fatalf("duplicate observation double counted: %+v", d.Runs[0])
	}
	// A contradictory signed receiver assertion is evidence ambiguity,
	// never a second success or a silently selected "best" source.
	contradictory := repeat
	contradictory.CaptureID = "8899aabbccddeeff0011223344556677"
	contradictory.Observations = []passivePacket{copyPacket}
	contradictory.Observations[0].ActualPacketSource = "10.88.0.1"
	contradictory.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := passiveSnapshot(filepath.Join(f.CaptureDir, "contradiction.json"), contradictory, cred, false); err != nil {
		t.Fatal(err)
	}
	d, cover, _, err := offlineCampaignDirection(f.Dir, f.CaptureDir, ca, "B_TO_A")
	if err != nil {
		t.Fatal(err)
	}
	if d.Runs[0].Observed != 3 || d.Runs[0].ConflictingObservations != 1 || cover[0].Ambiguous != 1 {
		t.Fatalf("conflicting signed observation counted as reachability: %+v / %+v", d.Runs[0], cover[0])
	}
}

func TestOfflineCompletedSenderWithoutReceiverProofRemainsInconclusive(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	f := makeOfflineCampaignFixture(t, ids, ca, "A_TO_B", 1, 1, 1)
	if err := os.Remove(filepath.Join(f.CaptureDir, "capture.json")); err != nil {
		t.Fatal(err)
	}
	report, coverage, _, err := offlineCampaignDirection(f.Dir, f.CaptureDir, ca, "A_TO_B")
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "NO_AUTHENTICATED_RECEIVER_OBSERVATION_INCONCLUSIVE" ||
		report.Runs[0].Submitted != 2 || report.Runs[0].Observed != 0 ||
		coverage[0].NotTested != 0 {
		t.Fatalf("missing receiver evidence converted into false failure/success: %+v %+v", report, coverage)
	}
}

func TestOfflineCampaignRejectsSameCaptureSourceContradictions(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	fixture := makeOfflineCampaignFixture(t, ids, ca, "A_TO_B", 1, 1, 1)
	distinct := fixture.Capture
	distinct.Observations = append([]passivePacket(nil), fixture.Capture.Observations...)
	conflict := distinct.Observations[0]
	conflict.Sequence = len(distinct.Observations)
	conflict.ActualPacketSource = "10.81.0.9"
	conflict.ReceivedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	distinct.Observations = append(distinct.Observations, conflict)
	distinct.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	credential, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.CaptureDir, "capture.json")
	if err := passiveSnapshot(path, distinct, credential, true); err != nil {
		t.Fatal(err)
	}
	result, coverage, _, err := offlineCampaignDirection(fixture.Dir, fixture.CaptureDir, ca, "A_TO_B")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Runs) != 1 || result.Runs[0].ConflictingObservations != 1 ||
		result.Runs[0].Observed != 1 || coverage[0].Ambiguous != 1 ||
		result.Sources[0].Ambiguous != 1 || result.Sources[0].Observed != 1 {
		t.Fatalf("same-capture contradiction counted as success: %+v / %+v", result, coverage)
	}
}
