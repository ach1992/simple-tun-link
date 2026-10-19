package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func passiveFixture(t *testing.T) (string, string, signedFieldChallenge, passiveCapture, []byte) {
	t.Helper()
	ids, ca := testCampaignIdentity(t)
	sources := testCandidateInventory(t, 1, "")
	ch, err := newFieldChallenge(fieldOptions{
		File: sources, Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"),
		CA: ca, Sender: "A", Receiver: "B", DestinationIP: "10.40.0.8", DataPort: 24572,
		PacketSize: 192, TTLSeconds: 600, Epoch: "private-lab", Transport: "field_udp_bound",
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := loadFieldCredential(filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := makeFieldPacket(ch.Challenge, ch.Challenge.Samples[0], cred.PrivateKey.(ed25519.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	capture, err := newPassiveCapture("B", "10.40.0.8", 24572, 120, 8)
	if err != nil {
		t.Fatal(err)
	}
	return ids, ca, ch, capture, packet
}

func TestPassiveReceiverNoSenderFileAndOfflineCorrelation(t *testing.T) {
	ids, ca, ch, capture, packet := passiveFixture(t)
	chPath := filepath.Join(t.TempDir(), "challenge.json")
	if err := saveNewJSON(chPath, ch); err != nil {
		t.Fatal(err)
	}
	ok, err := passiveAppend(&capture, packet, "10.99.0.1", time.Now().UTC())
	if err != nil || !ok {
		t.Fatalf("passive record failed: %v", err)
	}
	// Duplicates and unrelated SDF2-looking inputs can be observed but are
	// NOT authenticated until matching them with A's signed plan offline.
	if ok, err = passiveAppend(&capture, packet, "10.99.0.1", time.Now().UTC()); err != nil || !ok {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 0xff
	if ok, err = passiveAppend(&capture, tampered, "10.99.0.1", time.Now().UTC()); err != nil || !ok {
		t.Fatal(err)
	}
	if ok, err = passiveAppend(&capture, []byte("junk"), "10.99.0.1", time.Now().UTC()); err != nil || ok {
		t.Fatalf("unrelated payload was retained: %v %v", ok, err)
	}
	receiver, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	capture.Status = "COMPLETE"
	capture.StopReason = "WINDOW_ENDED"
	capture.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	receiptPath := filepath.Join(t.TempDir(), "passive.json")
	if err := passiveSnapshot(receiptPath, capture, receiver, false); err != nil {
		t.Fatal(err)
	}
	got, err := correlatePassive(chPath, receiptPath, "", ca)
	if err != nil {
		t.Fatal(err)
	}
	if got["authenticated_observed"] != 1 || got["source_rewritten"] != 1 ||
		got["source_matched"] != 0 || got["unmatched_or_duplicate_frames"] != 2 ||
		got["sender_evidence_state"] != "NOT_PROVIDED" ||
		got["return_to_sender"] != "NOT_TESTED" {
		t.Fatalf("incorrect offline distinction: %+v", got)
	}
	if _, err := correlatePassive(chPath, receiptPath, "", filepath.Join(ids, "A.crt")); err == nil {
		t.Fatal("wrong trust root accepted")
	}
	// Authenticated packet bytes with a receiver-declared time predating the
	// signed sender Run must not become evidence that the current Run arrived.
	oldTime := time.Now().UTC().Add(-4 * time.Minute)
	capture.StartedUTC = oldTime.Format(time.RFC3339Nano)
	capture.UpdatedUTC = oldTime.Add(90 * time.Second).Format(time.RFC3339Nano)
	for i := range capture.Observations {
		capture.Observations[i].ReceivedUTC = oldTime.Add(60 * time.Second).Format(time.RFC3339Nano)
	}
	oldPath := filepath.Join(t.TempDir(), "old-capture.json")
	if err := passiveSnapshot(oldPath, capture, receiver, false); err != nil {
		t.Fatal(err)
	}
	oldResult, err := correlatePassive(chPath, oldPath, "", ca)
	if err != nil {
		t.Fatal(err)
	}
	if oldResult["authenticated_observed"] != 0 || oldResult["unmatched_or_duplicate_frames"] != 3 {
		t.Fatalf("replayed or pre-run observation accepted: %+v", oldResult)
	}
}

func TestPassiveTamperingWrongRoleAndFiniteLimits(t *testing.T) {
	ids, ca, ch, capture, packet := passiveFixture(t)
	_ = ch
	for _, invalid := range []struct{ window, limit int }{{0, 1}, {14401, 1}, {1, 0}, {1, 2049}} {
		if _, err := newPassiveCapture("B", "10.40.0.8", 24572, invalid.window, invalid.limit); err == nil {
			t.Fatal("unbounded or invalid passive settings accepted")
		}
	}
	if _, err := passiveAppend(&capture, packet, "not-an-ip", time.Now()); err == nil {
		t.Fatal("invalid peer IP recorded")
	}
	ok, err := passiveAppend(&capture, packet, "10.40.0.7", time.Now())
	if err != nil || !ok {
		t.Fatal(err)
	}
	receiver, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "capture.json")
	if err := passiveSnapshot(path, capture, receiver, false); err != nil {
		t.Fatal(err)
	}
	if _, err := readAndVerifyPassive(path, ca, "B"); err != nil {
		t.Fatal(err)
	}
	if _, err := readAndVerifyPassive(path, ca, "A"); err == nil {
		t.Fatal("wrong observer role was accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var signed signedPassiveCapture
	if err = json.Unmarshal(data, &signed); err != nil {
		t.Fatal(err)
	}
	signed.Capture.Observations[0].ActualPacketSource = "10.99.0.11"
	changed, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAndVerifyPassive(path, ca, "B"); err == nil {
		t.Fatal("altered source was accepted without valid signature")
	}
}

func TestPassiveSameSignedCaptureConflictingActualSourcesAreAmbiguous(t *testing.T) {
	ids, ca, challenge, capture, packet := passiveFixture(t)
	chPath := filepath.Join(t.TempDir(), "challenge.json")
	if err := saveNewJSON(chPath, challenge); err != nil {
		t.Fatal(err)
	}
	declared := challenge.Challenge.Samples[0].Candidate.IP
	if yes, err := passiveAppend(&capture, packet, declared, time.Now().UTC()); err != nil || !yes {
		t.Fatal(err)
	}
	if yes, err := passiveAppend(&capture, packet, "10.79.4.11", time.Now().UTC()); err != nil || !yes {
		t.Fatal(err)
	}
	if yes, err := passiveAppend(&capture, packet, declared, time.Now().UTC()); err != nil || !yes {
		t.Fatal(err)
	}
	capture.Status = "COMPLETE"
	capture.StopReason = "WINDOW_ENDED"
	capture.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	credential, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "contradiction.json")
	if err := passiveSnapshot(path, capture, credential, false); err != nil {
		t.Fatal(err)
	}
	found, err := correlatePassive(chPath, path, "", ca)
	if err != nil {
		t.Fatal(err)
	}
	if found["authenticated_observed"] != 0 || found["source_matched"] != 0 ||
		found["source_rewritten"] != 0 || found["ambiguous_samples"] != 1 ||
		found["duplicate_authenticated_frames"] != 1 || found["conflicting_authenticated_frames"] != 1 ||
		found["not_observed"] != 0 {
		t.Fatalf("conflicting signed claim was silently accepted: %+v", found)
	}
	ambiguities, ok := found["ambiguous_observations"].([]map[string]any)
	if !ok || len(ambiguities) != 1 || ambiguities[0]["status"] != "AMBIGUOUS_CONFLICTING_SIGNED_RECEIVER_SOURCES" {
		t.Fatalf("signed ambiguity was not preserved: %+v", found)
	}
	if observations := found["observations"].([]map[string]any); len(observations) != 0 {
		t.Fatalf("false successful receiver observation: %+v", observations)
	}
}
