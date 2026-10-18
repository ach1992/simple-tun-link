package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This tests the complete signed-file evidence contract without network access.
// A signed peer receipt is never treated as proof of provider admission or return.
func TestFieldSignedReceiptRoundTripAndNegativeControls(t *testing.T) {
	base := t.TempDir()
	ids := filepath.Join(base, "identity")
	if err := createFieldIdentity(ids); err != nil {
		t.Fatal(err)
	}
	candidates := filepath.Join(base, "candidates.json")
	inventory := CandidateFile{SchemaVersion: schema, Mode: "field_candidates",
		Candidates: []Candidate{{IP: "10.40.0.7", Direction: "A_TO_B", Sender: "A", Receiver: "B"}}}
	if err := writeCandidateInventory(candidates, inventory); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(ids, "ca.crt")
	challengeOptions := fieldOptions{File: candidates, Cert: filepath.Join(ids, "A.crt"),
		Key: filepath.Join(ids, "A.key"), CA: ca, Sender: "A", Receiver: "B",
		Transport: "field_raw_ipv4", DestinationIP: "10.40.0.8", DataPort: 24572,
		PacketSize: 192, Epoch: "unit", TTLSeconds: 600}
	plan, err := newFieldChallenge(challengeOptions)
	if err != nil {
		t.Fatal(err)
	}
	challengePath := filepath.Join(base, "challenge.json")
	if err := saveNewJSON(challengePath, plan); err != nil {
		t.Fatal(err)
	}
	receiverOptions := fieldOptions{File: candidates, Cert: filepath.Join(ids, "B.crt"),
		Key: filepath.Join(ids, "B.key"), CA: ca, Sender: "A", Receiver: "B", Challenge: challengePath}
	grant, err := newFieldGrantWithDestinationOwnership(receiverOptions, func(ip string) error {
		if ip != "10.40.0.8" {
			return errors.New("destination outside owned test candidate")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	grantPath := filepath.Join(base, "grant.json")
	if err := saveNewJSON(grantPath, grant); err != nil {
		t.Fatal(err)
	}

	cert, err := loadFieldCredential(receiverOptions.Cert, receiverOptions.Key)
	if err != nil {
		t.Fatal(err)
	}
	receipt := fieldReceipt{
		SchemaVersion: schema, Environment: plan.Challenge.Environment,
		RunID: plan.Challenge.RunID, Observer: roleName("B"),
		CreatedUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: 1, ChallengeDigest: fieldChallengeDigest(plan.Challenge),
		Observations: []fieldSeen{{Index: 0, SourceCandidate: "10.40.0.7",
			ActualPacketSource: "10.40.0.7", PacketSize: 192, Direction: "A_TO_B",
			PolicyEpoch: "unit", Authenticated: true, SourceMatched: true}},
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
	}
	signed, err := signFieldReceipt(receipt, cert)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(base, "receipt.json")
	if err := saveNewJSON(receiptPath, signed); err != nil {
		t.Fatal(err)
	}
	got, err := verifyFieldPair(challengePath, grantPath, receiptPath, ca)
	if err != nil {
		t.Fatal(err)
	}
	if got["source_matched_at_peer"] != 1 || got["return_to_sender"] != "NOT_TESTED" ||
		got["private_l3"] != "NOT_TESTED" {
		t.Fatalf("signed receipt overclaimed results: %+v", got)
	}

	// An incorrectly claimed provider result is invalid, even with a valid
	// independent receiver signature over the forged result object.
	receipt.CandidateAdmission = "PROVIDER_VERIFIED"
	signed, err = signFieldReceipt(receipt, cert)
	if err != nil {
		t.Fatal(err)
	}
	invalidStatusPath := filepath.Join(base, "invalid-claim.json")
	if err := saveNewJSON(invalidStatusPath, signed); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFieldPair(challengePath, grantPath, invalidStatusPath, ca); err == nil {
		t.Fatal("signed provider-acceptance overclaim accepted")
	}

	receipt.CandidateAdmission = "NOT_TESTED"
	receipt.Observations[0].SourceMatched = false
	signed, err = signFieldReceipt(receipt, cert)
	if err != nil {
		t.Fatal(err)
	}
	invalidSourcePath := filepath.Join(base, "invalid-source.json")
	if err := saveNewJSON(invalidSourcePath, signed); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFieldPair(challengePath, grantPath, invalidSourcePath, ca); err == nil {
		t.Fatal("source match inconsistency accepted")
	}

	if err := os.WriteFile(receiptPath, []byte("{\"broken\":true}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFieldPair(challengePath, grantPath, receiptPath, ca); err == nil {
		t.Fatal("tampered receipt accepted")
	}
}
