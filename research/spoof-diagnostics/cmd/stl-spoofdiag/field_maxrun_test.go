package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFieldMaximumBoundedPlanAndReceiptStayWithinFileEnvelope(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "identities")
	if err := createFieldIdentity(identity); err != nil {
		t.Fatal(err)
	}
	inventory := CandidateFile{SchemaVersion: schema, Mode: "field_candidates"}
	for i := 1; i <= fieldMaxSelectedSources; i++ {
		inventory.Candidates = append(inventory.Candidates, Candidate{
			IP:        fmt.Sprintf("10.71.0.%d", i),
			Direction: "A_TO_B", Sender: "A", Receiver: "B",
		})
	}
	file := filepath.Join(dir, "inventory.json")
	if err := writeCandidateInventory(file, inventory); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(identity, "ca.crt")
	challenge, err := newFieldChallenge(fieldOptions{
		File: file, Cert: filepath.Join(identity, "A.crt"), Key: filepath.Join(identity, "A.key"),
		CA: ca, Sender: "A", Receiver: "B", DestinationIP: "10.71.0.100",
		Transport: "field_udp_bound", DataPort: 24572, PacketSize: 192,
		Epoch: "test", TTLSeconds: 600, SamplesPerSource: fieldMaxPacketsPerSource,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(challenge.Challenge.Samples) != fieldMaxSamples {
		t.Fatalf("expected %d signed samples, got %d", fieldMaxSamples, len(challenge.Challenge.Samples))
	}
	cPath := filepath.Join(dir, "challenge.json")
	if err := saveNewJSON(cPath, challenge); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(cPath)
	if err != nil || st.Size() > fieldMaxControl {
		t.Fatalf("signed challenge too large: %v %+v", err, st)
	}
	if _, err := readSignedFieldChallenge(cPath); err != nil {
		t.Fatal(err)
	}

	grant, err := newFieldGrantWithDestinationOwnership(fieldOptions{
		File: file, Cert: filepath.Join(identity, "B.crt"), Key: filepath.Join(identity, "B.key"),
		CA: ca, Sender: "A", Receiver: "B", Challenge: cPath,
	}, func(ip string) error {
		if ip != "10.71.0.100" {
			return fmt.Errorf("unapproved destination")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	gPath := filepath.Join(dir, "grant.json")
	if err := saveNewJSON(gPath, grant); err != nil {
		t.Fatal(err)
	}
	receiver, err := loadFieldCredential(filepath.Join(identity, "B.crt"), filepath.Join(identity, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := fieldReceipt{
		SchemaVersion: schema, Environment: challenge.Challenge.Environment,
		RunID: challenge.Challenge.RunID, Observer: roleName("B"),
		CreatedUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: len(challenge.Challenge.Samples),
		ChallengeDigest: fieldChallengeDigest(challenge.Challenge),
		EgressStatus:    "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
	}
	for _, sample := range challenge.Challenge.Samples {
		receipt.Observations = append(receipt.Observations, fieldSeen{
			Index: sample.Index, SourceCandidate: sample.Candidate.IP,
			ActualPacketSource: sample.Candidate.IP, SourceMatched: true,
			PacketSize: sample.Size, Direction: sample.Candidate.Direction,
			PolicyEpoch: sample.Epoch, Authenticated: true,
		})
	}
	signed, err := signFieldReceipt(receipt, receiver)
	if err != nil {
		t.Fatal(err)
	}
	rPath := filepath.Join(dir, "receipt.json")
	if err := saveNewJSON(rPath, signed); err != nil {
		t.Fatal(err)
	}
	st, err = os.Stat(rPath)
	if err != nil || st.Size() > fieldMaxControl {
		t.Fatalf("signed receipt too large: %v %+v", err, st)
	}
	result, err := verifyFieldPair(cPath, gPath, rPath, ca)
	if err != nil {
		t.Fatal(err)
	}
	if result["selected_source_count"] != fieldMaxSelectedSources ||
		result["peer_authenticated_received"] != fieldMaxSamples ||
		result["source_matched_at_peer"] != fieldMaxSamples {
		t.Fatalf("incorrect max-bounded-run results: %+v", result)
	}
}
