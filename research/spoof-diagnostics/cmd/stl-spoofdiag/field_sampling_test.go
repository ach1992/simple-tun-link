package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFieldRepeatedSamplingSignedReceiptAndSourceMetrics(t *testing.T) {
	dir := t.TempDir()
	ids := filepath.Join(dir, "identities")
	if err := createFieldIdentity(ids); err != nil {
		t.Fatal(err)
	}
	inventory := CandidateFile{
		SchemaVersion: schema, Mode: "field_candidates",
		Candidates: []Candidate{
			{IP: "10.31.0.7", Direction: "A_TO_B", Sender: "A", Receiver: "B"},
			{IP: "10.31.0.8", Direction: "A_TO_B", Sender: "A", Receiver: "B"},
		},
	}
	sourcePath := filepath.Join(dir, "sources.json")
	if err := writeCandidateInventory(sourcePath, inventory); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(ids, "ca.crt")
	plan, err := newFieldChallenge(fieldOptions{
		File: sourcePath, Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"),
		CA: ca, Sender: "A", Receiver: "B", DestinationIP: "10.31.0.9",
		Transport: "field_raw_ipv4", DataPort: 24572, PacketSize: 192,
		Epoch: "test", TTLSeconds: 600, SamplesPerSource: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Challenge.SamplesPerSource != 5 || len(plan.Challenge.Samples) != 10 {
		t.Fatalf("wrong number of samples in signed challenge: %+v", plan.Challenge)
	}
	for i, sample := range plan.Challenge.Samples {
		if sample.Index != i || sample.Candidate != inventory.Candidates[i%2] {
			t.Fatalf("samples not interleaved by exact source: %+v", sample)
		}
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkSignedFieldChallenge(plan, roots, time.Now(), true); err != nil {
		t.Fatal(err)
	}

	challengePath := filepath.Join(dir, "challenge.json")
	if err := saveNewJSON(challengePath, plan); err != nil {
		t.Fatal(err)
	}
	granted, err := newFieldGrantWithDestinationOwnership(fieldOptions{
		File: sourcePath, Cert: filepath.Join(ids, "B.crt"), Key: filepath.Join(ids, "B.key"),
		CA: ca, Sender: "A", Receiver: "B", Challenge: challengePath,
	}, func(ip string) error {
		if ip != "10.31.0.9" {
			return errors.New("destination not owned by test")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	grantPath := filepath.Join(dir, "grant.json")
	if err := saveNewJSON(grantPath, granted); err != nil {
		t.Fatal(err)
	}
	senderCert, err := loadFieldCredential(filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	senderLeaf, err := x509.ParseCertificate(senderCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[int]bool)
	// A second packet from the same source is valid only with its separate
	// signed index. The same index replayed must not be counted twice.
	for _, idx := range []int{0, 2} {
		packet, err := makeFieldPacket(plan.Challenge, plan.Challenge.Samples[idx],
			senderCert.PrivateKey.(ed25519.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := verifyFieldPacket(packet, plan.Challenge, senderLeaf.PublicKey.(ed25519.PublicKey), seen); !ok {
			t.Fatalf("valid independent sample %d rejected", idx)
		}
		if _, ok := verifyFieldPacket(packet, plan.Challenge, senderLeaf.PublicKey.(ed25519.PublicKey), seen); ok {
			t.Fatalf("replayed sample %d accepted", idx)
		}
	}

	receiverCert, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := fieldReceipt{
		SchemaVersion: schema, Environment: plan.Challenge.Environment,
		RunID: plan.Challenge.RunID, Observer: roleName("B"),
		CreatedUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: 10, ChallengeDigest: fieldChallengeDigest(plan.Challenge),
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
	}
	for _, idx := range []int{0, 1, 2, 3, 4, 6} {
		sample := plan.Challenge.Samples[idx]
		actual := sample.Candidate.IP
		if idx == 3 {
			actual = "10.31.0.99" // a receipt may observe a rewritten source
		}
		receipt.Observations = append(receipt.Observations, fieldSeen{
			Index: idx, SourceCandidate: sample.Candidate.IP, ActualPacketSource: actual,
			PacketSize: sample.Size, Direction: sample.Candidate.Direction, PolicyEpoch: sample.Epoch,
			Authenticated: true, SourceMatched: actual == sample.Candidate.IP,
		})
	}
	signed, err := signFieldReceipt(receipt, receiverCert)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dir, "receipt.json")
	if err := saveNewJSON(receiptPath, signed); err != nil {
		t.Fatal(err)
	}
	got, err := verifyFieldPair(challengePath, grantPath, receiptPath, ca)
	if err != nil {
		t.Fatal(err)
	}
	perSource, ok := got["per_source"].([]fieldSourceObservation)
	if !ok || len(perSource) != 2 {
		t.Fatalf("per-source metrics missing from signed verification: %+v", got)
	}
	a, b := perSource[0], perSource[1]
	if a.PlannedSamples != 5 || a.AuthenticatedPeerObservations != 4 ||
		a.ExactSourceObserved != 4 || a.PlannedButNotObserved != 1 ||
		a.PeerObservationPctOfSignedPlan != 80 || a.ExactSourcePctOfPeerObservations == nil ||
		*a.ExactSourcePctOfPeerObservations != 100 {
		t.Fatalf("incorrect first source statistics: %+v", a)
	}
	if b.PlannedSamples != 5 || b.AuthenticatedPeerObservations != 2 ||
		b.ExactSourceObserved != 1 || b.RewrittenSourceObserved != 1 ||
		b.PlannedButNotObserved != 3 || b.PeerObservationPctOfSignedPlan != 40 ||
		b.ExactSourcePctOfPeerObservations == nil || *b.ExactSourcePctOfPeerObservations != 50 {
		t.Fatalf("incorrect second source statistics: %+v", b)
	}
	if got["provider_source_acceptance"] != "NOT_INDEPENDENTLY_VERIFIED" ||
		got["return_to_sender"] != "NOT_TESTED" ||
		b.ProviderAuthorization != "NOT_VERIFIED_BY_DIAGNOSTICS" {
		t.Fatalf("observation confused with provider approval: %+v", got)
	}

	// A valid, signed zero-observation receipt means inconclusive, not a
	// demonstration that the network or source is blocked.
	receipt.Observations = nil
	empty, err := signFieldReceipt(receipt, receiverCert)
	if err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(dir, "no-ingress.json")
	if err := saveNewJSON(emptyPath, empty); err != nil {
		t.Fatal(err)
	}
	zero, err := verifyFieldPair(challengePath, grantPath, emptyPath, ca)
	if err != nil {
		t.Fatal(err)
	}
	noIngress := zero["per_source"].([]fieldSourceObservation)
	if noIngress[0].ExactSourcePctOfPeerObservations != nil ||
		noIngress[0].ObservationStatus != "NO_SIGNED_PEER_INGRESS_INCONCLUSIVE" ||
		noIngress[0].PlannedButNotObserved != 5 {
		t.Fatalf("zero observations incorrectly asserted as an absolute failure: %+v", noIngress)
	}
}

func TestFieldRepeatCeilingsAndLegacySignedPlan(t *testing.T) {
	dir := t.TempDir()
	ids := filepath.Join(dir, "ids")
	if err := createFieldIdentity(ids); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "sources.json")
	if err := writeCandidateInventory(file, CandidateFile{
		SchemaVersion: schema, Mode: "field_candidates",
		Candidates: []Candidate{{IP: "10.81.0.11", Direction: "A_TO_B", Sender: "A", Receiver: "B"}},
	}); err != nil {
		t.Fatal(err)
	}
	base := fieldOptions{
		File: file, Cert: filepath.Join(ids, "A.crt"), Key: filepath.Join(ids, "A.key"),
		CA: filepath.Join(ids, "ca.crt"), Sender: "A", Receiver: "B",
		DestinationIP: "10.81.0.12", Transport: "field_udp_bound",
		DataPort: 24572, PacketSize: 192, Epoch: "unit", TTLSeconds: 600,
	}
	base.SamplesPerSource = fieldMaxPacketsPerSource + 1
	if _, err := newFieldChallenge(base); err == nil {
		t.Fatal("excessive sampling accepted")
	}
	base.SamplesPerSource = -1
	if _, err := newFieldChallenge(base); err == nil {
		t.Fatal("negative sampling count accepted")
	}
	base.SamplesPerSource = 0
	legacy, err := newFieldChallenge(base)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Challenge.SamplesPerSource = 0 // historical signed JSON omitted it
	if err := validateFieldChallenge(legacy.Challenge, time.Now(), true); err != nil {
		t.Fatalf("legacy one-sample challenge rejected: %v", err)
	}
	legacy.Challenge.SamplesPerSource = 3
	if err := validateFieldChallenge(legacy.Challenge, time.Now(), true); err == nil {
		t.Fatal("incomplete signed sample list accepted")
	}
	legacy.Challenge.SamplesPerSource = -1
	if err := validateFieldChallenge(legacy.Challenge, time.Now(), true); err == nil {
		t.Fatal("negative signed sample count accepted")
	}
	legacy.Challenge.SamplesPerSource = 1
	legacy.Challenge.Samples = append(legacy.Challenge.Samples, legacy.Challenge.Samples[0])
	legacy.Challenge.Samples[1].Index = 1
	if err := validateFieldChallenge(legacy.Challenge, time.Now(), true); err == nil {
		t.Fatal("duplicate source sample in single-sample legacy run accepted")
	}
}

func TestAutomaticFieldReceiverWindowCoversRepeatedSampleEnvelope(t *testing.T) {
	cases := []struct {
		count, expected int
	}{
		{1, 16},
		{5, 16},
		{10, 17},
		{32, 22},
		{160, 47},
		{fieldMaxSamples, 79},
	}
	for _, test := range cases {
		actual := automaticFieldWindowSeconds(test.count)
		if actual != test.expected || actual < 15 {
			t.Fatalf("receiver window for %d samples: got %d, want %d",
				test.count, actual, test.expected)
		}
	}
}
