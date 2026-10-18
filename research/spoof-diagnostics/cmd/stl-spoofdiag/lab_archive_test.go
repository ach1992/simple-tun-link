package main

import (
	"crypto/tls"
	"path/filepath"
	"testing"
	"time"
)

// An offline receipt may be transferred hours later, long after the bounded
// challenge stopped authorizing packets. Archival verification must preserve
// signature checks without ever reopening that live send/receive window.
func TestArchivedOfflineReceiptVerificationAndFreshnessSeparation(t *testing.T) {
	dir, ca := testLabCredentials(t)
	source := testSourcesFile(t, "10.90.3.100")
	sender := testOpts(dir, ca, source, "A", "B")
	plan, err := newOfflineChallenge(sender)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	plan.Challenge.CreatedUTC = now.Add(-4 * time.Minute).Format(time.RFC3339Nano)
	plan.Challenge.ExpiresUnix = now.Add(-3 * time.Minute).Unix()

	a, err := tls.LoadX509KeyPair(filepath.Join(dir, "A.crt"), filepath.Join(dir, "A.key"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err = signedChallengeFor(plan.Challenge, a)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = challengeSignerCertificate(plan, roots, now); err == nil {
		t.Fatal("expired signed challenge still authorizes a live operation")
	}
	s := plan.Challenge.Samples[0]
	receipt := labReceipt{
		SchemaVersion: schema, Environment: "loopback_transport", RunID: plan.Challenge.RunID,
		Observer: roleName("B"), CreatedUTC: now.Add(-3*time.Minute - 20*time.Second).Format(time.RFC3339Nano),
		ExpectedSamples: len(plan.Challenge.Samples), ChallengeDigest: offlineChallengeDigest(plan.Challenge),
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
		Observations: []labSeen{{
			Index: s.Index, SourceCandidate: s.Candidate.IP, ActualPacketSource: "127.0.0.1",
			PacketSize: s.Size, Direction: s.Candidate.Direction, PolicyEpoch: s.Epoch, Authenticated: true,
		}},
	}
	b, err := tls.LoadX509KeyPair(filepath.Join(dir, "B.crt"), filepath.Join(dir, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := signLabReceipt(receipt, b)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	challengePath := filepath.Join(root, "challenge.json")
	receiptPath := filepath.Join(root, "receipt.json")
	if err = saveNewJSON(challengePath, plan); err != nil {
		t.Fatal(err)
	}
	if err = saveNewJSON(receiptPath, peer); err != nil {
		t.Fatal(err)
	}
	result, err := verifyOfflinePair(challengePath, receiptPath, ca)
	if err != nil {
		t.Fatalf("archived signed receipt rejected after authorized live window: %v", err)
	}
	if result["authenticated_peer_observations"] != 1 || result["verification_mode"] != "HISTORICAL_SIGNED_EVIDENCE_ONLY" {
		t.Fatalf("historical provenance or receipt observation incorrectly classified: %+v", result)
	}

	for name, changed := range map[string]labReceipt{
		"after_expiry": func() labReceipt { r := receipt; r.CreatedUTC = now.Format(time.RFC3339Nano); return r }(),
		"future": func() labReceipt {
			r := receipt
			r.CreatedUTC = now.Add(5 * time.Minute).Format(time.RFC3339Nano)
			return r
		}(),
		"wrong_challenge": func() labReceipt {
			r := receipt
			r.ChallengeDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			modified, err := signLabReceipt(changed, b)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "modified.json")
			if err := saveNewJSON(file, modified); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyOfflinePair(challengePath, file, ca); err == nil {
				t.Fatalf("signed but inadmissible historical evidence %s accepted", name)
			}
		})
	}
}
