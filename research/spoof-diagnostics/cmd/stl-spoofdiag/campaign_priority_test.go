package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestReversePriorityUsesOnlyVerifiedExactOverlapAndPreservesInventory(t *testing.T) {
	ids, ca, ch, cap, pkt := passiveFixture(t)
	if yes, err := passiveAppend(&cap, pkt, "10.91.0.1", time.Now()); err != nil || !yes {
		t.Fatal(err)
	}
	receiver, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	chPath := filepath.Join(base, "challenge.json")
	capPath := filepath.Join(base, "capture.json")
	if err := saveNewJSON(chPath, ch); err != nil {
		t.Fatal(err)
	}
	if err := passiveSnapshot(capPath, cap, receiver, false); err != nil {
		t.Fatal(err)
	}
	original := CandidateFile{SchemaVersion: schema, Mode: "field_candidates", Candidates: []Candidate{
		{IP: "10.91.0.2", Direction: "B_TO_A", Sender: "B", Receiver: "A"},
		{IP: "10.91.0.1", Direction: "B_TO_A", Sender: "B", Receiver: "A"},
		{IP: "10.91.0.3", Direction: "B_TO_A", Sender: "B", Receiver: "A"},
	}}
	in := filepath.Join(base, "b-source.json")
	if err := writeCandidateInventory(in, original); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "prioritized.json")
	audit, err := prepareReversePriority(in, chPath, capPath, "", ca, out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readCandidates(out)
	if err != nil {
		t.Fatal(err)
	}
	ips := []string{}
	for _, item := range got.Candidates {
		ips = append(ips, item.IP)
	}
	if !reflect.DeepEqual(ips, []string{"10.91.0.1", "10.91.0.2", "10.91.0.3"}) {
		t.Fatalf("wrong evidence-based order %v", ips)
	}
	if audit.Candidates[0].ObservedSourceMatched != 1 || audit.Candidates[2].Reason != "NO_REVERSE_EVIDENCE_OR_EXACT_IP_OVERLAP_KEEP_STABLE_ORDER" {
		t.Fatalf("incorrect provenance %+v", audit)
	}
	after, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("original B-owned inventory was mutated")
	}
	if _, err := os.Stat(filepath.Join(base, "prioritized.ranking.json")); err != nil {
		t.Fatal("priority audit missing", err)
	}
	if _, err := prepareReversePriority(in, chPath, capPath, "", ca, out); err == nil {
		t.Fatal("existing canonical prioritized source was overwritten")
	}
}

func TestReversePriorityRejectsAInventoryAsBSource(t *testing.T) {
	ids, ca, ch, cap, pkt := passiveFixture(t)
	if yes, err := passiveAppend(&cap, pkt, "10.91.0.1", time.Now()); err != nil || !yes {
		t.Fatal(err)
	}
	recv, err := loadFieldCredential(filepath.Join(ids, "B.crt"), filepath.Join(ids, "B.key"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	chPath := filepath.Join(base, "challenge.json")
	capPath := filepath.Join(base, "capture.json")
	if err := saveNewJSON(chPath, ch); err != nil {
		t.Fatal(err)
	}
	if err := passiveSnapshot(capPath, cap, recv, false); err != nil {
		t.Fatal(err)
	}
	// The hint is not permission to use A's address inventory from B.
	aFile := testCandidateInventory(t, 1, "")
	_, err = prepareReversePriority(aFile, chPath, capPath, "", ca, filepath.Join(base, "invalid.json"))
	if err == nil {
		t.Fatal("A-scope source list accepted as B's candidate list")
	}
}
