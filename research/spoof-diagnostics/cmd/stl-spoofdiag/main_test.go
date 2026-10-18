package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func ptr(b bool) *bool { return &b }
func TestCandidateValidation(t *testing.T) {
	c := CandidateFile{SchemaVersion: 1, Mode: "private_lab", Candidates: []Candidate{{IP: "10.9.9.1", Direction: "A_TO_B", Sender: "a", Receiver: "b"}, {IP: "10.9.9.2", Direction: "B_TO_A", Sender: "b", Receiver: "a"}}}
	if err := validateCandidates(c); err != nil {
		t.Fatal(err)
	}
	c.Candidates[0].IP = "1.1.1.1"
	if validateCandidates(c) == nil {
		t.Fatal("lab admitted public IP")
	}
	c.Candidates[0].IP = "10.9.9.1"
	c.Candidates[0].Direction = "both"
	if validateCandidates(c) == nil {
		t.Fatal("invalid direction admitted")
	}
	c.Candidates[0].Direction = "A_TO_B"
	c.Candidates = append(c.Candidates, c.Candidates[0])
	if validateCandidates(c) == nil {
		t.Fatal("duplicate admitted")
	}
}
func TestClassificationEvidenceLayers(t *testing.T) {
	o := Observation{SampleID: "sample1", RunID: "run", Environment: "private_lab", Direction: "A_TO_B", Sender: "A", Receiver: "B", SourceIP: "10.9.0.2", PacketSize: 128, Epoch: "e1", Attempted: true}
	s, _ := classify(o)
	if s.Result != "SUBMITTED_ONLY" {
		t.Fatalf("got %q", s.Result)
	}
	o.EgressObserved = ptr(true)
	s, _ = classify(o)
	if s.Result != "EGRESS_OBSERVED" {
		t.Fatalf("got %q", s.Result)
	}
	o.PeerObserved = ptr(true)
	s, _ = classify(o)
	if s.Result != "PEER_OBSERVED_UNAUTHENTICATED" {
		t.Fatalf("got %q", s.Result)
	}
	o.AuthVerified = ptr(true)
	s, _ = classify(o)
	if s.Result != "CLAIMED_AUTHENTICATED_PEER_OBSERVED" || s.ReturnStatus != "NOT_TESTED" || s.PrivateL3 != "NOT_TESTED" {
		t.Fatalf("invalid result %+v", s)
	}
	o.ReturnObserver = "C"
	o.ReturnAuthenticated = ptr(true)
	s, _ = classify(o)
	if s.ReturnStatus != "CLAIMED_AUTHENTICATED_AT:C" || s.PrivateL3 != "NOT_TESTED" {
		t.Fatalf("invalid return %+v", s)
	}
	o.AuthVerified = ptr(false)
	if _, err := classify(o); err == nil {
		t.Fatal("contradictory return admitted")
	}
}
func TestReportRejectsDuplicate(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "evidence.json")
	o := Observation{SampleID: "sample1", RunID: "run", Environment: "private_lab", Direction: "A_TO_B", Sender: "A", Receiver: "B", SourceIP: "10.9.0.2", PacketSize: 128, Epoch: "e1"}
	b, _ := json.Marshal(EvidenceFile{SchemaVersion: 1, Observations: []Observation{o, o}})
	if err := os.WriteFile(f, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := report(f); err == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestCSVImportDirectional(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "sources.csv")
	if err := os.WriteFile(f, []byte("ip,direction,sender,receiver\n10.1.0.7,A_TO_B,A,B\n10.1.0.8,B_TO_A,B,A\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := readCandidates(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Candidates) != 2 || c.Candidates[1].Direction != "B_TO_A" {
		t.Fatalf("bad candidates %+v", c)
	}
}
func TestFieldRejectsReservedAndAcceptsRoutableExact(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "198.51.100.2", "203.0.113.9", "100.64.1.9", "198.18.3.2", "127.0.0.1"} {
		if err := validateIP(ip, "approved_field_plan"); err == nil {
			t.Fatalf("unsafe address allowed %s", ip)
		}
	}
	if err := validateIP("1.1.1.1", "approved_field_plan"); err != nil {
		t.Fatal(err)
	}
}
func TestNoNetworkForValidation(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"preflight"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("unknown command accepted")
	}
}
func TestIndependentDirectionAndSampleIdentities(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "evidence.json")
	o := Observation{SampleID: "a", RunID: "run", Environment: "private_lab", Direction: "A_TO_B", Sender: "A", Receiver: "B", SourceIP: "10.9.0.2", PacketSize: 128, Epoch: "e1", Attempted: true}
	p := o
	p.SampleID = "b"
	p.Direction = "B_TO_A"
	p.Sender = "B"
	p.Receiver = "A"
	p.SourceIP = "10.9.0.3"
	b, _ := json.Marshal(EvidenceFile{SchemaVersion: 1, Observations: []Observation{o, p}})
	if err := os.WriteFile(f, b, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := report(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 2 || r[0].Direction == r[1].Direction {
		t.Fatalf("directions collapsed %+v", r)
	}
}
func TestAddSourceJSON(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "sources.json")
	a := Candidate{IP: "10.9.9.1", Direction: "A_TO_B", Sender: "A", Receiver: "B"}
	if err := addSource(path, "private_lab", a); err != nil {
		t.Fatal(err)
	}
	b := Candidate{IP: "10.9.9.2", Direction: "B_TO_A", Sender: "B", Receiver: "A"}
	if err := addSource(path, "", b); err != nil {
		t.Fatal(err)
	}
	c, err := readCandidates(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Candidates) != 2 {
		t.Fatalf("expected two got %d", len(c.Candidates))
	}
	if err := addSource(path, "", a); err == nil {
		t.Fatal("duplicate source silently accepted")
	}
	if err := addSource(path, "approved_field_plan", b); err == nil {
		t.Fatal("mode change silently accepted")
	}
	if err := os.Symlink(path, filepath.Join(d, "link.json")); err != nil {
		t.Fatal(err)
	}
	if err := addSource(filepath.Join(d, "link.json"), "", b); err == nil {
		t.Fatal("symlink silently accepted")
	}
}
