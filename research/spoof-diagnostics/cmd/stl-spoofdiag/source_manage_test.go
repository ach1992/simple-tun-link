package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCandidateInventoryLifecycleAndEmptyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.json")
	a := Candidate{IP: "10.91.1.77", Direction: "A_TO_B", Sender: "A", Receiver: "B"}
	b := Candidate{IP: "10.91.1.77", Direction: "B_TO_A", Sender: "B", Receiver: "A"}
	if err := addSource(path, "field_candidates", a); err != nil {
		t.Fatal(err)
	}
	if err := addSource(path, "", b); err != nil {
		t.Fatal(err)
	}
	original, err := readCandidates(path)
	if err != nil || len(original.Candidates) != 2 {
		t.Fatalf("could not store independent directions: %+v %v", original, err)
	}
	if err := removeCandidate(path, a); err != nil {
		t.Fatal(err)
	}
	if err := removeCandidate(path, a); err == nil {
		t.Fatal("second removal without exact identity accepted")
	}
	remaining, err := readCandidates(path)
	if err != nil || len(remaining.Candidates) != 1 || remaining.Candidates[0].Direction != "B_TO_A" {
		t.Fatalf("independent reverse direction was modified: %+v %v", remaining, err)
	}
	if err := removeCandidate(path, b); err != nil {
		t.Fatal(err)
	}
	empty, err := readCandidateInventory(path, true)
	if err != nil || len(empty.Candidates) != 0 {
		t.Fatalf("empty managed inventory not preserved: %+v %v", empty, err)
	}
	if _, err := readCandidates(path); err == nil {
		t.Fatal("empty candidate plan incorrectly allowed")
	}
	if err := addSource(path, "", a); err != nil {
		t.Fatalf("cannot add again to empty owned file: %v", err)
	}
	if err := replaceCandidate(path, a, b); err != nil {
		t.Fatal(err)
	}
	after, err := readCandidates(path)
	if err != nil || len(after.Candidates) != 1 || after.Candidates[0].Direction != "B_TO_A" {
		t.Fatal("atomic candidate replacement failed")
	}
	unsafe := b
	unsafe.IP = "198.51.100.7"
	if err := replaceCandidate(path, b, unsafe); err == nil {
		t.Fatal("documentation source accepted as field candidate")
	}
	still, err := readCandidates(path)
	if err != nil || still.Candidates[0].IP != b.IP {
		t.Fatal("bad replacement mutated original inventory")
	}
	if err := run([]string{"sources", "list", "--file", path}); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateImportMergeAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.json")
	csv := filepath.Join(dir, "import.csv")
	data := "ip,direction,sender,receiver\n10.91.1.77,A_TO_B,A,B\n10.91.1.78,A_TO_B,A,B\n"
	if err := os.WriteFile(csv, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	added, err := importCandidates(path, csv)
	if err != nil || added != 2 {
		t.Fatalf("failed initial CSV import: %v", err)
	}
	if _, err := importCandidates(path, csv); err == nil {
		t.Fatal("duplicate merge accepted")
	}
	c, err := readCandidates(path)
	if err != nil || len(c.Candidates) != 2 {
		t.Fatal("duplicate merge modified source")
	}
	if _, err := importCandidates(path, path); err == nil {
		t.Fatal("source/dest self import accepted")
	}
	field := filepath.Join(dir, "field.json")
	if err := os.WriteFile(field, []byte(`{"schema_version":1,"mode":"field_candidates","candidates":[{"ip":"203.0.113.2","direction":"A_TO_B","sender":"A","receiver":"B"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := importCandidates(path, field); err == nil {
		t.Fatal("reserved field candidate admitted")
	}
	symlink := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if err := removeCandidate(symlink, c.Candidates[0]); err == nil {
		t.Fatal("symlinked inventory modified")
	}
	if _, err := importCandidates(symlink, csv); err == nil {
		t.Fatal("symlink inventory accepted")
	}
}
