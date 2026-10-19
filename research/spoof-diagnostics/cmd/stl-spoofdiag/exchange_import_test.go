package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExchangeImportInertArchiveQuarantineAndIdempotence(t *testing.T) {
	f := exchangeGenerateFixture(t, 1, true)
	ex := filepath.Join(t.TempDir(), "private")
	if err := exchangeCreateBase(ex); err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(ex, "inbox", "my-manually-transferred-data")
	exchangeCopyFixtureFile(t, f.zips[0], renamed)
	results, err := exchangeImport(ex, f.ca, []string{renamed}, f.caseID)
	if err != nil || len(results) != 1 || results[0].Status != "ARCHIVED_VERIFIED_COPY" {
		t.Fatalf("valid signed bundle failed import: %+v %v", results, err)
	}
	if _, err := os.Stat(renamed); err != nil {
		t.Fatal("import removed user inbox file", err)
	}
	archived := results[0].ArchiveFile
	if _, err := os.Stat(archived); err != nil {
		t.Fatal(err)
	}
	results, err = exchangeImport(ex, f.ca, []string{renamed}, f.caseID)
	if err != nil || results[0].Status != "ALREADY_ARCHIVED_IDENTICAL" {
		t.Fatalf("non-idempotent import: %+v %v", results, err)
	}
	report, err := exchangeAnalyze(f.caseID, f.ca, []string{archived})
	if err != nil || report.Status != "INCOMPLETE" || len(report.Inputs) != 1 {
		t.Fatalf("archived bundle cannot be analyzed: %+v %v", report, err)
	}
	invalid := filepath.Join(ex, "inbox", "bogus.zip")
	if err := os.WriteFile(invalid, []byte("not a trusted ZIP"), 0600); err != nil {
		t.Fatal(err)
	}
	results, err = exchangeImport(ex, f.ca, []string{invalid}, "")
	if err != nil || len(results) != 1 || results[0].Status != "REJECTED_QUARANTINED_UNTRUSTED_DATA" {
		t.Fatalf("untrusted data was not quarantined: %+v %v", results, err)
	}
	if !strings.Contains(results[0].ArchiveFile, "/rejected/") {
		t.Fatal("untrusted data escaped rejected directory")
	}
	results, err = exchangeImport(ex, f.ca, []string{invalid}, "")
	if err != nil || results[0].Status != "REJECTED_ALREADY_QUARANTINED" {
		t.Fatalf("rejected data import non-idempotent: %+v %v", results, err)
	}
	link := filepath.Join(ex, "inbox", "symlink.zip")
	if err := os.Symlink(f.zips[1], link); err != nil {
		t.Fatal(err)
	}
	results, err = exchangeImport(ex, f.ca, []string{link}, "")
	if err != nil || results[0].Status != "REJECTED_NOT_COPIED_UNSAFE_INPUT" {
		t.Fatalf("symlink import not rejected: %+v %v", results, err)
	}
}

func TestExchangeUnpairedReceiverEvidenceAndConflictingSignedExports(t *testing.T) {
	f := exchangeGenerateFixture(t, 1, true)
	// A retained the challenge/grant but lost its sender attempt report.
	// B still has independently signed packet observations. Reporting them
	// as confirmed sender submissions would be an evidentiary overclaim.
	senderPath := filepath.Join(campaignAttemptDir(f.dirs[0], 1, 1), "sender.json")
	if err := os.Remove(senderPath); err != nil {
		t.Fatal(err)
	}
	otherRoot := filepath.Join(t.TempDir(), "private-output")
	if err := os.Mkdir(otherRoot, 0700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(otherRoot, "new-sender-archive.zip")
	if _, err := exchangeSignBundle(f.caseID, f.dirs[0], "sender",
		filepath.Join(f.ids, "A.crt"), filepath.Join(f.ids, "A.key"), f.ca, other); err != nil {
		t.Fatal(err)
	}
	set := []string{other, f.zips[1], f.zips[2], f.zips[3]}
	report, err := exchangeAnalyze(f.caseID, f.ca, set)
	if err != nil || report.Status != "INCOMPLETE" ||
		report.Directions[0].Runs[0].ObservedWithoutSubmitted != 1 ||
		report.Directions[0].Runs[0].Samples[0].SenderState != "NO_DECLARED_ATTEMPT" ||
		report.Directions[0].Runs[0].Samples[0].ReceiverState != "AUTHENTICATED_OBSERVED" {
		t.Fatalf("missing sender submission overclaimed: %+v %v", report, err)
	}
	set = append(set, f.zips[0])
	report, err = exchangeAnalyze(f.caseID, f.ca, set)
	if err != nil || report.Status != "INCOMPLETE" || len(report.Conflicts) == 0 {
		t.Fatalf("conflicting independently signed sender snapshots silently accepted: %+v %v", report, err)
	}
}

func TestExchangeRejectsZIPSymlinkEntries(t *testing.T) {
	f := exchangeGenerateFixture(t, 1, false)
	filename := filepath.Join(t.TempDir(), "symlink-in-archive.zip")
	fd, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(fd)
	header := &zip.FileHeader{Name: "danger.json", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0600)
	h, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write([]byte("/tmp/something")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	fd.Close()
	if _, err := exchangeOpenBundle(filename, f.ca); err == nil {
		t.Fatal("archive symlink entry accepted")
	}
}

func TestExchangeManyBatchesCanExportWithoutRunOrNetwork(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	original := testCandidateInventory(t, 1536, "10.99.0.2")
	dir := filepath.Join(t.TempDir(), "campaign")
	m, err := createCampaign(original, dir, testCampaignSettings())
	if err != nil || len(m.Batches) != 48 {
		t.Fatalf("large inventory setup failed %v", err)
	}
	outRoot := filepath.Join(t.TempDir(), "private-output")
	if err := os.Mkdir(outRoot, 0700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(outRoot, "large-offline.zip")
	if _, err := exchangeSignBundle("abcdefabcdefabcdefabcdefabcdefab", dir, "sender",
		filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"), ca, out); err != nil {
		t.Fatal(err)
	}
	b, err := exchangeOpenBundle(out, ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchangeValidateBundleContent(b, ca); err != nil {
		t.Fatal(err)
	}
	if len(b.Manifest.Files) != 49 {
		t.Fatalf("wrong number of signed batch files: %d", len(b.Manifest.Files))
	}
}
