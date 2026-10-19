package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExchangeCLIEntireOfflineFlowAndPrivatePaths(t *testing.T) {
	f := exchangeGenerateFixture(t, 1, true)
	base := filepath.Join(t.TempDir(), "my-exchange")
	if err := exchangeCLI([]string{"init", "--base", base}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"inbox", "outbox", "reports", "archive", "rejected"} {
		st, err := os.Lstat(filepath.Join(base, name))
		if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			t.Fatalf("unsafe initialized directory %s: %v", name, err)
		}
	}
	for i, file := range f.zips {
		exchangeCopyFixtureFile(t, file, filepath.Join(base, "inbox", "any-file-name-"+string(rune('a'+i))))
	}
	if err := exchangeCLI([]string{"import", "--base", base, "--ca", f.ca, "--case-id", f.caseID}); err != nil {
		t.Fatal(err)
	}
	if err := exchangeCLI([]string{"analyze", "--base", base, "--ca", f.ca, "--case-id", f.caseID}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "reports", "SDX-"+f.caseID+"-verified.json")
	result, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(result), "COMPLETE_SIGNED_EVIDENCE_NOT_CONNECTIVITY_PROOF") {
		t.Fatalf("CLI did not produce a complete signed-evidence report: %v", err)
	}
	if err := exchangeCLI([]string{"analyze", "--base", base, "--ca", f.ca, "--case-id", f.caseID}); err != nil {
		t.Fatal("CLI must idempotently reproduce reports:", err)
	}
	if err := exchangeCLI([]string{"analyze", "--case-id", f.caseID}); err == nil {
		t.Fatal("CLI allowed analysis without independent trust anchor")
	}
	if err := exchangeCLI([]string{"import", "--base", base, "--ca", f.ca, "--case-id", "not-an-id"}); err == nil {
		t.Fatal("CLI imported malformed case ID")
	}
}
