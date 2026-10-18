package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMenuHelperProcess(t *testing.T) {
	if os.Getenv("SPOOFDIAG_TEST_MENU") != "1" {
		return
	}
	if err := run([]string{"menu"}); err != nil {
		t.Fatal(err)
	}
}

func testMenuSession(t *testing.T, input string) (string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMenuHelperProcess$")
	cmd.Env = append(os.Environ(), "SPOOFDIAG_TEST_MENU=1", "NO_COLOR=1", "COLUMNS=54")
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("menu terminated on valid or invalid input: %v\nSTDOUT:\n%s\nSTDERR:\n%s", err, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String()
}

func TestMenuInvalidInputRecoverAndEOF(t *testing.T) {
	out, errs := testMenuSession(t, "wrong\n3\n?\n4\n/nonexistent/evidence.json\n1\n2\n8\n0\n")
	if strings.Count(out, "STL SPOOF DIAGNOSTICS") != 7 {
		t.Fatalf("menu did not return to top-level after errors (%d): %s", strings.Count(out, "STL SPOOF DIAGNOSTICS"), out)
	}
	for _, want := range []string{"Mode: loopback", "Field traffic: DISABLED", "Evidence levels:", "Go", "Goodbye"} {
		if !strings.Contains(out, want) && !(want == "Go" && strings.Contains(out, "go")) {
			t.Fatalf("menu missing %q: %s", want, out)
		}
	}
	if !strings.Contains(errs, "Unknown choice") || !strings.Contains(errs, "Operation not completed") {
		t.Fatalf("malformed inputs did not produce actionable recoverable errors: %s", errs)
	}
	out, errs = testMenuSession(t, "")
	if !strings.Contains(out, "Session ended.") || errs != "" {
		t.Fatalf("EOF should end normally, got %s / %s", out, errs)
	}
}

func TestMenuInventoryFullLifecycle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sources.json")
	sequence := strings.Join([]string{
		"3", "2", path, "private_lab", "10.91.1.77", "A_TO_B", "A", "B",
		"3", "1", path,
		"3", "5", path, "10.91.1.77", "A_TO_B", "A", "B", "10.91.1.78", "B_TO_A", "B", "A",
		"3", "1", path,
		"3", "4", path, "10.91.1.78", "B_TO_A", "B", "A",
		"3", "1", path,
		"3", "2", path, "", "8.8.8.8", "A_TO_B", "A", "B",
		"0",
	}, "\n") + "\n"
	out, errs := testMenuSession(t, sequence)
	if !strings.Contains(out, "NO_CANDIDATES_NOT_RUN") || !strings.Contains(out, "10.91.1.78") {
		t.Fatalf("menu inventory didn't maintain direction or fail closed on empty list: %s", out)
	}
	if !strings.Contains(errs, "Operation not completed") || !strings.Contains(errs, "private_lab requires RFC1918") {
		t.Fatalf("invalid public source not rejected with meaningful error: %s", errs)
	}
	inv, err := readCandidateInventory(path, true)
	if err != nil || len(inv.Candidates) != 0 {
		t.Fatalf("expected empty safely stored inventory: %+v %v", inv, err)
	}
	if _, err := readCandidates(path); err == nil {
		t.Fatal("empty candidates unexpectedly runnable")
	}
}

func TestMenuOversizedLineDoesNotSkipNextChoice(t *testing.T) {
	out, errs := testMenuSession(t, strings.Repeat("x", 20000)+"\n8\n0\n")
	if !strings.Contains(errs, "input too long") || !strings.Contains(out, "Requirements: Linux") {
		t.Fatalf("oversized input shifted prompt or escaped: %s / %s", out, errs)
	}
}
