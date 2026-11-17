package maintenance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These fixtures reuse the canonical installer record, executable digest,
// symlink alias and recovery-journal proofs. No production binary is touched.
func TestCompletedInstallationReceiptProofWithCanonicalJournal(t *testing.T) {
	for _, tc := range []struct {
		name       string
		prepare    func(t *testing.T, g Gate, stage, hash string)
		wantReject bool
	}{
		{"fully committed no retained journal", func(t *testing.T, _ Gate, stage, _ string) {
			t.Helper()
			if err := os.RemoveAll(stage); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"verified retained COMMITTED update", func(t *testing.T, _ Gate, stage, hash string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(stage, committedName), []byte(journalV1("update", hash)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"uncommitted transaction retained", func(t *testing.T, _ Gate, _, _ string) {
			t.Helper()
		}, true},
		{"incomplete COMMITTED marker retained", func(t *testing.T, _ Gate, stage, _ string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(stage, committedName), []byte("status=committed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"committed journal mismatches binary digest", func(t *testing.T, _ Gate, stage, _ string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(stage, committedName), []byte(journalV1("update", strings.Repeat("a", 64))), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"missing install-record", func(t *testing.T, g Gate, stage, _ string) {
			t.Helper()
			if err := os.RemoveAll(stage); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(g.Directory, RecordName)); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"invalid install-record", func(t *testing.T, g Gate, stage, _ string) {
			t.Helper()
			if err := os.RemoveAll(stage); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(g.Directory, RecordName),
				[]byte("format=1\nproject=simple-tun-link\nversion=v0.1.0\nsha256=bad\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"record permissions too broad", func(t *testing.T, g Gate, stage, _ string) {
			t.Helper()
			if err := os.RemoveAll(stage); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(g.Directory, RecordName), 0o644); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"record and executable sha256 mismatch", func(t *testing.T, g Gate, stage, _ string) {
			t.Helper()
			if err := os.RemoveAll(stage); err != nil {
				t.Fatal(err)
			}
			next := filepath.Join(g.Directory, "next-stl")
			if err := os.WriteFile(next, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(next, g.Canonical); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"alias no longer installer-owned", func(t *testing.T, g Gate, stage, _ string) {
			t.Helper()
			if err := os.RemoveAll(stage); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(g.Directory, "stlink")); err != nil {
				t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, stage, hash := installedJournalFixture(t)
			tc.prepare(t, g, stage, hash)
			err := g.VerifyCompletedInstallation("v0.1.0")
			if (err != nil) != tc.wantReject {
				t.Fatalf("completed installation proof: wantReject=%v err=%v", tc.wantReject, err)
			}
		})
	}
}

// Reproduce the same post-swap failure shape as the existing
// STL_INSTALL_TEST_CORRUPT_BACKUP shell fixture: a newly installed
// executable reports the signed target, but the old install-record
// and an UNCOMMITTED recovery transaction remain.
func TestCompletedInstallationReceiptRejectsPartialCompensationNewExecutable(t *testing.T) {
	g, stage, _ := installedJournalFixture(t)
	const newCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	next := filepath.Join(g.Directory, "incoming")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' '{\"schema_version\":1,\"version\":\"v0.1.1\",\"commit\":\"" + newCommit + "\"}'\n"
	if err := os.WriteFile(next, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, g.Canonical); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(g.Canonical, "version", "--json").Output()
	if err != nil || !strings.Contains(string(raw), "\"version\":\"v0.1.1\"") ||
		!strings.Contains(string(raw), newCommit) {
		t.Fatalf("partial-state new executable does not report signed target: %q err=%v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(stage, committedName)); !os.IsNotExist(err) {
		t.Fatalf("partial rollback unexpectedly has committed journal: %v", err)
	}
	if err := g.VerifyCompletedInstallation("v0.1.1"); err == nil {
		t.Fatal("matching signed executable advanced receipt despite old record and unresolved journal")
	}
	// Even removing the unresolved journal (which real recovery MUST NOT do)
	// cannot make an older record authorize the new executable.
	if err := os.RemoveAll(stage); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyCompletedInstallation("v0.1.1"); err == nil {
		t.Fatal("new executable was mistaken for a completed installer-owned version")
	}
}

func TestCompletedInstallationReceiptRejectsDifferentRecordVersion(t *testing.T) {
	g, stage, _ := installedJournalFixture(t)
	if err := os.RemoveAll(stage); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyCompletedInstallation("v0.1.1"); err == nil {
		t.Fatal("signed target differs from canonical installed record version")
	}
}
