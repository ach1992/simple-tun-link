package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCampaignPauseResumeAndTerminalStopNeverSends(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	source := testCandidateInventory(t, 3, "")
	dir := filepath.Join(t.TempDir(), "campaign")
	_, err := createCampaign(source, dir, testCampaignSettings())
	if err != nil {
		t.Fatal(err)
	}
	before, err := campaignControlStatus(dir, ca)
	if err != nil || before["control_state"] != "ACTIVE" {
		t.Fatalf("bad default: %+v %v", before, err)
	}
	// Campaign creation owns a mandatory active control record. Merely
	// reading status must not change its revision.
	if st, err := os.Lstat(campaignControlFile(dir)); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("new Campaign lacks mandatory state: %v", err)
	}
	if before["control_revision"] != 1 {
		t.Fatalf("status unexpectedly changed initial revision: %+v", before)
	}
	paused, err := changeCampaignControl(dir, "pause", "Review the first batch")
	if err != nil || paused["state"] != "PAUSED" {
		t.Fatal(paused, err)
	}
	old, err := changeCampaignControl(dir, "pause", "Repeated pause")
	if err != nil || old["status"] != "UNCHANGED_ALREADY_IN_STATE" {
		t.Fatal(old, err)
	}
	m, err := readCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireCampaignActive(dir, m); err == nil {
		t.Fatal("paused campaign admitted a new operation")
	}
	cert, key := filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key")
	if _, err := campaignNext(dir, cert, key, ca, false); err == nil {
		t.Fatal("campaign next ignored pause")
	}
	if _, err := campaignSend(context.Background(), dir, cert, key, ca, "", false); err == nil {
		t.Fatal("strict campaign send ignored pause")
	}
	if _, err := changeCampaignControl(dir, "resume", "Operator checks complete"); err != nil {
		t.Fatal(err)
	}
	if _, err := campaignNext(dir, cert, key, ca, false); err != nil {
		t.Fatal("signed offline batch preparation blocked after resume", err)
	}
	status, err := campaignControlStatus(dir, ca)
	if err != nil {
		t.Fatal(err)
	}
	if status["control_state"] != "ACTIVE" {
		t.Fatal(status)
	}
	if _, err := changeCampaignControl(dir, "stop", ""); err == nil {
		t.Fatal("empty stop reason accepted")
	}
	stopped, err := changeCampaignControl(dir, "stop", "Enough evidence collected; remaining IPs untested")
	if err != nil || stopped["state"] != "STOPPED_BY_OPERATOR" {
		t.Fatal(stopped, err)
	}
	if _, err := campaignNext(dir, cert, key, ca, false); err == nil {
		t.Fatal("stopped campaign generated another batch")
	}
	if _, err := campaignSend(context.Background(), dir, cert, key, ca, "", false); err == nil {
		t.Fatal("stopped campaign admitted additional sender operation")
	}
	if _, err := changeCampaignControl(dir, "resume", ""); err == nil {
		t.Fatal("terminal stop was reversible")
	}
	if _, err := changeCampaignControl(dir, "pause", ""); err == nil {
		t.Fatal("terminal stop was reset to paused")
	}
	if _, err := changeCampaignControl(dir, "stop", "same stop"); err != nil {
		t.Fatal("idempotent stop failed", err)
	}
	if _, err := os.Stat(filepath.Join(campaignAttemptDir(dir, 1, 1), "sender.json")); !os.IsNotExist(err) {
		t.Fatal("control test unexpectedly created sender evidence or sent data")
	}
}

func TestCampaignControlInvalidStateFailsClosedAndFlock(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	source := testCandidateInventory(t, 1, "")
	dir := filepath.Join(t.TempDir(), "campaign")
	_, err := createCampaign(source, dir, testCampaignSettings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changeCampaignControl(dir, "pause", "reason\nwith newline"); err == nil {
		t.Fatal("newline control reason was accepted")
	}
	// Flock protects transition against an in-flight Batch operation.
	lock, err := os.Open(filepath.Join(dir, "campaign.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	_, err = changeCampaignControl(dir, "pause", "locked")
	if err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatal("concurrent Campaign control mutation accepted", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if _, err := changeCampaignControl(dir, "pause", "normal"); err != nil {
		t.Fatal(err)
	}
	path := campaignControlFile(dir)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Local state corruption must be rejected rather than default to ACTIVE.
	broken := strings.Replace(string(b), "PAUSED", "ACTIVE_TAMPERED", 1)
	if err := os.WriteFile(path, []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := campaignNext(dir, filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"), ca, false); err == nil {
		t.Fatal("invalid control silently defaulted to ACTIVE")
	}
}

func TestStoppedCampaignNeverSilentlyReactivatesIfControlDisappears(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	source := testCandidateInventory(t, 2, "")
	dir := filepath.Join(t.TempDir(), "campaign")
	m, err := createCampaign(source, dir, testCampaignSettings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changeCampaignControl(dir, "stop", "Operator explicitly ended this campaign"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(campaignStopFile(dir)); err != nil {
		t.Fatalf("terminal marker missing: %v", err)
	}
	if err := os.Remove(campaignControlFile(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := readCampaignControl(dir, m); err == nil {
		t.Fatal("missing STOP record reverted to ACTIVE")
	}
	if err := requireCampaignActive(dir, m); err == nil {
		t.Fatal("missing STOP record allowed network operation")
	}
	cert, key := filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key")
	if _, err := campaignNext(dir, cert, key, ca, false); err == nil {
		t.Fatal("removed STOP record unlocked next")
	}
	if _, err := campaignSend(context.Background(), dir, cert, key, ca, "", false); err == nil {
		t.Fatal("removed STOP record unlocked send")
	}
	if _, err := changeCampaignControl(dir, "resume", ""); err == nil {
		t.Fatal("removed STOP record allowed resume")
	}
	if _, err := changeCampaignControl(dir, "adopt", legacyCampaignAdoption); err == nil {
		t.Fatal("terminal marker allowed legacy adoption")
	}
	// Even a fake earlier ACTIVE state file does not override the separate
	// terminal marker. A real operator may only create a NEW Campaign.
	fake := campaignControl{Format: campaignControlFormat, CampaignID: m.CampaignID,
		ManifestSHA256: mustCampaignDigestForTest(t, dir), State: "ACTIVE", Revision: 1,
		Reason: "FAKE_OLD", UpdatedUTC: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := writeStagedJSON(campaignControlFile(dir), fake, false); err != nil {
		t.Fatal(err)
	}
	if err := requireCampaignActive(dir, m); err == nil {
		t.Fatal("terminal marker ignored on ACTIVE rollback")
	}
}

func mustCampaignDigestForTest(t *testing.T, dir string) string {
	t.Helper()
	b, err := readSmallRegular(filepath.Join(dir, "campaign.json"), 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	return digestBytes(b)
}

func TestLegacyCampaignWithoutControlFailsClosedUntilExplicitAdoption(t *testing.T) {
	ids, ca := testCampaignIdentity(t)
	source := testCandidateInventory(t, 1, "")
	dir := filepath.Join(t.TempDir(), "campaign")
	m, err := createCampaign(source, dir, testCampaignSettings())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an old created Campaign without the new mandatory state.
	if err := os.Remove(campaignControlFile(dir)); err != nil {
		t.Fatal(err)
	}
	if err := requireCampaignActive(dir, m); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent legacy control should be fail-closed missing state: %v", err)
	}
	if _, err := campaignNext(dir, filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"), ca, false); err == nil {
		t.Fatal("missing legacy state silently enabled next")
	}
	if _, err := changeCampaignControl(dir, "resume", ""); err == nil {
		t.Fatal("legacy resume bypassed explicit adoption")
	}
	if _, err := changeCampaignControl(dir, "adopt", "I think this was active"); err == nil {
		t.Fatal("ambiguous legacy adoption accepted")
	}
	result, err := changeCampaignControl(dir, "adopt", legacyCampaignAdoption)
	if err != nil || result["status"] != "LEGACY_CONTROL_ADOPTED_EXPLICITLY" {
		t.Fatalf("legacy migration failed: %+v / %v", result, err)
	}
	if err := requireCampaignActive(dir, m); err != nil {
		t.Fatal(err)
	}
	if _, err := campaignNext(dir, filepath.Join(ids, "A.crt"), filepath.Join(ids, "A.key"), ca, false); err != nil {
		t.Fatalf("explicitly adopted legacy Campaign did not resume normal strict plan: %v", err)
	}
}
