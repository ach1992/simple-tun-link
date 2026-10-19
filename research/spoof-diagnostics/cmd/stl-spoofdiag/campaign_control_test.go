package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
	if _, err := os.Stat(campaignControlFile(dir)); !os.IsNotExist(err) {
		t.Fatal("default status created a control file without operator request")
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
