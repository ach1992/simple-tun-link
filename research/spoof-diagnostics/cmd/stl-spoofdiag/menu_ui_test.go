package main

import (
	"bufio"
	"strings"
	"testing"
)

// Offline menu parser checks; no network packets or peers.
func TestMenuBoundedInput(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", 20000) + "\n0\n"))
	if _, err := menuRead(reader); err == nil {
		t.Fatal("oversized menu input accepted")
	}
	next, err := menuRead(reader)
	if err != nil || next != "0" {
		t.Fatalf("menu lost subsequent input: %q %v", next, err)
	}
}

// The campaign receiver action must not run merely because paths exist.
func TestMenuCampaignReceiverNeedsExplicitConsent(t *testing.T) {
	input := "/not-a-real-campaign\nB.crt\nB.key\nca.crt\n\nCANCEL\n"
	reader := bufio.NewReader(strings.NewReader(input))
	err := menuCampaignReceive(reader)
	if err == nil || !strings.Contains(err.Error(), "receiver operation not selected") {
		t.Fatalf("receiver action not gated on explicit consent: %v", err)
	}
}

func TestMenuCampaignReceiverRejectsTruncatedInput(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("/not-a-real-campaign\n"))
	if err := menuCampaignReceive(reader); err == nil {
		t.Fatal("truncated receiver form accepted")
	}
}
