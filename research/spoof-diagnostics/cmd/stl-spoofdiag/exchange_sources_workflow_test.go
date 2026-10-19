package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTXTAutoReadDirectLargeCampaignAndStageCLI(t *testing.T) {
	base := filepath.Join(t.TempDir(), "exchange")
	if err := exchangeCLI([]string{"init", "--base", base}); err != nil {
		t.Fatal(err)
	}
	var input strings.Builder
	input.WriteString(sourceTXTAB + "\n")
	const n = 12000
	for i := 0; i < n; i++ {
		fmt.Fprintf(&input, "10.77.%d.%d\n", i/250, i%250+1)
	}
	path := filepath.Join(base, "inbox", "ip.txt")
	if err := os.WriteFile(path, []byte(input.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exchangeCLI([]string{"sources", "inspect", "--base", base}); err != nil {
		t.Fatal(err)
	}
	// No extra CLI confirmation: placing ip.txt and invoking stage is enough.
	if err := exchangeCLI([]string{"sources", "stage", "--base", base}); err != nil {
		t.Fatal(err)
	}
	campaign := filepath.Join(t.TempDir(), "campaign")
	m, err := createCampaign(path, campaign, testCampaignSettings())
	if err != nil || m.SourceCount != n || len(m.Batches) != 375 || m.TTLSeconds != 600 {
		t.Fatalf("large direct ip.txt Campaign failed: %+v %v", m, err)
	}
	got, err := readCampaign(campaign)
	if err != nil || got.CampaignID != m.CampaignID {
		t.Fatalf("offline Campaign unreadable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(campaign, "runs", "batch-00001")); !os.IsNotExist(err) {
		t.Fatal("Campaign creation silently initiated a Field run")
	}
}

func TestTXTMixedInboxIsNotMisreadAsSignedEvidence(t *testing.T) {
	f := exchangeGenerateFixture(t, 1, true)
	base := filepath.Join(t.TempDir(), "exchange")
	if err := exchangeCreateBase(base); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "inbox", "ip.txt")
	if err := os.WriteFile(source, []byte(sourceTXTAB+"\n10.20.30.40\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inputs := []string{source}
	for i, zip := range f.zips {
		path := filepath.Join(base, "inbox", fmt.Sprintf("evidence-%d", i))
		exchangeCopyFixtureFile(t, zip, path)
		inputs = append(inputs, path)
	}
	result, err := exchangeImport(base, f.ca, inputs, f.caseID)
	if err != nil || len(result) != 5 || result[0].Status != "SOURCE_INVENTORY_STAGED_NOT_AUTHORIZED" {
		t.Fatalf("mixed inbox did not auto-identify TXT: %+v %v", result, err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatal("operator's TXT was deleted")
	}
	r, err := exchangeAnalyze(f.caseID, f.ca, inputs)
	if err != nil || r.Status != "COMPLETE_SIGNED_EVIDENCE_NOT_CONNECTIVITY_PROOF" ||
		len(r.Inputs) != 4 || len(r.Rejected) != 0 {
		t.Fatalf("harmless TXT corrupted signed four-bundle report: %v, %+v", err, r)
	}
}

func TestTXTSourceInputSafety(t *testing.T) {
	base := filepath.Join(t.TempDir(), "exchange")
	if err := exchangeCreateBase(base); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(base, "inbox", "ip.txt")
	if err := os.WriteFile(original, []byte(sourceTXTAB+"\n10.20.30.40\n"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(base, "inbox", "linked")
	if err := os.Symlink(original, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := exchangeSourceStage(base, symlink); err == nil {
		t.Fatal("symlink inventory accepted")
	}
	saved, _, _, err := exchangeSourceStage(base, original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saved, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := exchangeSourceStage(base, original); err == nil {
		t.Fatal("conflicting digest-named source was silently overwritten")
	}
}

func TestSingleDirectionTXTInfersCampaignRoleWithoutExtraFlags(t *testing.T) {
	for _, tc := range []struct{ header, direction, sender, receiver string }{
		{sourceTXTAB, "A_TO_B", "A", "B"},
		{sourceTXTBA, "B_TO_A", "B", "A"},
	} {
		t.Run(tc.direction, func(t *testing.T) {
			root := t.TempDir()
			input := filepath.Join(root, "any-filename")
			if err := os.WriteFile(input, []byte(tc.header+"\n10.20.30.40\n"), 0600); err != nil {
				t.Fatal(err)
			}
			campaign := filepath.Join(root, "campaign")
			if err := campaignCLI([]string{"create", "--file", input, "--dir", campaign, "--destination-ip", "10.20.30.50"}); err != nil {
				t.Fatal(err)
			}
			manifest, err := readCampaign(campaign)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Direction != tc.direction || manifest.Sender != tc.sender || manifest.Receiver != tc.receiver || manifest.SourceCount != 1 {
				t.Fatalf("campaign ignored one-line header: %+v", manifest)
			}
		})
	}
}

func TestMenuCampaignTXTNeedsNoDirectionPrompt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ip.txt")
	campaign := filepath.Join(root, "campaign")
	if err := os.WriteFile(path, []byte(sourceTXTBA+"\n10.20.30.40\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input := fmt.Sprintf("%s\n%s\n10.20.30.50\n\n", path, campaign)
	if err := menuCampaignCreate(bufio.NewReader(strings.NewReader(input))); err != nil {
		t.Fatal(err)
	}
	manifest, err := readCampaign(campaign)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Direction != "B_TO_A" {
		t.Fatalf("menu did not infer B_TO_A: %+v", manifest)
	}
}

func TestMixedCSVLegacyDefaultAndExplicitDirection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "inventory.csv")
	data := "ip,direction,sender,receiver\n10.20.30.40,A_TO_B,A,B\n10.20.30.41,B_TO_A,B,A\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		extra    []string
		expected string
	}{
		{nil, "A_TO_B"},
		{[]string{"--direction", "B_TO_A"}, "B_TO_A"},
	} {
		campaign := filepath.Join(root, tc.expected)
		args := append([]string{"create", "--file", path, "--dir", campaign, "--destination-ip", "10.20.30.50"}, tc.extra...)
		if err := campaignCLI(args); err != nil {
			t.Fatal(err)
		}
		manifest, err := readCampaign(campaign)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.Direction != tc.expected || manifest.SourceCount != 1 {
			t.Fatalf("legacy mixed inventory selection wrong: %+v", manifest)
		}
	}
}

func TestMenuCampaignMixedSourceStillPromptsForDirection(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "both.csv")
	data := "ip,direction,sender,receiver\n10.20.30.40,A_TO_B,A,B\n10.20.30.41,B_TO_A,B,A\n"
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	campaign := filepath.Join(root, "campaign")
	operatorInput := fmt.Sprintf("%s\nB_TO_A\n%s\n10.20.30.50\n\n", file, campaign)
	if err := menuCampaignCreate(bufio.NewReader(strings.NewReader(operatorInput))); err != nil {
		t.Fatal(err)
	}
	manifest, err := readCampaign(campaign)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Direction != "B_TO_A" || manifest.SourceCount != 1 {
		t.Fatalf("lost mixed-direction menu selection: %+v", manifest)
	}
}
