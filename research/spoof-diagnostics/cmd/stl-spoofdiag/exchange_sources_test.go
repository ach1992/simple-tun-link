package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// All cases below exercise only local file parsing, durable batch preparation,
// and report-planning arithmetic. They never create a network socket.
func TestExchangeSourceTextSimpleHeaderAndRoleMapping(t *testing.T) {
	inputs := []struct{ name, body, direction, sender, receiver string }{
		{"a_crlf_bom", "\ufeff# SDX-IP-LIST v1 direction=A_TO_B\r\n\r\n# operator comment\r\n10.24.1.2\r\n10.24.1.3\r\n", "A_TO_B", "A", "B"},
		{"b_lf", "# SDX-IP-LIST v1 direction=B_TO_A\n10.24.1.2\n# note\n10.24.1.3\n", "B_TO_A", "B", "A"},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := exchangeParseSourceBytes([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if got.SchemaVersion != schema || got.Mode != "field_candidates" || len(got.Candidates) != 2 {
				t.Fatalf("wrong inventory shape: %+v", got)
			}
			for _, item := range got.Candidates {
				if item.Direction != tc.direction || item.Sender != tc.sender || item.Receiver != tc.receiver {
					t.Fatalf("incorrect inferred role: %+v", item)
				}
			}
		})
	}
}

func TestExchangeSourceTextInvalidFormatsDoNotBecomeCampaigns(t *testing.T) {
	cases := []string{
		"",
		"10.24.1.1\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n",
		"# SDX-IP-LIST v1 direction=ANY\n10.24.1.1\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n10.24.1.1\n10.24.1.1\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n10.24.1.1/32\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n10.24.1.1:9999\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n# SDX-IP-LIST v1 direction=B_TO_A\n10.24.1.1\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n203.0.113.4\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n10.24.1.1 # trailing data\n",
		"# SDX-IP-LIST v1 direction=A_TO_B\n10.24.1.1\ninvalid\n",
	}
	for i, bad := range cases {
		t.Run(fmt.Sprintf("invalid-%d", i), func(t *testing.T) {
			if _, err := exchangeParseSourceBytes([]byte(bad)); err == nil {
				t.Fatalf("accepted invalid text inventory: %q", bad)
			}
		})
	}
}

func TestExchangeSourceTXTStagesOnceAndFeedsExistingCampaign(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "exchange")
	if err := exchangeCreateBase(base); err != nil {
		t.Fatal(err)
	}
	infile := filepath.Join(base, "inbox", "ip.txt")
	text := "# SDX-IP-LIST v1 direction=A_TO_B\n10.24.1.3\n10.24.1.2\n"
	if err := os.WriteFile(infile, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	first, n, duplicate, err := exchangeSourceStage(base, infile)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || duplicate {
		t.Fatalf("unexpected first stage: %d %v", n, duplicate)
	}
	if filepath.Ext(first) != ".json" {
		t.Fatalf("staged file not native JSON: %s", first)
	}
	second, n2, duplicate2, err := exchangeSourceStage(base, infile)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || n2 != 2 || !duplicate2 {
		t.Fatalf("not idempotent: %s vs %s (%v)", first, second, duplicate2)
	}
	if orig, err := os.ReadFile(infile); err != nil || !bytes.Equal(orig, []byte(text)) {
		t.Fatalf("operator original altered: %v", err)
	}
	inventory, err := readCandidates(first)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Candidates[0].IP != "10.24.1.2" {
		t.Fatalf("canonical inventory is not deterministic: %+v", inventory)
	}
	campaign, err := createCampaign(first, filepath.Join(root, "campaign-ab"), campaignManifest{
		Direction: "A_TO_B", DestinationIP: "10.25.1.1", Transport: "field_udp_bound",
		BatchSize: 32, SamplesPerSource: 5, PacketSize: 192, DataPort: 24572,
		TTLSeconds: 600, Epoch: "operator-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if campaign.SourceCount != 2 || len(campaign.Batches) != 1 {
		t.Fatalf("unexpected internally converted campaign: %+v", campaign)
	}
}

func TestExchangeSourceLongCampaignIsNot900SecondTotal(t *testing.T) {
	var b strings.Builder
	b.WriteString("# SDX-IP-LIST v1 direction=A_TO_B\n")
	const total = 1536
	for i := 0; i < total; i++ {
		fmt.Fprintf(&b, "10.24.%d.%d\n", i/254, (i%254)+1)
	}
	inv, err := exchangeParseSourceBytes([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	estimates, err := exchangeEstimateSourcePlan(inv, 32, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(estimates) != 1 {
		t.Fatalf("unexpected direction count: %+v", estimates)
	}
	e := estimates[0]
	if e.SourceCount != total || e.BatchCount != 48 || e.PlannedSamples != total*5 || e.MinimumSenderSeconds != 1536 {
		t.Fatalf("unexpected finite-batch planning arithmetic: %+v", e)
	}
	// This number is only the aggregate minimum sender pacing time, never
	// authority to issue a >900-second challenge or run without receiver consent.
}
