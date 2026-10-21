package linux

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const wssTestLinkID = domain.LinkID("lnk_0123456789abcdef0123456789abcdef")

func wssGuardFixture(t *testing.T) WSSWGIngressPlan {
	t.Helper()
	p, err := NewWSSWGIngressPlan(wssTestLinkID, 51820)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func validWSSNFTSnapshot() string {
	return `{"nftables":[
{"metainfo":{"version":"1.1.3","json_schema_version":1}},
{"table":{"family":"inet","name":"stlwss_09506b2028cc50fd","handle":1}},
{"chain":{"family":"inet","table":"stlwss_09506b2028cc50fd","name":"ingress","handle":1,"type":"filter","hook":"input","prio":-250,"policy":"accept"}},
{"rule":{"family":"inet","table":"stlwss_09506b2028cc50fd","chain":"ingress","handle":2,"comment":"stl:lnk_0123456789abcdef0123456789abcdef:wg-udp-guard:51820",
"expr":[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"lo"}},
{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":51820}},
{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}
]}`
}

func TestWSSWGIngressRenderMatchesCommittedNftTransaction(t *testing.T) {
	plan := wssGuardFixture(t)
	want, err := os.ReadFile("testdata/wss_wg_ingress.nft")
	if err != nil {
		t.Fatal(err)
	}
	got, err := plan.NFTBatch()
	if err != nil || got != string(want) {
		t.Fatalf("nft batch does not match executable isolated-lab fixture: error=%v, got=%q, want=%q", err, got, want)
	}
	if !strings.Contains(got, "hook input priority -250; policy accept;") ||
		!strings.Contains(got, `iifname != "lo" udp dport 51820 counter drop`) {
		t.Fatal("ingress rule lost its exact non-loopback filter priority/port")
	}
	another, err := NewWSSWGIngressPlan("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 52820)
	if err != nil {
		t.Fatal(err)
	}
	otherBatch, err := another.NFTBatch()
	if err != nil || otherBatch == got || another.tableName() == plan.tableName() {
		t.Fatalf("separate Link cannot share an ingress guard identity: err=%v", err)
	}
}

func TestWSSWGIngressFailClosedOnInvalidIdentityOrPort(t *testing.T) {
	for _, tt := range []struct {
		id   domain.LinkID
		port uint16
	}{
		{"", 51820},
		{"../../foreign", 51820},
		{"lnk_0123456789abcdef0123456789abcdef\nadd rule", 51820},
		{wssTestLinkID, 0},
	} {
		if _, err := NewWSSWGIngressPlan(tt.id, tt.port); err == nil {
			t.Fatalf("accepted invalid guard identity/port: %q %d", tt.id, tt.port)
		}
		invalid := WSSWGIngressPlan{LinkID: tt.id, ListenPort: tt.port}
		if batch, err := invalid.NFTBatch(); err == nil || batch != "" {
			t.Fatalf("rendered unsafe nft batch: %q %v", batch, err)
		}
		if err := invalid.VerifyNFTJSON([]byte(validWSSNFTSnapshot())); err == nil {
			t.Fatalf("adopted guard with invalid identity/port")
		}
	}
}

func TestWSSWGIngressReadOnlyVerificationRequiresExactSingleOwnedShape(t *testing.T) {
	plan := wssGuardFixture(t)
	valid := validWSSNFTSnapshot()
	for _, snapshot := range []string{
		valid,
		strings.Replace(valid, `"packets":0,"bytes":0`, `"packets":987,"bytes":65535`, 1),
		strings.Replace(valid, `{"metainfo":{"version":"1.1.3","json_schema_version":1}},`, "", 1),
	} {
		if err := plan.VerifyNFTJSON([]byte(snapshot)); err != nil {
			t.Fatalf("valid dynamic nft snapshot unexpectedly rejected: %v", err)
		}
	}
	tampered := []struct {
		name string
		from string
		to   string
	}{
		{"different-table", `"name":"stlwss_09506b2028cc50fd"`, `"name":"stlwss_other"`},
		{"different-chain", `"name":"ingress"`, `"name":"other"`},
		{"wrong-hook", `"hook":"input"`, `"hook":"forward"`},
		{"late-hook-priority", `"prio":-250`, `"prio":0`},
		{"dangerous-chain-policy", `"policy":"accept"`, `"policy":"drop"`},
		{"foreign-rule-marker", `"comment":"stl:lnk_0123456789abcdef0123456789abcdef:wg-udp-guard:51820"`, `"comment":"stl:lnk_0123456789abcdef0123456789abcdef:wg-udp-guard:51821"`},
		{"wrong-interface", `"right":"lo"`, `"right":"eth0"`},
		{"inverted-interface-matcher", `"op":"!="`, `"op":"=="`},
		{"wrong-protocol", `"protocol":"udp"`, `"protocol":"tcp"`},
		{"wrong-udp-port", `"right":51820`, `"right":51821`},
		{"accept-instead-of-drop", `{"drop":null}`, `{"accept":null}`},
		{"altered-verdict", `{"drop":null}`, `{"drop":{}}`},
		{"missing-counter-byte-field", `"packets":0,"bytes":0`, `"packets":0`},
		{"extra-rule-condition", `{"counter":{"packets":0,"bytes":0}}`, `{"counter":{"packets":0,"bytes":0},"limit":{"rate":100}}`},
		{"unknown-rule-condition", `{"drop":null}`, `{"accept":null},{"drop":null}`},
		{"foreign-chain-table", `"table":"stlwss_09506b2028cc50fd"`, `"table":"foreign"`},
		{"extra-chain-property", `"policy":"accept"`, `"policy":"accept","device":"eth0"`},
	}
	for _, tt := range tampered {
		t.Run(tt.name, func(t *testing.T) {
			next := strings.Replace(valid, tt.from, tt.to, 1)
			if next == valid {
				t.Fatal("mutation did not actually alter the fixture")
			}
			if err := plan.VerifyNFTJSON([]byte(next)); err == nil {
				t.Fatal("altered or foreign ingress nft object was trusted")
			}
		})
	}
	for _, tt := range []struct {
		name string
		json string
	}{
		{"empty", ""},
		{"missing-data", `{"nftables":[]}`},
		{"trailing-JSON", valid + " {}"},
		{"missing-rule", strings.Replace(valid, `"rule":`, `"ignored":`, 1)},
		{"missing-chain", strings.Replace(valid, `"chain":`, `"ignored":`, 1)},
		{"unknown-entry", strings.Replace(valid, `{"rule":`, `{"flowtable":`, 1)},
		{"wrong-top-level-type", `{"nftables":"not an array"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := plan.VerifyNFTJSON([]byte(tt.json)); err == nil {
				t.Fatal("ambiguous nft snapshot was trusted")
			}
		})
	}
	// Duplicates must be valid JSON with complete real object shapes,
	// not malformed input accidentally rejected by the decoder.
	for _, tt := range []struct {
		name string
		idx  int
	}{
		{"duplicate-metadata", 0},
		{"duplicate-table", 1},
		{"duplicate-chain", 2},
		{"duplicate-rule", 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var dump wssNFTDump
			if err := json.Unmarshal([]byte(valid), &dump); err != nil {
				t.Fatal(err)
			}
			dump.Nftables = append(dump.Nftables, dump.Nftables[tt.idx])
			raw, err := json.Marshal(dump)
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.VerifyNFTJSON(raw); err == nil {
				t.Fatal("duplicate nft object incorrectly accepted as a uniquely owned guard")
			}
		})
	}
}

func TestWSSWGIngressVerifyIsolatedRuntimeSnapshot(t *testing.T) {
	file := os.Getenv("STL_WSS_INGRESS_E2E_NFT_JSON")
	if file == "" {
		t.Skip("isolated runtime JSON not supplied")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := wssGuardFixture(t).VerifyNFTJSON(data); err != nil {
		t.Fatalf("real nftables readback differs from the immutable fixture: %v", err)
	}
	if bytes.Contains(data, []byte(`"accept":null`)) {
		t.Fatal("runtime guard includes a permissive rule")
	}
}
