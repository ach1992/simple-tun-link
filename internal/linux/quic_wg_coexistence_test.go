package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func wgIngressSnapshot(t *testing.T, p wgIngressSpec) string {
	t.Helper()
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	raw := validWSSNFTSnapshot()
	old := wssGuardFixture(t).spec()
	raw = strings.ReplaceAll(raw, old.tableName(), p.tableName())
	raw = strings.ReplaceAll(raw, old.ruleComment(), p.ruleComment())
	raw = strings.ReplaceAll(raw, `"right":51820`, fmt.Sprintf(`"right":%d`, p.listenPort))
	if !json.Valid([]byte(raw)) || p.VerifyNFTJSON([]byte(raw)) != nil {
		t.Fatal("test did not create a valid exact nft guard generation")
	}
	return raw
}

func combineWGIngressSnapshots(t *testing.T, raws ...string) string {
	t.Helper()
	var combined wssNFTDump
	for _, raw := range raws {
		var other wssNFTDump
		if err := json.Unmarshal([]byte(raw), &other); err != nil || len(other.Nftables) == 0 {
			t.Fatal("invalid nft snapshot fixture")
		}
		for _, item := range other.Nftables {
			if len(item) == 1 && item["metainfo"] != nil {
				if len(combined.Nftables) == 0 {
					combined.Nftables = append(combined.Nftables, item)
				}
				continue
			}
			combined.Nftables = append(combined.Nftables, item)
		}
	}
	out, err := json.Marshal(combined)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func testWGCoexistenceGuards(t *testing.T) (WSSWGIngressPlan, QUICWGIngressPlan, QUICWGIngressPlan, WGFirewallEvidence) {
	t.Helper()
	w := wssGuardFixture(t)
	w.OriginalNonce = quicTestNonce
	q, err := NewQUICWGIngressPlan("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 51831, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewQUICWGIngressPlan("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 51832, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw := combineWGIngressSnapshots(t, wgIngressSnapshot(t, w.spec()), wgIngressSnapshot(t, q.spec()))
	return w, q, next, wssHostEvidence(raw)
}

func TestQUICWGCoexistenceOnlyExcludesExactAttestedWSSAndQUICGuards(t *testing.T) {
	w, q, next, evidence := testWGCoexistenceGuards(t)
	if err := next.CheckQUICWGFirewallCoexistence(evidence); err == nil {
		t.Fatal("unattested WSS/QUIC prior hooked guards were accepted")
	}
	if err := next.CheckQUICWGFirewallCoexistenceWithVerifiedSiblings(evidence,
		[]WSSWGIngressPlan{w}, nil); err == nil {
		t.Fatal("one attested WSS guard disguised another untrusted QUIC hook")
	}
	if err := next.CheckQUICWGFirewallCoexistenceWithVerifiedSiblings(evidence,
		nil, []QUICWGIngressPlan{q}); err == nil {
		t.Fatal("one attested QUIC guard disguised another untrusted WSS hook")
	}
	if err := next.CheckQUICWGFirewallCoexistenceWithVerifiedSiblings(evidence,
		[]WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err != nil {
		t.Fatalf("independently attested WSS and QUIC siblings incorrectly block new QUIC: %v", err)
	}
	newWSS, err := NewWSSWGIngressPlan("lnk_cccccccccccccccccccccccccccccccc", 51833)
	if err != nil {
		t.Fatal(err)
	}
	newWSS.OriginalNonce = quicTestNonce
	if err := newWSS.CheckWSSWGFirewallCoexistenceWithVerifiedSiblings(evidence,
		[]WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err != nil {
		t.Fatalf("new WSS rejected fully attested independent QUIC sibling: %v", err)
	}
	if err := newWSS.CheckWSSWGFirewallCoexistence(evidence); err == nil {
		t.Fatal("old WSS admission silently adopted unverified QUIC hook")
	}
	if err := next.CheckQUICWGFirewallCoexistence(wssHostEvidence(wssHostEmptyRuleset)); err != nil {
		t.Fatalf("empty foreign-hook inventory unexpectedly rejected: %v", err)
	}
}

// mutateWGIngressDropVerdict changes the single exact attested table's
// DROP verdict, not the first DROP in a mixed WSS+QUIC host ruleset.
// Validate the rule's carrier/nonce/port-bound marker so a mislabeled
// negative test cannot accidentally exercise a different sibling.
func mutateWGIngressDropVerdict(t *testing.T, original []byte, p wgIngressSpec) []byte {
	t.Helper()
	var dump wssNFTDump
	if err := json.Unmarshal(original, &dump); err != nil {
		t.Fatal(err)
	}
	changed := 0
	for _, object := range dump.Nftables {
		raw, ok := object["rule"]
		if !ok {
			continue
		}
		var rule wssNFTRule
		if err := json.Unmarshal(raw, &rule); err != nil {
			t.Fatal(err)
		}
		if rule.Table != p.tableName() {
			continue
		}
		if rule.Comment != p.ruleComment() || rule.Family != "inet" ||
			rule.Chain != "ingress" || len(rule.Expr) != 4 ||
			len(rule.Expr[3]) != 1 || string(rule.Expr[3]["drop"]) != "null" {
			t.Fatal("intended sibling did not have the expected original DROP rule")
		}
		rule.Expr[3] = map[string]json.RawMessage{"accept": json.RawMessage("null")}
		altered, err := json.Marshal(rule)
		if err != nil {
			t.Fatal(err)
		}
		object["rule"] = altered
		changed++
	}
	if changed != 1 {
		t.Fatalf("expected exactly one altered %s sibling verdict, changed %d", p.carrier, changed)
	}
	result, err := json.Marshal(dump)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestQUICWGCoexistenceRejectsForeignSiblingDriftWithoutMutation(t *testing.T) {
	w, q, next, good := testWGCoexistenceGuards(t)
	allowed := func(e WGFirewallEvidence, ws []WSSWGIngressPlan, qs []QUICWGIngressPlan) error {
		return next.CheckQUICWGFirewallCoexistenceWithVerifiedSiblings(e, ws, qs)
	}
	if err := allowed(good, []WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), good.NFTRuleset...)
	tests := []struct {
		name   string
		change func(*WGFirewallEvidence, *[]WSSWGIngressPlan, *[]QUICWGIngressPlan)
	}{
		{"missing-wss-table", func(e *WGFirewallEvidence, _ *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			e.NFTRuleset = []byte(wgIngressSnapshot(t, q.spec()))
		}},
		{"missing-quic-table", func(e *WGFirewallEvidence, _ *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			e.NFTRuleset = []byte(wgIngressSnapshot(t, w.spec()))
		}},
		{"wrong-wss-generation", func(_ *WGFirewallEvidence, ws *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			(*ws)[0].OriginalNonce = "abcdef0123456789abcdef0123456789"
		}},
		{"wrong-quic-generation", func(_ *WGFirewallEvidence, _ *[]WSSWGIngressPlan, qs *[]QUICWGIngressPlan) {
			(*qs)[0].OriginalNonce = "abcdef0123456789abcdef0123456789"
		}},
		{"wrong-quic-port", func(_ *WGFirewallEvidence, _ *[]WSSWGIngressPlan, qs *[]QUICWGIngressPlan) {
			(*qs)[0].ListenPort++
		}},
		{"sibling-conflicting-udp-port", func(_ *WGFirewallEvidence, _ *[]WSSWGIngressPlan, qs *[]QUICWGIngressPlan) {
			(*qs)[0].ListenPort = next.ListenPort
		}},
		{"duplicate-wss-attestation", func(_ *WGFirewallEvidence, ws *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			*ws = append(*ws, w)
		}},
		{"duplicate-quic-attestation", func(_ *WGFirewallEvidence, _ *[]WSSWGIngressPlan, qs *[]QUICWGIngressPlan) {
			*qs = append(*qs, q)
		}},
		{"self-exclusion", func(_ *WGFirewallEvidence, _ *[]WSSWGIngressPlan, qs *[]QUICWGIngressPlan) {
			*qs = append(*qs, next)
		}},
		{"missing-legacy", func(e *WGFirewallEvidence, _ *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			e.LegacySaveV6 = nil
		}},
		{"foreign-legacy-policy", func(e *WGFirewallEvidence, _ *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			e.LegacySaveV4 = []byte("*filter\n:INPUT DROP [0:0]\nCOMMIT\n")
		}},
		{"altered-wss-drop", func(e *WGFirewallEvidence, _ *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			e.NFTRuleset = mutateWGIngressDropVerdict(t, e.NFTRuleset, w.spec())
		}},
		{"altered-quic-drop", func(e *WGFirewallEvidence, _ *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			e.NFTRuleset = mutateWGIngressDropVerdict(t, e.NFTRuleset, q.spec())
		}},
		{"duplicate-casefolded-nft-member", func(e *WGFirewallEvidence, _ *[]WSSWGIngressPlan, _ *[]QUICWGIngressPlan) {
			e.NFTRuleset = []byte(strings.Replace(string(e.NFTRuleset), `"hook":"input"`,
				`"Hook":"forward","hook":"input"`, 1))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := good
			ws, qs := []WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}
			tt.change(&evidence, &ws, &qs)
			if err := allowed(evidence, ws, qs); err == nil {
				t.Fatal("missing, foreign, altered or self-attested guard was admitted")
			}
			if !reflect.DeepEqual(before, good.NFTRuleset) {
				t.Fatal("read-only guard coexistence unexpectedly mutated original evidence")
			}
		})
	}
	t.Run("foreign-prior-input-hook", func(t *testing.T) {
		raw := combineWGIngressSnapshots(t, string(good.NFTRuleset),
			wssHostInventory(t, "foreign", "interceptor", "input", -300, "accept", true))
		foreign := good
		foreign.NFTRuleset = []byte(raw)
		if err := allowed(foreign, []WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err == nil {
			t.Fatal("validated siblings suppressed a foreign higher-priority firewall hook")
		}
	})
	t.Run("new-wss-self-exclusion", func(t *testing.T) {
		if err := w.CheckWSSWGFirewallCoexistenceWithVerifiedSiblings(good,
			[]WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err == nil {
			t.Fatal("proposed new WSS guard excluded its own supposedly occupied table")
		}
	})
}

type quicCoexistenceRunner struct {
	wssHostReadbackRunner
	nft []byte
}

func (r *quicCoexistenceRunner) RunBounded(ctx context.Context, limit CaptureLimits, name string, args ...string) (CommandResult, error) {
	if name == "nft" && reflect.DeepEqual(args, []string{"-j", "list", "ruleset"}) {
		r.calls = append(r.calls, "nft -j list ruleset")
		return CommandResult{Stdout: r.nft}, nil
	}
	return r.wssHostReadbackRunner.RunBounded(ctx, limit, name, args...)
}

func TestQUICWGCoexistenceProbeUsesOnlyFiveReadOnlyHostQueries(t *testing.T) {
	w, q, next, e := testWGCoexistenceGuards(t)
	runner := &quicCoexistenceRunner{nft: e.NFTRuleset}
	if err := next.ProbeQUICWGFirewallCoexistenceWithVerifiedSiblings(context.Background(),
		runner, []WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err != nil {
		t.Fatalf("bounded QUIC host read-only preflight rejected exact existing guards: %v", err)
	}
	want := []string{"nft -j list ruleset", "iptables -V", "ip6tables -V",
		"iptables-legacy-save", "ip6tables-legacy-save"}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("read-only preflight issued nonapproved commands: %v", runner.calls)
	}
	newWSS, err := NewWSSWGIngressPlan("lnk_dddddddddddddddddddddddddddddddd", 51834)
	if err != nil {
		t.Fatal(err)
	}
	newWSS.OriginalNonce = quicTestNonce
	reverse := &quicCoexistenceRunner{nft: e.NFTRuleset}
	if err := newWSS.ProbeWSSWGFirewallCoexistenceWithVerifiedSiblings(context.Background(),
		reverse, []WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err != nil ||
		!reflect.DeepEqual(reverse.calls, want) {
		t.Fatalf("new WSS did not reuse identical bounded probe for attested QUIC sibling: %v %v", err, reverse.calls)
	}
	if err := next.ProbeQUICWGFirewallCoexistence(context.Background(), runner); err == nil {
		t.Fatal("unattested hooks accepted by ordinary QUIC preflight")
	}
	runner = &quicCoexistenceRunner{nft: e.NFTRuleset}
	if err := next.ProbeQUICWGFirewallCoexistenceWithVerifiedSiblings(context.Background(),
		runner, []WSSWGIngressPlan{w}, []QUICWGIngressPlan{next}); err == nil ||
		len(runner.calls) != 0 {
		t.Fatal("new QUIC guard self-exclusion was not rejected before any host query")
	}
	runner = &quicCoexistenceRunner{nft: e.NFTRuleset}
	runner.fail = "ip6tables-legacy-save"
	if err := next.ProbeQUICWGFirewallCoexistenceWithVerifiedSiblings(context.Background(),
		runner, []WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err == nil {
		t.Fatal("failed mandatory IPv6 legacy snapshot accepted")
	}
	const privateDiagnostic = "SENSITIVE_OWNED_FIREWALL_COMMAND_TOKEN"
	runner = &quicCoexistenceRunner{nft: e.NFTRuleset}
	runner.fail = "iptables -V"
	runner.failErr = fmt.Errorf("foreign runner stderr %s", privateDiagnostic)
	if err := next.ProbeQUICWGFirewallCoexistenceWithVerifiedSiblings(context.Background(),
		runner, []WSSWGIngressPlan{w}, []QUICWGIngressPlan{q}); err == nil ||
		strings.Contains(err.Error(), privateDiagnostic) {
		t.Fatal("QUIC firewall probe exposed arbitrary untrusted runner diagnostics")
	}
	if err := next.ProbeQUICWGFirewallCoexistence(context.Background(), nil); err == nil {
		t.Fatal("nil host runner accepted")
	}
	if err := next.ProbeQUICWGFirewallCoexistence(nil, runner); err == nil {
		t.Fatal("nil probe context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner = &quicCoexistenceRunner{nft: e.NFTRuleset}
	if err := next.ProbeQUICWGFirewallCoexistence(ctx, runner); err == nil || len(runner.calls) != 0 {
		t.Fatal("canceled QUIC host probe queried a host or returned success")
	}
}

// Regression for independent high-assurance finding: different verified
// sibling tables can still claim the same global kernel WG UDP port. Both
// source-check and bounded-probe paths must reject BEFORE querying the host.
func TestWGMixedCarrierSiblingsRejectEveryPairwiseUDPPortCollision(t *testing.T) {
	const sharedPort uint16 = 51820
	originalWSS := wssGuardFixture(t)
	originalWSS.OriginalNonce = quicTestNonce
	siblingWSS, err := NewWSSWGIngressPlan("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sharedPort)
	if err != nil {
		t.Fatal(err)
	}
	siblingWSS.OriginalNonce = quicTestNonce
	originalQUIC, err := NewQUICWGIngressPlan("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", sharedPort, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	siblingQUIC, err := NewQUICWGIngressPlan("lnk_cccccccccccccccccccccccccccccccc", sharedPort, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	newWSS, err := NewWSSWGIngressPlan("lnk_dddddddddddddddddddddddddddddddd", 51833)
	if err != nil {
		t.Fatal(err)
	}
	newQUIC, err := NewQUICWGIngressPlan("lnk_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 51832, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		wss  []WSSWGIngressPlan
		quic []QUICWGIngressPlan
	}{
		{"wss-quic", []WSSWGIngressPlan{originalWSS}, []QUICWGIngressPlan{originalQUIC}},
		{"wss-wss", []WSSWGIngressPlan{originalWSS, siblingWSS}, nil},
		{"quic-quic", nil, []QUICWGIngressPlan{originalQUIC, siblingQUIC}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Each separate original guard has a genuinely valid, complete
			// nonce-bound nft readback. An invalid fixture must not be the
			// accidental reason that duplicate-port admission fails.
			var snap []string
			for _, p := range tc.wss {
				snap = append(snap, wgIngressSnapshot(t, p.spec()))
			}
			for _, p := range tc.quic {
				snap = append(snap, wgIngressSnapshot(t, p.spec()))
			}
			if len(snap) != 2 {
				t.Fatal("expected exactly two distinct sibling nft guards")
			}
			evidence := wssHostEvidence(combineWGIngressSnapshots(t, snap...))
			t.Run("new-quic-source", func(t *testing.T) {
				if err := newQUIC.CheckQUICWGFirewallCoexistenceWithVerifiedSiblings(evidence, tc.wss, tc.quic); err == nil {
					t.Fatal("pairwise sibling global UDP port overlap accepted by NEW QUIC source admission")
				}
			})
			t.Run("new-wss-source", func(t *testing.T) {
				if err := newWSS.CheckWSSWGFirewallCoexistenceWithVerifiedSiblings(evidence, tc.wss, tc.quic); err == nil {
					t.Fatal("pairwise sibling global UDP port overlap accepted by NEW WSS source admission")
				}
			})
			t.Run("new-quic-probe", func(t *testing.T) {
				runner := &quicCoexistenceRunner{nft: evidence.NFTRuleset}
				if err := newQUIC.ProbeQUICWGFirewallCoexistenceWithVerifiedSiblings(context.Background(), runner, tc.wss, tc.quic); err == nil ||
					len(runner.calls) != 0 {
					t.Fatalf("NEW QUIC pairwise collision probed host or was accepted: err=%v calls=%v", err, runner.calls)
				}
			})
			t.Run("new-wss-probe", func(t *testing.T) {
				runner := &quicCoexistenceRunner{nft: evidence.NFTRuleset}
				if err := newWSS.ProbeWSSWGFirewallCoexistenceWithVerifiedSiblings(context.Background(), runner, tc.wss, tc.quic); err == nil ||
					len(runner.calls) != 0 {
					t.Fatalf("NEW WSS pairwise collision probed host or was accepted: err=%v calls=%v", err, runner.calls)
				}
			})
		})
	}
}
