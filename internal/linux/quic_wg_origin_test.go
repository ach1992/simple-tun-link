package linux

import (
	"context"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

const quicTestNonce = "0123456789abcdef0123456789abcdef"

func TestQUICWGHostOriginDistinctTransportGeneration(t *testing.T) {
	id := wssTestLinkID
	q, err := PlanQUICWGHostOrigin(id, quicTestNonce, 51820)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWSSWGIngressPlan(id, 51820)
	if err != nil {
		t.Fatal(err)
	}
	w.OriginalNonce = quicTestNonce
	wa, err := WSSStagingName(id, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := WSSOwnerTag(id, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if q.OwnerTag == wt || q.StagingName == wa ||
		q.Guard.TableName() == w.TableName() ||
		!strings.HasPrefix(q.Guard.TableName(), "stlquic_") {
		t.Fatal("QUIC host identity collides with WSS for the same Link and original nonce")
	}
	if len(q.StagingName) != 15 || !validWireGuardStagingName(q.StagingName, 'q') ||
		validWireGuardStagingName(q.StagingName, 'w') {
		t.Fatal("QUIC original kernel name is not in its exclusive namespace")
	}
	if gotID, gotNonce, ok := ParseQUICWGOwnerTag(q.OwnerTag); !ok ||
		gotID != id || gotNonce != quicTestNonce {
		t.Fatal("QUIC owner tag cannot be parsed exactly")
	}
	if _, _, ok := ParseQUICWGOwnerTag(wt); ok {
		t.Fatal("WSS original tag accepted as QUIC ownership")
	}
	if _, _, ok := ParseWSSOwnerTag(q.OwnerTag); ok {
		t.Fatal("QUIC original tag accepted as WSS ownership")
	}
	other, err := PlanQUICWGHostOrigin("lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", quicTestNonce, 51820)
	if err != nil || other.Guard.TableName() == q.Guard.TableName() ||
		other.StagingName == q.StagingName || other.OwnerTag == q.OwnerTag {
		t.Fatal("two distinct Links share a QUIC host identity")
	}
	another, err := PlanQUICWGHostOrigin(id, "abcdef0123456789abcdef0123456789", 51820)
	if err != nil || another.Guard.TableName() != q.Guard.TableName() ||
		another.OwnerTag == q.OwnerTag || another.StagingName == q.StagingName {
		t.Fatal("new journal generation was not independently bound to exact original nonce")
	}
	if q.Guard.OriginalNonce != quicTestNonce || q.Guard.ListenPort != 51820 {
		t.Fatal("QUIC guard diverged from host-origin nonce or kernel WG port")
	}
}

func quicGuardJSON(t *testing.T, plan QUICWGIngressPlan) string {
	t.Helper()
	if plan.LinkID != wssTestLinkID || plan.ListenPort != 51820 {
		t.Fatal("unexpected test fixture Link/port")
	}
	raw := validWSSNFTSnapshot()
	raw = strings.ReplaceAll(raw, "stlwss_09506b2028cc50fd", plan.TableName())
	raw = strings.ReplaceAll(raw, "stl:lnk_0123456789abcdef0123456789abcdef:wg-udp-guard:51820",
		plan.spec().ruleComment())
	return raw
}

func TestQUICWGGuardIsExactSourceOnlyReadbackAndIsolation(t *testing.T) {
	q, err := NewQUICWGIngressPlan(wssTestLinkID, 51820, quicTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWSSWGIngressPlan(wssTestLinkID, 51820)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := q.NFTBatch()
	if err != nil || !strings.Contains(generated,
		"create table inet "+q.TableName()+"\n") ||
		!strings.Contains(generated, "hook input priority -250; policy accept;") ||
		!strings.Contains(generated, `iifname != "lo" udp dport 51820 counter drop`) ||
		!strings.Contains(generated, q.spec().ruleComment()) ||
		strings.Contains(generated, w.TableName()) {
		t.Fatalf("QUIC ingress source-only batch lost exclusive guard semantics: %v", err)
	}
	valid := quicGuardJSON(t, q)
	if err := q.VerifyNFTJSON([]byte(valid)); err != nil {
		t.Fatalf("exact nonce-bound QUIC nft snapshot rejected: %v", err)
	}
	if err := w.VerifyNFTJSON([]byte(valid)); err == nil {
		t.Fatal("QUIC guard accepted as WSS-owned guard")
	}
	if err := q.VerifyNFTJSON([]byte(validWSSNFTSnapshot())); err == nil {
		t.Fatal("WSS guard accepted as QUIC-owned guard")
	}
	for _, tc := range []struct {
		name, mutated string
	}{
		{"missing original nonce", strings.Replace(valid, ":tx:"+quicTestNonce, "", 1)},
		{"different original nonce", strings.Replace(valid, quicTestNonce, "abcdef0123456789abcdef0123456789", 1)},
		{"wrong destination port", strings.Replace(valid, `"right":51820`, `"right":51821`, 1)},
		{"replaced comment", strings.Replace(valid, `"comment":"stl:quic:`, `"comment":"stl:wss:`, 1)},
		{"removed drop verdict", strings.Replace(valid, `{"drop":null}`, `{"accept":null}`, 1)},
		{"foreign table", strings.Replace(valid, q.TableName(), "stlquic_foreign", 1)},
		{"duplicate guard hook", strings.Replace(valid, `"hook":"input"`, `"hook":"forward","hook":"input"`, 1)},
		{"duplicate casefolded hook", strings.Replace(valid, `"hook":"input"`, `"Hook":"forward","hook":"input"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mutated == valid {
				t.Fatal("test mutation did not change fixture")
			}
			if err := q.VerifyNFTJSON([]byte(tc.mutated)); err == nil {
				t.Fatal("foreign, drifted or ambiguous guard accepted")
			}
		})
	}
	// The caller cannot weaken nonce/port requirements after construction.
	q.OriginalNonce = ""
	if got, err := q.NFTBatch(); err == nil || got != "" {
		t.Fatal("zero-nonce QUIC guard permitted after caller mutation")
	}
	if err := q.VerifyNFTJSON([]byte(valid)); err == nil {
		t.Fatal("QUIC guard readback permitted after nonce removal")
	}
}

func TestQUICWGOriginRejectsUnboundIdentityAndUnsafeKernelNames(t *testing.T) {
	for _, tc := range []struct {
		id    domain.LinkID
		nonce string
		port  uint16
	}{
		{"", quicTestNonce, 51820},
		{"lnk_bad", quicTestNonce, 51820},
		{wssTestLinkID, "", 51820},
		{wssTestLinkID, "a", 51820},
		{wssTestLinkID, strings.ToUpper(quicTestNonce), 51820},
		{wssTestLinkID, quicTestNonce, 0},
	} {
		if _, err := PlanQUICWGHostOrigin(tc.id, tc.nonce, tc.port); err == nil {
			t.Fatalf("invalid host origin was admitted: %+v", tc)
		}
		if tc.port == 0 || tc.id.Validate() != nil || tc.nonce == "" || len(tc.nonce) != 32 ||
			strings.ToLower(tc.nonce) != tc.nonce {
			if _, err := NewQUICWGIngressPlan(tc.id, tc.port, tc.nonce); err == nil {
				t.Fatal("invalid QUIC guard identity was admitted")
			}
		}
	}
	for _, raw := range []string{
		"", "wabcdefghijklmno", "q", "qABCDEFGHIJKLMN",
		"q00000000000000", "qabcdefghijklmn\n",
		"qabcdefghijklm_", "qabcdefghijklm1",
	} {
		if validWireGuardStagingName(raw, 'q') {
			t.Fatalf("untrusted QUIC creation name accepted: %q", raw)
		}
		// An invalid name must fail before issuing any kernel request.
		if err := CreateQUICWireGuardStaged(context.Background(), raw); err == nil {
			t.Fatalf("unsafe QUIC creation name reached netlink: %q", raw)
		}
	}
	if _, _, ok := ParseQUICWGOwnerTag("stl:quic:" + string(wssTestLinkID) + ":tx:" + quicTestNonce + ":extra"); ok {
		t.Fatal("extra suffix was admitted as an original QUIC alias")
	}
}
