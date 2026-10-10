package ipsec

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

type xfrmFixture struct {
	rows   map[string][]byte
	fail   string
	called []string
}

func (f *xfrmFixture) Run(_ context.Context, binary string, args ...string) ([]byte, error) {
	call := binary + " " + strings.Join(args, " ")
	f.called = append(f.called, call)
	if f.fail == call {
		return []byte("secret-from-host"), errors.New("sensitive execution error")
	}
	src, ok := f.rows[call]
	if !ok {
		return nil, fmt.Errorf("unconfigured fake read")
	}
	return append([]byte(nil), src...), nil
}

func goodXFRMFixture() *xfrmFixture {
	return &xfrmFixture{rows: map[string][]byte{
		"ip -details -json link show": []byte(`[{"ifname":"lo"},{"ifname":"eth0","linkinfo":{"info_kind":"veth"}}]`),
		"ip -json xfrm policy":        []byte("[]"),
		"ip -json xfrm state":         []byte("[]"),
	}}
}

func TestXFRMVacancyReadsAllThreeHostCollisionSurfaces(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	f := goodXFRMFixture()
	if err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip -details -json link show",
		"ip -json xfrm policy",
		"ip -json xfrm state",
	}
	if !reflect.DeepEqual(f.called, want) {
		t.Fatalf("incomplete host inspection: %v", f.called)
	}
}

func TestXFRMVacancyRejectsForeignAliasNameIDPolicyAndState(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapNATT))
	if err != nil {
		t.Fatal(err)
	}
	hexID := "0x" + strconv.FormatUint(uint64(p.InterfaceID), 16)
	cases := []struct {
		label  string
		cmd    string
		output string
	}{
		{"foreign-non-xfrm-name", "ip -details -json link show",
			fmt.Sprintf(`[{"ifname":"%s","ifalias":"stl:lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","linkinfo":{"info_kind":"veth"}}]`, p.InterfaceName)},
		{"foreign-xfrm-id", "ip -details -json link show",
			fmt.Sprintf(`[{"ifname":"other-xfrm","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"%s"}}}]`, hexID)},
		{"xfrm-id-decimal", "ip -details -json link show",
			fmt.Sprintf(`[{"ifname":"other-xfrm","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":%d}}}]`, p.InterfaceID)},
		{"orphan-policy", "ip -json xfrm policy", fmt.Sprintf(`[{"src":"10.251.1.1/32","dst":"10.251.1.2/32","dir":"out","if_id":"%s"}]`, hexID)},
		{"orphan-sa", "ip -json xfrm state", fmt.Sprintf(`[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"esp","if_id":"%s","aead":{"key":"sensitive-fixture-must-not-leak"}}]`, hexID)},
		{"malformed-foreign-interface", "ip -details -json link show", `[{"ifname":"other-xfrm","linkinfo":{"info_kind":"xfrm"}}]`},
		{"duplicate-interface", "ip -details -json link show", `[{"ifname":"same"},{"ifname":"same"}]`},
		{"malformed-policy", "ip -json xfrm policy", `[{"if_id":"not-an-ID"}]`},
		{"malformed-sa", "ip -json xfrm state", `[{"if_id":-5}]`},
		{"empty-policy", "ip -json xfrm policy", `null`},
		{"invalid-sa", "ip -json xfrm state", `null`},
		{"invalid-json", "ip -details -json link show", `{"unknown":"not-array"}`},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			f := goodXFRMFixture()
			f.rows[tc.cmd] = []byte(tc.output)
			err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p)
			if err == nil || strings.Contains(err.Error(), "sensitive-fixture") || strings.Contains(err.Error(), "stl:lnk_") {
				t.Fatalf("foreign or unverified resource accepted/leaked: %v", err)
			}
		})
	}
	for _, cmd := range []string{"ip -details -json link show", "ip -json xfrm policy", "ip -json xfrm state"} {
		t.Run("unavailable-"+cmd, func(t *testing.T) {
			f := goodXFRMFixture()
			f.fail = cmd
			err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p)
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("unavailable host resource treated as empty or leaked: %v", err)
			}
		})
	}
}

func TestXFRMVacancyAllowsUnrelatedHostResourcesAndRefusesForgedProfiles(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	f := goodXFRMFixture()
	otherID := uint32(42)
	if otherID == p.InterfaceID {
		otherID++
	}
	f.rows["ip -details -json link show"] = []byte(fmt.Sprintf(`[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"0x%x"}}}]`, otherID))
	f.rows["ip -json xfrm policy"] = []byte(fmt.Sprintf(`[{"src":"10.251.1.1/32","dst":"10.251.1.2/32","dir":"in","if_id":%d}]`, otherID))
	f.rows["ip -json xfrm state"] = []byte(fmt.Sprintf(`[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"esp","if_id":%d}]`, otherID))
	i := XFRMVacancyInspector{Runner: f.Run}
	if err := i.RequireVacant(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := i.RequireVacant(context.Background(), Profile{Link: p.Link, InterfaceID: p.InterfaceID}); err == nil {
		t.Fatal("forged noncanonical XFRM profile accepted")
	}
	if err := i.RequireVacant(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := (XFRMVacancyInspector{}).RequireVacant(context.Background(), p); err == nil {
		t.Fatal("missing inspector runner accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := i.RequireVacant(ctx, p); err == nil {
		t.Fatal("canceled inspection accepted")
	}
	if _, err := xfrmIfID([]byte(`"0x100000000"`), false); err == nil {
		t.Fatal("32-bit overflow accepted")
	}
}

// iproute2 6.1 emits no stdout when the kernel policy/state table is
// genuinely empty; a failed command with empty output is still UNKNOWN.
func TestXFRMVacancyAllowsSuccessfulEmptyPolicyAndStateOutput(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	f := goodXFRMFixture()
	f.rows["ip -json xfrm policy"] = nil
	f.rows["ip -json xfrm state"] = []byte(" \n")
	if err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	f.fail = "ip -json xfrm state"
	if err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p); err == nil {
		t.Fatal("failed empty-state command accepted as successful inventory")
	}
}

// Debian-bookworm iproute2 6.1 accepts -json on xfrm but emits legacy text
// once at least one entry exists; this must not bypass the if_id collision gate.
func TestXFRMVacancyLegacyTextPolicyAndSAInventory(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("0x%x", p.InterfaceID)
	otherID := uint32(19)
	if otherID == p.InterfaceID {
		otherID++
	}
	cases := []struct {
		name, cmd, output string
		block             bool
	}{
		{"orphan-policy-text", "ip -json xfrm policy",
			fmt.Sprintf("src 10.251.1.1/32 dst 10.251.1.2/32 \n\tdir out priority 0 ptype main \n\ttmpl src 192.0.2.10 dst 192.0.2.11\n\tif_id %s\n", target), true},
		{"orphan-SA-text", "ip -json xfrm state",
			fmt.Sprintf("src 192.0.2.10 dst 192.0.2.11\n\tproto esp spi 0x12345678 reqid 17 mode tunnel\n\tif_id %s\n", target), true},
		{"unrelated-policy", "ip -json xfrm policy",
			fmt.Sprintf("src 10.251.1.1/32 dst 10.251.1.2/32\n\tdir out priority 0 ptype main\n\tif_id 0x%x\n", otherID), false},
		{"unrelated-SA", "ip -json xfrm state",
			fmt.Sprintf("src 192.0.2.10 dst 192.0.2.11\n\tproto esp spi 0x12345678 reqid 17 mode tunnel\n\tif_id 0x%x\n", otherID), false},
		{"unknown-text", "ip -json xfrm policy", "unparseable unverified inventory", true},
		{"missing-policy-dir", "ip -json xfrm policy", "src 10.1.1.1/32 dst 10.1.1.2/32\n\tif_id 0x2a\n", true},
		{"bad-text-ifid", "ip -json xfrm state", "src 10.1.1.1 dst 10.1.1.2\n\tproto esp\n\tif_id not-a-number\n", true},
		{"duplicate-text-ifid", "ip -json xfrm policy", "src 10.1.1.1/32 dst 10.1.1.2/32\n\tdir out\n\tif_id 0x1\n\tif_id 0x2\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodXFRMFixture()
			f.rows[tc.cmd] = []byte(tc.output)
			err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p)
			if tc.block && err == nil {
				t.Fatal("collision/unknown legacy inventory was accepted")
			}
			if !tc.block && err != nil {
				t.Fatalf("unrelated legacy inventory rejected: %v", err)
			}
		})
	}
}

// Inventory may be declared vacant only after EACH nonempty JSON row is
// structurally verified, including its endpoints, policy direction / SA
// protocol and unique exact interface-ID representation. Invalid rows cannot
// be skipped, even when an earlier record was unrelated to the planned Link.
func TestXFRMInventoryJSONDescriptorAndIdentityValidation(t *testing.T) {
	const id uint32 = 0x2121
	cases := []struct {
		name, kind, raw    string
		collision, invalid bool
	}{
		{"empty", "policy", `[]`, false, false},
		{"policy-wildcard", "policy", `[{"src":"0.0.0.0/0","dst":"0.0.0.0/0","dir":"in"}]`, false, false},
		{"policy-unrelated", "policy", `[{"src":"10.251.1.1/32","dst":"10.251.1.2/32","dir":"out","if_id":"0x123"}]`, false, false},
		{"policy-target", "policy", `[{"src":"10.251.1.1/32","dst":"10.251.1.2/32","dir":"fwd","if_id":"0x2121"}]`, true, false},
		{"state-no-ifid", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"ah"}]`, false, false},
		{"state-target", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"esp","if_id":8481}]`, true, false},
		{"policy-blank-object", "policy", `[{}]`, false, true},
		{"state-blank-object", "state", `[{}]`, false, true},
		{"policy-unknown-only", "policy", `[{"unknown":"whatever"}]`, false, true},
		{"state-unknown-only", "state", `[{"unknown":"whatever"}]`, false, true},
		{"policy-no-dir", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24"}]`, false, true},
		{"state-no-proto", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11"}]`, false, true},
		{"policy-bad-dir", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"sideways"}]`, false, true},
		{"policy-dir-null", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":null}]`, false, true},
		{"policy-dir-number", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":1}]`, false, true},
		{"state-bad-proto", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"unknown"}]`, false, true},
		{"state-proto-null", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":null}]`, false, true},
		{"policy-no-src", "policy", `[{"dst":"10.1.0.0/24","dir":"out"}]`, false, true},
		{"state-no-dst", "state", `[{"src":"192.0.2.10","proto":"esp"}]`, false, true},
		{"policy-bad-src", "policy", `[{"src":"invalid","dst":"10.1.0.0/24","dir":"out"}]`, false, true},
		{"state-bad-dst", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11/32","proto":"esp"}]`, false, true},
		{"policy-null-ifid", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"out","if_id":null}]`, false, true},
		{"state-invalid-ifid", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"esp","if_id":"bad"}]`, false, true},
		{"duplicate-policy-ifid", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"out","if_id":"0x123","if_id":"0x2121"}]`, false, true},
		{"duplicate-state-ifid", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"esp","if_id":"0x123","if_id":"0x2121"}]`, false, true},
		{"duplicate-policy-dir", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"out","dir":"in"}]`, false, true},
		{"duplicate-state-proto", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"esp","proto":"ah"}]`, false, true},
		{"duplicate-source", "policy", `[{"src":"10.0.0.0/24","src":"10.0.1.0/24","dst":"10.1.0.0/24","dir":"in"}]`, false, true},
		{"duplicate-other-field", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","proto":"esp","spi":"0x01","spi":"0x02"}]`, false, true},
		{"noncanonical-ifid-case", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"out","IF_ID":"0x2121"}]`, false, true},
		{"noncanonical-descriptor-case", "state", `[{"src":"192.0.2.10","dst":"192.0.2.11","PROTO":"esp"}]`, false, true},
		{"malformed-second-row", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"out"},{"unknown":"invalid"}]`, false, true},
		{"null-row", "state", `[null]`, false, true},
		{"unsupported-json-top-level", "policy", `{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"out"}`, false, true},
		{"invalid-trailing-data", "policy", `[{"src":"10.0.0.0/24","dst":"10.1.0.0/24","dir":"out"}] garbage`, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := xfrmInventoryUsesID([]byte(tc.raw), id, tc.kind)
			if (err != nil) != tc.invalid || (!tc.invalid && got != tc.collision) {
				t.Fatalf("unexpected JSON inventory result: collision=%v err=%v, want collision=%v invalid=%v",
					got, err, tc.collision, tc.invalid)
			}
		})
	}
}

func TestXFRMInventoryLegacyDescriptorAndHeaderValidation(t *testing.T) {
	const id uint32 = 0x2121
	cases := []struct {
		name, kind, raw    string
		collision, invalid bool
	}{
		{"policy-no-id", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir out priority 0\n", false, false},
		{"state-no-id", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto esp spi 0x1234\n", false, false},
		{"policy-target", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir out priority 0\n\tif_id 0x2121\n", true, false},
		{"state-target", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto esp spi 0x1234\n\tif_id 0x2121\n", true, false},
		{"bare-policy-dir", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir\n", false, true},
		{"bare-state-proto", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto\n", false, true},
		{"policy-dir-next-token-invalid", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir priority 4\n", false, true},
		{"state-proto-next-token-invalid", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto spi 0x3\n", false, true},
		{"bad-policy-dir", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir sideways\n", false, true},
		{"bad-state-proto", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto unknown\n", false, true},
		{"duplicate-policy-dir", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir out\n\tdir in\n", false, true},
		{"duplicate-state-proto", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto esp\n\tproto ah\n", false, true},
		{"missing-src-dst-header", "policy", "src foo dst bar\n\tdir out\n", false, true},
		{"wrong-state-header", "state", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tproto esp\n", false, true},
		{"duplicate-ifid", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir out\n\tif_id 0x2\n\tif_id 0x2121\n", false, true},
		{"unrecognized-text", "state", "nothing recognizably XFRM", false, true},
		{"incomplete-second-record", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir in\nsrc 10.0.1.0/24 dst 10.1.1.0/24\n", false, true},
		{"valid-multiple-records", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir in\nsrc 10.0.1.0/24 dst 10.1.1.0/24\n\tdir out\n\tif_id 0x2121\n", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := xfrmInventoryUsesID([]byte(tc.raw), id, tc.kind)
			if (err != nil) != tc.invalid || (!tc.invalid && got != tc.collision) {
				t.Fatalf("unexpected legacy inventory result: collision=%v err=%v, want collision=%v invalid=%v",
					got, err, tc.collision, tc.invalid)
			}
		})
	}
}

// Duplicate JSON keys inside Linux link entries must never hide another Link
// name, a real XFRM kind, or an interface ID.
func TestXFRMVacancyLinkInventoryDuplicateKeys(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("0x%x", p.InterfaceID)
	cases := []struct {
		name, inventory string
		reject          bool
	}{
		{"ifname-later-foreign", fmt.Sprintf(`[{"ifname":"%s","ifname":"other"}]`, p.InterfaceName), true},
		{"ifname-later-planned", fmt.Sprintf(`[{"ifname":"other","ifname":"%s"}]`, p.InterfaceName), true},
		{"duplicate-linkinfo", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":1}},"linkinfo":{"info_kind":"veth"}}]`, true},
		{"duplicate-info-kind", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_kind":"veth","info_data":{"if_id":1}}}]`, true},
		{"duplicate-info-kind-reversed", `[{"ifname":"other","linkinfo":{"info_kind":"veth","info_kind":"xfrm","info_data":{"if_id":1}}}]`, true},
		{"duplicate-info-data", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":1},"info_data":{"if_id":2}}}]`, true},
		{"duplicate-if-id", fmt.Sprintf(`[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"%s","if_id":1}}}]`, target), true},
		{"duplicate-if-id-reversed", fmt.Sprintf(`[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":1,"if_id":"%s"}}}]`, target), true},
		{"noncanonical-ifname", `[{"IfName":"other"}]`, true},
		{"noncanonical-linkinfo", `[{"ifname":"other","LinkInfo":{"info_kind":"veth"}}]`, true},
		{"noncanonical-info-kind", `[{"ifname":"other","linkinfo":{"Info_Kind":"xfrm","info_data":{"if_id":1}}}]`, true},
		{"noncanonical-info-data", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","Info_Data":{"if_id":1}}}]`, true},
		{"noncanonical-if-id", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"If_ID":1}}}]`, true},
		{"missing-ifname", `[{}]`, true},
		{"missing-xfrm-if-id", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{}}}]`, true},
		{"normal-physical-link", `[{"ifname":"lo"}]`, false},
		{"normal-veth", `[{"ifname":"veth42","linkinfo":{"info_kind":"veth","info_data":{"peer":{"ifindex":42}}}}]`, false},
		{"bridge-slave-link", `[{"ifname":"eth42","linkinfo":{"info_slave_kind":"bridge","info_slave_data":{"state":"forwarding"}}}]`, false},
		{"foreign-xfrm", `[{"ifname":"not-stl","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"0x2a"}}}]`, false},
		{"colliding-name", fmt.Sprintf(`[{"ifname":"%s"}]`, p.InterfaceName), true},
		{"colliding-ifid", fmt.Sprintf(`[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"%s"}}}]`, target), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodXFRMFixture()
			f.rows["ip -details -json link show"] = []byte(tc.inventory)
			err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p)
			if (err != nil) != tc.reject {
				t.Fatalf("unexpected link inventory result: err=%v reject=%t", err, tc.reject)
			}
		})
	}
}

// Valid iproute2 state output can include both SA proto and selector proto.
// The selector's transport protocol must not count as a second SA identity.
func TestXFRMTextStateSelectorProtocolScope(t *testing.T) {
	const id uint32 = 0x2121
	const sa = "src 192.0.2.10 dst 192.0.2.11\n\tproto esp spi 0x12345678 reqid 17 mode tunnel\n"
	const sel = "\tsel src 10.0.0.0/24 dst 10.1.0.0/24 proto tcp\n"
	cases := []struct {
		name, kind, text string
		collides, reject bool
	}{
		{"selector-no-id", "state", sa + sel, false, false},
		{"selector-different-id", "state", sa + "\tif_id 0x2a\n" + sel, false, false},
		{"selector-target-id", "state", sa + sel + "\tif_id 0x2121\n", true, false},
		{"selector-target-before", "state", sa + "\tif_id 0x2121\n" + sel, true, false},
		{"true-duplicate-sa", "state", sa + "\tproto ah spi 0x1\n" + sel, false, true},
		{"bare-sa-proto", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto\n" + sel, false, true},
		{"no-sa-proto", "state", "src 192.0.2.10 dst 192.0.2.11\n" + sel, false, true},
		{"invalid-sa-proto", "state", "src 192.0.2.10 dst 192.0.2.11\n\tproto tcp\n" + sel, false, true},
		{"bare-selector", "state", sa + "\tsel\n", false, true},
		{"broken-selector-endpoint", "state", sa + "\tsel src broken dst 10.1.0.0/24 proto tcp\n", false, true},
		{"two-top-level-ids", "state", sa + "\tif_id 0x2a\n" + sel + "\tif_id 0x2121\n", false, true},
		{"policy-nested-proto", "policy", "src 10.0.0.0/24 dst 10.1.0.0/24\n\tdir out priority 0\n\ttmpl src 192.0.2.10 dst 192.0.2.11 proto esp mode tunnel\n", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := xfrmInventoryUsesID([]byte(tc.text), id, tc.kind)
			if (err != nil) != tc.reject || (!tc.reject && got != tc.collides) {
				t.Fatalf("parser: collision=%v err=%v wantCollision=%v wantReject=%v", got, err, tc.collides, tc.reject)
			}
		})
	}
}

func TestXFRMVacancyRejectsNonXFRMIfIDAmbiguity(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`[{"ifname":"other","linkinfo":{"info_kind":"XFRM","info_data":{"if_id":42}}}]`,
		`[{"ifname":"other","linkinfo":{"info_kind":"veth","info_data":{"if_id":42}}}]`,
		`[{"ifname":"other","linkinfo":{"info_kind":"veth","info_data":{"if_id":42,"if_id":43}}}]`,
	}
	for _, raw := range cases {
		f := goodXFRMFixture()
		f.rows["ip -details -json link show"] = []byte(raw)
		if err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p); err == nil {
			t.Fatal("ambiguous link inventory accepted")
		}
	}
}

func TestXFRMLinkJSONRejectsMisplacedIdentityByScope(t *testing.T) {
	p, err := NewProfile(testIPsecLink(t, domain.EncapESP))
	if err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("0x%x", p.InterfaceID)
	cases := []struct {
		name   string
		raw    string
		reject bool
	}{
		{"root-if-id-target", fmt.Sprintf(`[{"ifname":"other","if_id":"%s"}]`, target), true},
		{"root-if-id-unrelated", `[{"ifname":"other","if_id":42}]`, true},
		{"root-info-kind", `[{"ifname":"other","info_kind":"xfrm"}]`, true},
		{"root-info-data", `[{"ifname":"other","info_data":{"if_id":42}}]`, true},
		{"root-linkinfo-nested-kind", `[{"ifname":"other","linkinfo":{"info_kind":"veth","if_id":42}}]`, true},
		{"linkinfo-if-id-target", fmt.Sprintf(`[{"ifname":"other","linkinfo":{"info_kind":"xfrm","if_id":"%s","info_data":{"if_id":42}}}]`, target), true},
		{"linkinfo-if-id-unrelated", `[{"ifname":"other","linkinfo":{"info_kind":"veth","if_id":42}}]`, true},
		{"linkinfo-misplaced-ifname", `[{"ifname":"other","linkinfo":{"ifname":"planned","info_kind":"veth"}}]`, true},
		{"linkinfo-misplaced-linkinfo", `[{"ifname":"other","linkinfo":{"linkinfo":{},"info_kind":"veth"}}]`, true},
		{"info-data-misplaced-ifname", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":42,"ifname":"stl"}}}]`, true},
		{"info-data-misplaced-linkinfo", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":42,"linkinfo":{}}}}]`, true},
		{"info-data-misplaced-info-kind", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":42,"info_kind":"veth"}}}]`, true},
		{"info-data-misplaced-info-data", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":42,"info_data":{}}}}]`, true},
		{"non-xfrm-info-data-misplaced-kind", `[{"ifname":"other","linkinfo":{"info_kind":"veth","info_data":{"info_kind":"xfrm"}}}]`, true},
		{"non-xfrm-info-data-misplaced-ifname", `[{"ifname":"other","linkinfo":{"info_kind":"veth","info_data":{"ifname":"stl"}}}]`, true},
		{"null-misplaced-if-id", `[{"ifname":"other","if_id":null}]`, true},
		{"unrelated-physical", `[{"ifname":"lo"}]`, false},
		{"unrelated-veth", `[{"ifname":"veth42","linkinfo":{"info_kind":"veth","info_data":{"peer":{"ifindex":7,"ifname":"veth43"}}}}]`, false},
		{"unrelated-bridge-slave", `[{"ifname":"eth42","linkinfo":{"info_slave_kind":"bridge","info_slave_data":{"state":"forwarding"}}}]`, false},
		{"unrelated-xfrm", `[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":42}}}]`, false},
		{"target-xfrm-id", fmt.Sprintf(`[{"ifname":"other","linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"%s"}}}]`, target), true},
		{"target-link-name", fmt.Sprintf(`[{"ifname":"%s"}]`, p.InterfaceName), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodXFRMFixture()
			f.rows["ip -details -json link show"] = []byte(tc.raw)
			err := (XFRMVacancyInspector{Runner: f.Run}).RequireVacant(context.Background(), p)
			if (err != nil) != tc.reject {
				t.Fatalf("mis-scoped XFRM identity: error=%v, reject=%t", err, tc.reject)
			}
		})
	}
}

func TestXFRMLegacyStateSelectorTailFailClosed(t *testing.T) {
	const id uint32 = 0x2121
	const sa = "src 192.0.2.10 dst 192.0.2.11\n\tproto esp spi 0x12345678 reqid 17 mode tunnel\n"
	const sel = "\tsel src 10.0.0.0/24 dst 10.1.0.0/24"
	cases := []struct {
		name               string
		tail               string
		collision, invalid bool
	}{
		{"plain-selector", "", false, false},
		{"tcp-ports", " proto tcp sport 423 dport 443 dev eth0", false, false},
		{"udp-ports", " proto udp sport 5353 dport 53", false, false},
		{"numeric-protocol", " proto 6 sport 443 dport 9443 uid 1000", false, false},
		{"icmp-selector", " proto icmp type 8 code 0 dev lo", false, false},
		{"icmp-type-max", " proto icmp type 255", false, false},
		{"icmp-code-max", " proto icmp code 255", false, false},
		{"icmpv6-type-max", " proto ipv6-icmp type 255 code 255", false, false},
		{"icmpv6-code-max", " proto ipv6-icmp code 255", false, false},
		{"transport-ports-max", " proto tcp sport 65535 dport 65535", false, false},
		{"gre-key-max", " proto gre key 4294967295", false, false},
		{"mh-type-max", " proto mobility-header type 255", false, false},
		{"mh-hex-max", " proto mobility-header (dport) 0xffff", false, false},
		{"database-proto-ggp", " proto ggp", false, false},
		{"database-proto-ax25", " proto ax.25", false, false},
		{"database-proto-wesp", " proto wesp", false, false},
		{"database-proto-ipip", " proto ipip", false, false},
		{"device-hash", " proto tcp dev stl#valid", false, false},
		{"device-exclamation", " proto tcp dev eth!0", false, false},
		{"device-tilde", " proto tcp dev eth~0", false, false},
		{"device-leading-hyphen", " proto tcp dev -eth", false, false},
		{"device-max-length", " proto tcp dev abcdefghijklmno", false, false},
		// Linux ctype treats the raw byte 0xa0 as whitespace, but 0xa1 is
		// not whitespace. These are byte sequences, not Unicode whitespace.
		{"device-kernel-space-0xa0", " proto tcp dev eth" + string([]byte{0xa0}) + "0", false, true},
		{"device-kernel-neighbor-0xa1", " proto tcp dev eth" + string([]byte{0xa1}) + "0", false, false},
		{"device-only-0xa0", " dev " + string([]byte{0xa0}), false, true},
		{"device-only-0xa1", " dev " + string([]byte{0xa1}), false, false},

		{"gre-selector", " proto gre key 123 dev tun0", false, false},
		{"mh-selector", " proto mobility-header type 3 (dport) 0x0001", false, false},
		{"mh-port-only", " proto mobility-header (dport) 0x0001", false, false},
		{"icmpv6-code-only", " proto ipv6-icmp code 3", false, false},
		{"unknown-numeric-protocol", " proto 254 sport 4", false, false},
		{"dev-and-uid", " dev eth0 uid 1000", false, false},
		{"proto-bare", " proto", false, true},
		{"proto-invalid", " proto made-up-protocol", false, true},
		{"proto-overflow", " proto 256", false, true},
		{"proto-noncanonical-decimal", " proto 006", false, true},
		{"transport-port-noncanonical", " proto tcp sport 0001", false, true},
		{"icmp-type-noncanonical", " proto icmp type 0255", false, true},
		{"icmp-code-noncanonical", " proto icmp code 0000", false, true},
		{"gre-key-noncanonical", " proto gre key 00001", false, true},
		{"uid-noncanonical", " uid 0001", false, true},
		{"proto-duplicate", " proto tcp proto udp", false, true},
		{"proto-conflicting-forms", " proto tcp proto 6", false, true},
		{"sport-bare", " proto tcp sport", false, true},
		{"sport-duplicate", " proto tcp sport 53 sport 8080", false, true},
		{"sport-invalid", " proto tcp sport not-a-port", false, true},
		{"dport-overflow", " proto udp dport 65536", false, true},
		{"icmp-type-out-of-range", " proto icmp type 256", false, true},
		{"icmp-code-out-of-range", " proto icmp code 256", false, true},
		{"icmpv6-type-out-of-range", " proto ipv6-icmp type 256", false, true},
		{"icmpv6-code-out-of-range", " proto ipv6-icmp code 65535", false, true},
		{"mh-type-out-of-range", " proto mobility-header type 256", false, true},
		{"mh-hex-short", " proto mobility-header (dport) 0x1", false, true},
		{"mh-hex-too-long", " proto mobility-header (dport) 0x00001", false, true},
		{"mh-hex-uppercase", " proto mobility-header (dport) 0x00AF", false, true},
		{"mh-hex-nonhex", " proto mobility-header (dport) 0x0xyz", false, true},
		{"device-single-dot", " proto tcp dev .", false, true},
		{"device-double-dot", " proto tcp dev ..", false, true},
		{"device-slash", " proto tcp dev eth/1", false, true},
		{"device-colon", " proto tcp dev eth:1", false, true},
		{"device-space", " proto tcp dev eth 1", false, true},
		{"device-too-long", " proto tcp dev abcdefghijklmnop", false, true},
		{"proto-invalid-database-alias", " proto IPSEC-ESP", false, true},
		{"proto-unsupported-local-name", " proto made-up-protocol", false, true},

		{"dport-negative", " proto udp dport -1", false, true},
		{"dev-bare", " proto tcp dev", false, true},
		{"dev-literal-quotes", " proto tcp dev \"\"", false, false},
		{"uid-negative", " uid -1", false, true},
		{"unexpected-token", " proto tcp unknown 4", false, true},
		{"orphan-tail-token", " proto tcp sport 21 missing", false, true},
		{"malformed-type-for-tcp", " proto tcp type 8", false, true},
		{"malformed-key-for-udp", " proto udp key 0x1", false, true},
		{"duplicate-dev", " dev eth0 dev eth1", false, true},
		{"selector-ifid-target", " if_id 0x2121", false, true},
		{"selector-ifid-unrelated", " if_id 0x2a", false, true},
		{"selector-ifid-bare", " if_id", false, true},
		{"selector-id-later", " proto tcp sport 123 if_id 0x2121", false, true},
		{"selector-id-unrelated-later", " proto tcp sport 123 if_id 42", false, true},
		{"selector-duplicate-uid", " uid 100 uid 101", false, true},
		{"selector-bad-mh-code", " proto mobility-header code 8", false, true},
		{"selector-bad-icmp-port", " proto icmp sport 8", false, true},
		{"selector-bad-gre-port", " proto gre dport 22", false, true},
		{"unknown-port-order", " proto tcp dport 80 sport 443", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := sa + sel + tc.tail + "\n"
			found, err := xfrmInventoryUsesID([]byte(raw), id, "state")
			if (err != nil) != tc.invalid || (!tc.invalid && found != tc.collision) {
				t.Fatalf("selector tail: found=%t err=%v expected collision=%t invalid=%t", found, err, tc.collision, tc.invalid)
			}
		})
	}
	for _, pair := range []struct {
		name, idText string
		collision    bool
	}{
		{"parent-id-before", "0x2121", true},
		{"unrelated-id-before", "0x2a", false},
	} {
		t.Run(pair.name, func(t *testing.T) {
			raw := sa + "\tif_id " + pair.idText + "\n" + sel + " proto tcp sport 7 dport 9\n"
			found, err := xfrmInventoryUsesID([]byte(raw), id, "state")
			if err != nil || found != pair.collision {
				t.Fatalf("parent ID: found=%t err=%v", found, err)
			}
		})
	}
	raw := sa + sel + " proto tcp sport 7 dport 9\n\tif_id 0x2121\n"
	found, err := xfrmInventoryUsesID([]byte(raw), id, "state")
	if err != nil || !found {
		t.Fatalf("parent if_id after selector: found=%t err=%v", found, err)
	}
	for _, tc := range []struct{ name, raw string }{
		{"duplicate-selector", sa + sel + " proto tcp\n" + sel + " proto udp\n"},
		{"selector-before-parent-proto", "src 192.0.2.10 dst 192.0.2.11\n" + sel + " proto tcp\n\tproto esp spi 0x1 reqid 17 mode tunnel\n"},
		{"id-noncanonical-line", sa + "\tmeta if_id 0x2121\n"},
		{"id-in-parent-proto", sa + "\tproto esp if_id 0x2121\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := xfrmInventoryUsesID([]byte(tc.raw), id, "state")
			if err == nil {
				t.Fatal("invalid selector or misplaced identifier accepted")
			}
		})
	}
}

// The legacy iproute2 selector protocol is the primary name returned by
// libc's getprotobynumber(), not a small built-in protocol-name whitelist.
// Test the first-name rule and uncommon entries with an isolated table.
func TestXFRMSelectorProtocolTableFileBacked(t *testing.T) {
	const db = "# /etc/protocols fixture\n" +
		"ip 0 IP\n" +
		"hopopt 0 HOPOPT\n" +
		"ggp 3 GGP\n" +
		"tcp 6 TCP\n" +
		"tcp-alternate 6 TCP-ALTERNATE\n" +
		"mobility-header 135 Mobility-Header\n" +
		"ax.25 93 AX.25\n" +
		"wesp 141 WESP\n" +
		"custom-proto 222 CUSTOM-PROTO\n" +
		"out-of-range 262 MPTCP\n"
	for _, tc := range []struct {
		name   string
		number uint64
		valid  bool
	}{
		{"ggp", 3, true},
		{"ax.25", 93, true},
		{"wesp", 141, true},
		{"mobility-header", 135, true},
		{"custom-proto", 222, true},
		{"tcp", 6, true},
		{"tcp-alternate", 0, false},
		{"TCP", 0, false},
		{"hopopt", 0, false},
		{"made-up-protocol", 0, false},
		{"out-of-range", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := xfrmSelectorProtocolTable(tc.name, []byte(db))
			if ok != tc.valid || (ok && got != tc.number) {
				t.Fatalf("protocol lookup: got=%d valid=%t, want %d/%t", got, ok, tc.number, tc.valid)
			}
		})
	}
	if _, ok := xfrmSelectorProtocolTable("tcp", []byte("tcp 6\nTCP 6\ntcp 17\n")); ok {
		t.Fatal("conflicting primary mappings must fail closed")
	}
	if n, ok := xfrmSelectorProtocol("254"); !ok || n != 254 {
		t.Fatalf("numeric protocol fallback invalid: %d / %t", n, ok)
	}
	if _, ok := xfrmSelectorProtocol("256"); ok {
		t.Fatal("protocol greater than uint8 unexpectedly accepted")
	}
}

// Supported Debian/Ubuntu runtimes provide /etc/protocols. These entries
// also come from getent's canonical number->name results on the isolated
// Debian 12 runtime; they are all absent from the previous hard-coded map.
func TestXFRMSelectorProtocolHostDatabase(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   uint64
	}{
		{"ggp", 3}, {"ax.25", 93}, {"ipip", 94},
		{"mobility-header", 135}, {"wesp", 141},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := xfrmSelectorProtocol(tc.name)
			if !ok || got != tc.id {
				t.Fatalf("file-backed %s: got %d / %t, want %d", tc.name, got, ok, tc.id)
			}
		})
	}
	if _, ok := xfrmSelectorProtocol("made-up-protocol"); ok {
		t.Fatal("invented protocol name must not prove valid inventory")
	}
}

// Validate the kernel's dev_valid_name constraints rather than an STL
// naming convention; foreign link names may include punctuation such as #.
func TestXFRMSelectorDeviceKernelNames(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"eth0", true}, {"eth#hash", true}, {"dev!name", true},
		{"stl~test", true}, {"-leading", true}, {"quote\"name", true},
		{"abcdefghi123456", true}, {"veth@peer", true},
		// Raw Linux ctype byte classification: 0xa0 is space, 0xa1 is not.
		{string([]byte{0xa0}), false}, {string([]byte{0xa1}), true},
		{"eth" + string([]byte{0xa0}) + "0", false},
		{"eth" + string([]byte{0xa1}) + "0", true},
		{"", false}, {".", false}, {"..", false},
		{"has/slash", false}, {"eth:alias", false},
		{"two words", false}, {"has\ttab", false},
		{"has\nnewline", false}, {"has\rreturn", false},
		{"has\vvertical", false}, {"has\fform", false},
		{"a\x00b", false}, {"abcdefghijklmnop", false},
	} {
		t.Run(fmt.Sprintf("%q", tc.name), func(t *testing.T) {
			got := validXFRMSelectorDevice(tc.name)
			if got != tc.valid {
				t.Fatalf("device %q: got %t, want %t", tc.name, got, tc.valid)
			}
		})
	}
}
