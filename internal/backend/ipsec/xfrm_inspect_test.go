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
		{"orphan-policy", "ip -json xfrm policy", fmt.Sprintf(`[{"if_id":"%s","dir":"out"}]`, hexID)},
		{"orphan-sa", "ip -json xfrm state", fmt.Sprintf(`[{"if_id":"%s","aead":{"key":"sensitive-fixture-must-not-leak"}}]`, hexID)},
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
	f.rows["ip -json xfrm policy"] = []byte(fmt.Sprintf(`[{"if_id":%d}]`, otherID))
	f.rows["ip -json xfrm state"] = []byte(fmt.Sprintf(`[{"if_id":%d}]`, otherID))
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
