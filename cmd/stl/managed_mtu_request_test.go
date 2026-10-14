package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
)

func TestDesiredLinkV2AddsOnlyEndpointLocalMTUAndPreservesV1(t *testing.T) {
	link, oldJSON := makeLifecycleDesired(t, "2", "10.70.55.0/31")
	old, err := decodeDesiredLink(strings.NewReader(oldJSON))
	if err != nil || old.MTU.Mode != domain.MTUUnmanaged {
		t.Fatalf("frozen v1 input changed meaning: %+v %v", old, err)
	}
	var v1 desiredLinkRequestV1
	if err := json.Unmarshal([]byte(oldJSON), &v1); err != nil {
		t.Fatal(err)
	}
	v2 := desiredLinkRequestV2{SchemaVersion: managedMTUSchemaVersion, Link: desiredLinkV2{
		desiredLinkV1: v1.Link, MTU: domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1300},
	}}
	raw, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"mtu":{"mode":"manual","bytes":1300}`)) ||
		!bytes.Contains(raw, []byte(`"backend":"gre"`)) {
		t.Fatalf("v2 serializer lost inline fields: %s", raw)
	}
	got, err := decodeDesiredLink(bytes.NewReader(raw))
	if err != nil || got.ID != link.ID || got.MTU != v2.Link.MTU {
		t.Fatalf("v2 failed exact decode %+v %v", got, err)
	}
	unmanagedRequest := v2
	unmanagedRequest.Link.MTU = domain.MTUPolicy{Mode: domain.MTUUnmanagedExplicit}
	disableBytes, err := json.Marshal(unmanagedRequest)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := decodeDesiredLink(bytes.NewReader(disableBytes))
	if err != nil || disabled.MTU.Mode != domain.MTUUnmanagedExplicit {
		t.Fatalf("explicit v2 unmanaged opt-out rejected: %+v %v", disabled.MTU, err)
	}
	for _, tc := range []struct{ name, body string }{
		{"v1 rejects new mtu", strings.Replace(oldJSON, `"encapsulation":"native"`, `"encapsulation":"native","mtu":{"mode":"auto"}`, 1)},
		{"v2 unknown local field", strings.Replace(string(raw), `"bytes":1300`, `"bytes":1300,"remote_mtu":1390`, 1)},
		{"v2 manual without bytes", strings.Replace(string(raw), `"bytes":1300`, `"bytes":0`, 1)},
		{"v2 unsupported mode", strings.Replace(string(raw), `"mode":"manual"`, `"mode":"adaptive"`, 1)},
		{"v2 duplicate mtu", strings.Replace(string(raw), `"mtu":`, `"mtu":{},"mtu":`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeDesiredLink(strings.NewReader(tc.body)); err == nil {
				t.Fatalf("unsafe schema accepted: %s", tc.body)
			}
		})
	}
}

func TestManagedV2CreatorRequestsAndLegacyStillDecode(t *testing.T) {
	link, _ := makeLifecycleDesired(t, "3", "10.70.56.0/31")
	wg := wireGuardSenderRequestV1{
		SchemaVersion: 1, LinkID: link.ID,
		Underlay:   desiredUnderlayV1{Local: link.Underlay.Local, Peer: link.Underlay.Peer},
		Addresses:  desiredLinkAddressesV1{Local: link.Addresses.Local, Peer: link.Addresses.Peer},
		ListenPort: 51871, PeerPort: 51872,
	}
	wire, err := json.Marshal(wg)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := decodeWireGuardSenderRequest(bytes.NewReader(wire))
	if err != nil || legacy.MTU.Mode != domain.MTUUnmanaged {
		t.Fatalf("v1 WireGuard creator drifted: %+v %v", legacy, err)
	}
	wg.SchemaVersion = 2
	wire, err = json.Marshal(wireGuardSenderRequestV2{
		wireGuardSenderRequestV1: wg, MTU: domain.MTUPolicy{Mode: domain.MTUAuto},
	})
	if err != nil {
		t.Fatal(err)
	}
	managed, err := decodeWireGuardSenderRequest(bytes.NewReader(wire))
	if err != nil || managed.MTU.Mode != domain.MTUAuto {
		t.Fatalf("v2 WireGuard creator rejected: %+v %v", managed, err)
	}
	if _, err = decodeWireGuardSenderRequest(strings.NewReader(strings.Replace(string(wire), `"mode":"auto"`, `"mode":"unsafe"`, 1))); err == nil {
		t.Fatal("unknown WireGuard MTU mode admitted")
	}
	ipsec := ipsecSenderRequestV1{
		SchemaVersion: 1, LinkID: link.ID, Underlay: wg.Underlay,
		Addresses: wg.Addresses, Encapsulation: domain.EncapNATT,
	}
	wire, err = json.Marshal(ipsec)
	if err != nil {
		t.Fatal(err)
	}
	legacyIP, err := decodeIPsecSenderRequest(bytes.NewReader(wire))
	if err != nil || legacyIP.MTU.Mode != domain.MTUUnmanaged {
		t.Fatalf("v1 IPsec creator drifted: %+v %v", legacyIP, err)
	}
	ipsec.SchemaVersion = 2
	wire, err = json.Marshal(ipsecSenderRequestV2{ipsecSenderRequestV1: ipsec,
		MTU: domain.MTUPolicy{Mode: domain.MTUManual, Bytes: 1250}})
	if err != nil {
		t.Fatal(err)
	}
	managedIP, err := decodeIPsecSenderRequest(bytes.NewReader(wire))
	if err != nil || managedIP.MTU.Bytes != 1250 {
		t.Fatalf("v2 IPsec creator rejected: %+v %v", managedIP, err)
	}
	if _, err = decodeIPsecSenderRequest(strings.NewReader(strings.Replace(string(wire), `"bytes":1250`, `"bytes":0`, 1))); err == nil {
		t.Fatal("invalid IPsec MTU accepted")
	}
}
