package ipsec

import (
	"context"
	"strings"
	"testing"
)

func TestStrongSwanSocketBypassPoliciesAreDistinctFromOwnedXFRMID(t *testing.T) {
	sockets := strings.Join([]string{
		"src ::/0 dst ::/0 ",
		"\tsocket in priority 0 ",
		"src 0.0.0.0/0 dst 0.0.0.0/0 ",
		"\tsocket out priority 0 ",
		"src 10.88.10.0/31 dst 10.88.10.1/31 ",
		"\tdir in priority 12345",
		"\tif_id 999",
	}, "\n") + "\n"
	has, err := xfrmTextUsesID(context.Background(), []byte(sockets), 999, "policy")
	if err != nil || !has {
		t.Fatalf("child policy after bypass not identified: found=%v err=%v", has, err)
	}
	has, err = xfrmTextUsesID(context.Background(), []byte(sockets), 1000, "policy")
	if err != nil || has {
		t.Fatalf("socket bypass falsely reported target ID: found=%v err=%v", has, err)
	}
}

func TestSocketBypassUnexpectedAttributesFailClosed(t *testing.T) {
	for name, descriptor := range map[string]string{
		"nonzero-priority":  "socket out priority 1",
		"ambiguous-mark":    "socket in priority 0 mark 99",
		"invalid-direction": "socket fwd priority 0",
		"missing-priority":  "socket in",
		"attached-if-id":    "socket in priority 0\n\tif_id 42",
		"nonwildcard":       "socket in priority 0",
	} {
		t.Run(name, func(t *testing.T) {
			header := "src ::/0 dst ::/0 \n"
			if name == "nonwildcard" {
				header = "src 10.88.0.1/32 dst 10.88.0.2/32 \n"
			}
			if found, err := xfrmTextUsesID(context.Background(), []byte(header+"\t"+descriptor+"\n"), 42, "policy"); err == nil {
				t.Fatalf("untrusted socket-like policy accepted as vacant found=%v", found)
			}
		})
	}
}
