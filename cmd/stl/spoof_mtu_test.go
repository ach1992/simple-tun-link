package main

import (
	"github.com/ach1992/simple-tun-link/internal/domain"
	"testing"
)

func TestSpoofMTUValidationAndOperatorConfig(t *testing.T) {
	for _, raw := range []string{"", "auto"} {
		got, e := parseSpoofMTU(raw)
		if e != nil || got.Mode != domain.MTUAuto {
			t.Fatalf("auto %q: %+v %v", raw, got, e)
		}
	}
	for _, raw := range []string{"576", "1024", "1280", "65431"} {
		got, e := parseSpoofMTU(raw)
		if e != nil || got.Mode != domain.MTUManual {
			t.Fatalf("manual %q: %+v %v", raw, got, e)
		}
	}
	for _, raw := range []string{"-1", "0", "1", "575", "65432", "65535", "abc", "12.5", "auto;rm"} {
		if _, e := parseSpoofMTU(raw); e == nil {
			t.Fatalf("invalid MTU %q accepted", raw)
		}
	}
}
