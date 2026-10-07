package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "simple-tun-link") {
		t.Fatalf("help output missing project name: %q", out.String())
	}
}

func TestVersionJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr=%q", code, errOut.String())
	}

	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("version output is not JSON: %v", err)
	}
	for _, key := range []string{"version", "commit", "date"} {
		if got[key] == "" {
			t.Fatalf("version JSON missing %q: %#v", key, got)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"nope"}, &out, &errOut); code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("stderr missing useful error: %q", errOut.String())
	}
}
