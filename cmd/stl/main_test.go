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

	var got struct {
		SchemaVersion int    `json:"schema_version"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		Date          string `json:"date"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("version output is not JSON: %v", err)
	}
	if got.SchemaVersion != jsonSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", got.SchemaVersion, jsonSchemaVersion)
	}
	if got.Version == "" || got.Commit == "" || got.Date == "" {
		t.Fatalf("version JSON contains empty fields: %#v", got)
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
