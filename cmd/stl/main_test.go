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

func TestUnknownLinkSubcommandReportsCorrectHelpAndJSON(t *testing.T) {
	for _, tc := range []struct {
		name, operation, detail string
		args                    []string
		json                    bool
	}{
		{"unknown plain", "link", "unknown or missing link subcommand", []string{"link", "nonsense"}, false},
		{"unknown JSON", "link", "unknown or missing link subcommand", []string{"link", "nonsense", "--json"}, true},
		{"missing JSON", "link", "unknown or missing link subcommand", []string{"link", "--json"}, true},
		{"restore invalid plain", "link_restore", "usage: stl link restore --all", []string{"link", "restore", "--bad"}, false},
		{"restore invalid JSON", "link_restore", "usage: stl link restore --all", []string{"link", "restore", "--bad", "--json"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := runWithRuntimeInput(tc.args, nil, &out, &errOut, nil); code != 2 {
				t.Fatalf("code=%d want=2, stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if tc.json {
				if errOut.Len() != 0 {
					t.Fatalf("JSON error leaked to stderr: %q", errOut.String())
				}
				var got linkReadErrorResponse
				if err := json.Unmarshal(out.Bytes(), &got); err != nil {
					t.Fatalf("invalid JSON error: %v; stdout=%q", err, out.String())
				}
				if got.SchemaVersion != jsonSchemaVersion || got.Error == nil ||
					got.Error.Code != "invalid" || got.Error.Operation != tc.operation ||
					!strings.Contains(got.Error.Detail, tc.detail) || got.Error.ReasonCode == "" ||
					got.Error.NextStep == "" {
					t.Fatalf("wrong JSON guidance: %+v", got)
				}
			} else if out.Len() != 0 || !strings.Contains(errOut.String(), tc.detail) ||
				strings.Contains(errOut.String(), "usage: stl link restore --all") && tc.operation != "link_restore" {
				t.Fatalf("misleading Link guidance: stdout=%q stderr=%q", out.String(), errOut.String())
			}
		})
	}
}

func TestGuidedCreateCancelNoticeFitsNarrowTerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	prompts := createPrompts{out: &stdout, errOut: &stderr}
	if code := prompts.failed(errCreateCancelled); code != 0 || stderr.Len() != 0 {
		t.Fatalf("cancel returned an error: code=%d stderr=%q", code, stderr.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n") {
		if len(line) > 76 {
			t.Fatalf("operator cancellation notice exceeds 76 columns: %q", line)
		}
	}
	if !strings.Contains(stdout.String(), "No new Link was created") ||
		!strings.Contains(stdout.String(), "preparation is not rolled back") {
		t.Fatalf("cancelled create lost prerequisite persistence guidance: %q", stdout.String())
	}
}
