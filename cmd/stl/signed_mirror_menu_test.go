package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestSignedMirrorMenuNeverExecutesWithoutInstalledRootTTY(t *testing.T) {
	input := strings.NewReader("https://mirror.example.test/install.sh\nUPDATE\n")
	var out, errors bytes.Buffer
	calls := 0
	got := menuUpdateSignedMirror(input, bufio.NewReader(input), &out, &errors, false,
		func([]string, io.Writer, io.Writer) int { calls++; return 0 })
	if got != 0 || calls != 0 || !strings.Contains(out.String(), "requires the installed root STL") {
		t.Fatalf("redirected non-privileged signed update was offered: code=%d calls=%d out=%q",
			got, calls, out.String())
	}
}

func TestSignedMirrorMenuFreshConsentAndSourceValidation(t *testing.T) {
	cases := []struct {
		name, input string
		calls, want int
	}{
		{"valid explicit confirmation", "https://mirror.example.test/install.sh\nUPDATE\n", 1, menuUpdatedExecutable},
		{"cancel", "https://mirror.example.test/install.sh\n\n", 0, 0},
		{"invalid insecure origin", "http://mirror.example.test/install.sh\nUPDATE\n", 0, 0},
		{"query-bearing origin", "https://mirror.example.test/install.sh?x=1\nUPDATE\n", 0, 0},
		{"missing source", "\nUPDATE\n", 0, 0},
		{"no confirmation", "https://mirror.example.test/install.sh\nNO\n", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.NewReader(tc.input)
			calls := 0
			var out, stderr bytes.Buffer
			got := menuUpdateSignedMirror(input, bufio.NewReader(input), &out, &stderr, true,
				func(args []string, _, _ io.Writer) int {
					calls++
					if len(args) != 2 || args[0] != "--signed-mirror" ||
						args[1] != "https://mirror.example.test/install.sh" {
						t.Fatalf("unverified signed mirror args: %q", args)
					}
					return 0
				})
			if got != tc.want || calls != tc.calls {
				t.Fatalf("signed mirror consent contract: got=%d want=%d calls=%d wantCalls=%d out=%q",
					got, tc.want, calls, tc.calls, out.String())
			}
		})
	}
}

func TestSignedMirrorSameInstalledVersionOnlyRecoversExactPublisherCommit(t *testing.T) {
	state, key, meta, _, _ := sampleSignedMirror(t)
	meta.Version = "v0.1.25"
	meta.Commit = strings.Repeat("a", 40)
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, raw)
	pub, err := validatedPublisherTrust(state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyMirrorSignedRelease(raw, sig, pub, state, "v0.1.25")
	if err != nil || got.Version != "v0.1.25" {
		t.Fatalf("exact installed-version recovery rejected: %v", err)
	}
	meta.Sequence = 8
	raw, _ = json.Marshal(meta)
	sig = ed25519.Sign(key, raw)
	if _, err := verifyMirrorSignedRelease(raw, sig, pub, state, "v0.1.25"); err == nil {
		t.Fatal("replayed same-version recovery was accepted")
	}
}
