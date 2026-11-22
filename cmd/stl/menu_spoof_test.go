package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/carrier/spoof"
	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
)

func TestGuidedSpoofCreateConfirmationIsEffectFreeBeforeYES(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "sources.txt")
	if err := os.WriteFile(source, []byte("198.18.0.11\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "setup.code")
	answers := strings.Join([]string{
		source, "1", "", "192.0.2.10:42001", "198.51.100.20:42002",
		"10.245.62.1", "10.245.62.2", "", output, "no", "",
	}, "\n")
	input := strings.NewReader(answers)
	var out, stderr bytes.Buffer
	if code := menuCreateSpoof(input, bufio.NewReader(input), &out, &stderr, nil); code != 0 {
		t.Fatalf("cancel must be effect-free, exit=%d stdout=%s stderr=%s", code, out.String(), stderr.String())
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created protected handoff before explicit YES: %v", err)
	}
	if !strings.Contains(out.String(), "Cancelled") || !strings.Contains(out.String(), "Spoof") {
		t.Fatal("guided Spoof confirmation not shown")
	}
}

func TestGuidedSpoofImportReviewsFileWithoutEchoingCodeOrMutating(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "sources.txt")
	if err := os.WriteFile(source, []byte("198.18.0.12\n"), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := domain.NewLinkID()
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := spoof.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	offer, err := pairing.NewSpoofSetup(id, netip.MustParseAddrPort("192.0.2.10:42001"),
		netip.MustParseAddrPort("198.51.100.20:42002"), netip.MustParseAddr("10.245.62.1"), netip.MustParseAddr("10.245.62.2"), public)
	if err != nil {
		t.Fatal(err)
	}
	code, err := offer.EncodeSensitive()
	if err != nil {
		t.Fatal(err)
	}
	setup := filepath.Join(root, "secret.code")
	if err := os.WriteFile(setup, []byte(code+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input := strings.NewReader(strings.Join([]string{setup, source, "", "no", ""}, "\n"))
	var out, stderr bytes.Buffer
	if exit := menuImportSpoof(input, bufio.NewReader(input), &out, &stderr, nil); exit != 0 {
		t.Fatalf("cancel import=%d out=%s err=%s", exit, out.String(), stderr.String())
	}
	if strings.Contains(out.String(), code) || strings.Contains(stderr.String(), code) {
		t.Fatal("sensitive Setup Code leaked through menu")
	}
	if !strings.Contains(out.String(), string(id)) ||
		!strings.Contains(out.String(), "Cancelled") {
		t.Fatal("menu did not show review/cancel result")
	}
}

func TestGuidedSpoofSourceFileRecheckCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-sources.txt")
	input := strings.NewReader(path + "\nq\n")
	var out bytes.Buffer
	_, err := askSpoofSourceFile(createPrompts{reader: bufio.NewReader(input), out: &out, errOut: io.Discard})
	if !errors.Is(err, errCreateCancelled) || !strings.Contains(out.String(), "Recheck") {
		t.Fatal("missing inventory must give accurate Recheck and allow cancel")
	}
}
