package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ach1992/simple-tun-link/internal/domain"
	"github.com/ach1992/simple-tun-link/internal/pairing"
)

func TestIPsecCreateFailClosedBeforePSKStaging(t *testing.T) {
	private := t.TempDir()
	output := filepath.Join(private, "sensitive-ipsec.url")
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"schema_version": 1, "link_id": "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"underlay":      map[string]string{"local": "192.0.2.1", "peer": "192.0.2.2"},
		"addresses":     map[string]string{"local": "10.88.90.0/31", "peer": "10.88.90.1/31"},
		"encapsulation": "esp",
	}
	data, _ := json.Marshal(request)
	root := filepath.Join(private, "state")
	opts := &runtimeOptions{stateRoot: root}
	var stdout, stderr bytes.Buffer
	exit := runWithRuntimeInput([]string{"link", "create-ipsec", "--stdin", "--output", output, "--json"},
		bytes.NewReader(data), &stdout, &stderr, opts)
	if exit != 4 || stderr.Len() != 0 {
		t.Fatalf("without admitted runtime must fail: code=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("unadmitted sender wrote handoff")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("unadmitted sender staged key or state")
	}
	var response lifecycleFailureResponse
	if json.Unmarshal(stdout.Bytes(), &response) != nil || response.Error.Code != "unsupported" ||
		response.SchemaVersion != 1 || response.Outcome != "unconfirmed" {
		t.Fatalf("incorrect secret-safe versioned failure: %s", stdout.String())
	}
}

func TestIPsecRecipientImportWithoutAdmittedServiceKeepsSecretProtected(t *testing.T) {
	temp := t.TempDir()
	secret := bytes.Repeat([]byte{0x42}, 32)
	link := domain.Link{
		ID:      domain.LinkID("lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Backend: domain.BackendIPsec, Encapsulation: domain.EncapNATT,
		Underlay:  domain.Underlay{Local: netip.MustParseAddr("192.0.2.1"), Peer: netip.MustParseAddr("192.0.2.2")},
		Addresses: domain.LinkAddresses{Local: netip.MustParsePrefix("10.88.92.0/31"), Peer: netip.MustParsePrefix("10.88.92.1/31")},
	}
	offer, err := pairing.NewQuickOffer(link, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer offer.ClearRecipientCredential()
	encoded, err := offer.EncodeSetupLink()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(encoded))
	opts := &runtimeOptions{stateRoot: filepath.Join(temp, "state")}
	var stdout, stderr bytes.Buffer
	exit := runWithRuntimeInput([]string{"link", "import", "--stdin", "--confirm", hex.EncodeToString(hash[:]), "--json"},
		strings.NewReader(encoded), &stdout, &stderr, opts)
	if exit != 4 || stderr.Len() != 0 {
		t.Fatalf("unadmitted IPsec import must fail: code=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(opts.stateRoot); !os.IsNotExist(err) {
		t.Fatal("recipient staged key before admission")
	}
	if strings.Contains(stdout.String(), encoded) {
		t.Fatal("SENSITIVE Quick Link leaked")
	}
}

func TestIPsecCLIRejectsWrongConfirmationAndUnsafeSchema(t *testing.T) {
	opts := &runtimeOptions{stateRoot: filepath.Join(t.TempDir(), "state")}
	id := "lnk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var out, errs bytes.Buffer
	exit := runWithRuntime([]string{"link", "connect-ipsec", id, "--confirm",
		"lnk_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "--json"}, &out, &errs, opts)
	if exit != 2 {
		t.Fatalf("wrong confirmation accepted: %d", exit)
	}
	out.Reset()
	errs.Reset()
	exit = runWithRuntime([]string{"link", "connect-ipsec", id, "--confirm", id, "--json"}, &out, &errs, opts)
	if exit != 4 {
		t.Fatalf("unadmitted Connect reached VICI: %d", exit)
	}
	raw := []string{
		"{\"schema_version\":1,\"schema_version\":1}",
		"{\"schema_version\":1,\"secret\":\"never-allowed\"}",
		"{\"schema_version\":2}",
	}
	for _, candidate := range raw {
		if _, err := decodeIPsecSenderRequest(strings.NewReader(candidate)); err == nil {
			t.Fatalf("invalid IPsec creator JSON accepted: %s", candidate)
		}
	}
	if pairing.SchemaVersion != 2 {
		t.Fatalf("unexpected Quick Link schema change: %d", pairing.SchemaVersion)
	}
}
