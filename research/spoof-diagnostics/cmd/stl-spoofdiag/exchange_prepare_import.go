package main

// Content-identified Case preparation files are inert. A single signature
// proves one node's declaration, NOT that the other side has agreed.
import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type exchangeCasePart struct {
	CaseID    string
	Node      string
	Type      string
	Canonical []byte
}

func exchangeRecognizeCase(path, ca string) (exchangeCasePart, error) {
	var zero exchangeCasePart
	data, err := readSmallRegular(path, fieldMaxControl)
	if err != nil {
		return zero, err
	}
	raw := bytes.TrimSpace(data)
	if len(raw) == 0 || raw[0] != '{' {
		return zero, errors.New("not a Case preparation JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return zero, err
	}
	if _, ok := fields["format"]; ok {
		var c scheduledCase
		if err := strictJSON(raw, &c); err != nil {
			return zero, err
		}
		if err := validateScheduledCase(c, time.Now(), false); err != nil {
			return zero, err
		}
		normalized, err := jsonBytes(c)
		if err != nil {
			return zero, err
		}
		return exchangeCasePart{CaseID: c.CaseID, Node: "", Type: "UNSIGNED_CASE", Canonical: normalized}, nil
	}
	if _, ok := fields["case"]; ok {
		var env signedScheduledCase
		if err := strictJSON(raw, &env); err != nil {
			return zero, err
		}
		if err := validateScheduledCase(env.Case, time.Now(), false); err != nil {
			return zero, err
		}
		if env.Node != "A" && env.Node != "B" {
			return zero, errors.New("unknown signed Case node")
		}
		if ca == "" {
			return zero, errors.New("signed Case needs an independently supplied CA")
		}
		roots, err := certificateRoots(ca)
		if err != nil {
			return zero, err
		}
		declaredAt, err := time.Parse(time.RFC3339Nano, env.Case.CreatedUTC)
		if err != nil {
			return zero, err
		}
		leaf, err := verifyFieldSignature(env.Case, env.CertificatePEM, env.SignatureHex, roots,
			env.Node, declaredAt, x509.ExtKeyUsageClientAuth)
		if err != nil {
			return zero, err
		}
		pinned := env.Case.ACertificateSHA256
		if env.Node == "B" {
			pinned = env.Case.BCertificateSHA256
		}
		if exchangeSHA(leaf.Raw) != pinned {
			return zero, errors.New("Case fragment signer differs from pinned node identity")
		}
		normalized, err := jsonBytes(env)
		if err != nil {
			return zero, err
		}
		return exchangeCasePart{CaseID: env.Case.CaseID, Node: env.Node, Type: "SIGNED_CASE_FRAGMENT",
			Canonical: normalized}, nil
	}
	return zero, errors.New("not a recognizable Case preparation file")
}

func exchangeStageCase(base string, part exchangeCasePart) (string, bool, error) {
	if !exchangeIDPattern.MatchString(part.CaseID) || len(part.Canonical) == 0 {
		return "", false, errors.New("invalid Case preparation to stage")
	}
	folder := filepath.Join(base, "preparation")
	st, err := os.Lstat(folder)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return "", false, errors.New("prepare private exchange directories using exchange init")
	}
	suffix := "definition"
	if part.Type == "SIGNED_CASE_FRAGMENT" {
		suffix = "signed-" + part.Node
	}
	hash := exchangeSHA(part.Canonical)
	target := filepath.Join(folder, fmt.Sprintf("SDX-CASE-%s-%s-%s.json", part.CaseID, suffix, hash))
	old, err := os.Lstat(target)
	if err == nil {
		if !old.Mode().IsRegular() || old.Mode().Perm()&0077 != 0 {
			return "", false, errors.New("unsafe existing Case part")
		}
		contents, err := readSmallRegular(target, fieldMaxControl)
		if err != nil || !bytes.Equal(contents, part.Canonical) {
			return "", false, errors.New("Case digest path contains conflicting content")
		}
		return target, true, nil
	}
	if !os.IsNotExist(err) {
		return "", false, err
	}
	if err := exchangeWriteNew(target, part.Canonical); err != nil {
		return "", false, err
	}
	return target, false, nil
}

func exchangeFindStagedCase(base, caseID, ca string) (string, string, string, error) {
	if !exchangeIDPattern.MatchString(caseID) {
		return "", "", "", errors.New("invalid Case ID")
	}
	directory := filepath.Join(base, "preparation")
	st, err := os.Lstat(directory)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return "", "", "", errors.New("private preparation directory missing or unsafe")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", "", "", err
	}
	if len(entries) > exchangeMaxEntries {
		return "", "", "", errors.New("too many staged Case entries")
	}
	found := map[string]string{}
	identities := map[string]string{}
	for _, file := range entries {
		if !file.Type().IsRegular() {
			return "", "", "", errors.New("unsafe staged Case entry")
		}
		path := filepath.Join(directory, file.Name())
		part, err := exchangeRecognizeCase(path, ca)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid staged Case file %s: %w", file.Name(), err)
		}
		if part.CaseID != caseID {
			continue
		}
		slot := part.Node
		if slot == "" {
			slot = "definition"
		}
		digest := exchangeSHA(part.Canonical)
		if previous, exists := identities[slot]; exists {
			if previous != digest {
				return "", "", "", fmt.Errorf("conflicting Case %s part; resolve manually", slot)
			}
			continue
		}
		identities[slot] = digest
		found[slot] = path
	}
	for _, slot := range []string{"definition", "A", "B"} {
		if found[slot] == "" {
			return "", "", "", fmt.Errorf("Case preparation incomplete: missing %s", slot)
		}
	}
	return found["definition"], found["A"], found["B"], nil
}

// When a trusted CA is available, the auto-discovered three immutable
// artifacts can be verified without manual renaming or guessing paths.
func exchangeValidateStagedCase(base, caseID, ca string) (scheduledCase, error) {
	def, a, b, err := exchangeFindStagedCase(base, caseID, ca)
	if err != nil {
		return scheduledCase{}, err
	}
	return verifyScheduledCase(def, a, b, ca, time.Now(), true)
}
