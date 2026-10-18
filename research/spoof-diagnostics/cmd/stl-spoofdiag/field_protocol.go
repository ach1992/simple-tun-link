package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	fieldMinPacket  = 128
	fieldMaxPacket  = 1200
	fieldMaxSamples = 32
	fieldMaxControl = 64 << 10
)

type fieldSample struct {
	Index     int       `json:"index"`
	Candidate Candidate `json:"candidate"`
	Size      int       `json:"packet_size"`
	Epoch     string    `json:"policy_epoch"`
}

type fieldSeen struct {
	Index              int    `json:"index"`
	SourceCandidate    string `json:"source_candidate"`
	ActualPacketSource string `json:"actual_packet_source"`
	PacketSize         int    `json:"packet_size"`
	Direction          string `json:"direction"`
	PolicyEpoch        string `json:"policy_epoch"`
	Authenticated      bool   `json:"authenticated"`
	SourceMatched      bool   `json:"source_matched"`
}

type fieldReceipt struct {
	SchemaVersion      int         `json:"schema_version"`
	Environment        string      `json:"environment"`
	RunID              string      `json:"run_id"`
	Observer           string      `json:"observer"`
	CreatedUTC         string      `json:"created_utc"`
	ExpectedSamples    int         `json:"expected_samples"`
	ChallengeDigest    string      `json:"challenge_digest,omitempty"`
	Observations       []fieldSeen `json:"observations"`
	EgressStatus       string      `json:"egress_status"`
	CandidateAdmission string      `json:"candidate_admission"`
	ReturnToSender     string      `json:"return_to_sender"`
	PrivateL3          string      `json:"private_l3"`
}

type fieldEnvelope struct {
	Receipt                fieldReceipt `json:"receipt"`
	ObserverCertificatePEM string       `json:"observer_certificate_pem"`
	SignatureHex           string       `json:"signature_hex"`
}

func strictJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > fieldMaxControl {
		return errors.New("invalid message size")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func readSmallRegular(path string, max int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("unsafe or oversized file %q", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > max {
		return nil, errors.New("unsafe file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("oversized input file")
	}
	return data, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func roleDirection(sender, receiver string) (string, error) {
	switch {
	case sender == "A" && receiver == "B":
		return "A_TO_B", nil
	case sender == "B" && receiver == "A":
		return "B_TO_A", nil
	default:
		return "", errors.New("field requires distinct A/B node roles")
	}
}

func signFieldReceipt(receipt fieldReceipt, cert tls.Certificate) (fieldEnvelope, error) {
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return fieldEnvelope{}, errors.New("field signing requires Ed25519 leaf key")
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return fieldEnvelope{}, err
	}
	if len(cert.Certificate) == 0 {
		return fieldEnvelope{}, errors.New("missing signer certificate")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	return fieldEnvelope{Receipt: receipt, ObserverCertificatePEM: string(pemBytes), SignatureHex: hex.EncodeToString(ed25519.Sign(key, body))}, nil
}

func verifyFieldReceipt(env fieldEnvelope, roots *x509.CertPool, peerName, expectedRun string, now time.Time) error {
	r := env.Receipt
	if r.SchemaVersion != schema || (r.Environment != "field_udp_bound" && r.Environment != "field_raw_ipv4") ||
		r.RunID != expectedRun || r.EgressStatus != "NOT_TESTED" ||
		r.CandidateAdmission != "NOT_TESTED" || r.ReturnToSender != "NOT_TESTED" ||
		r.PrivateL3 != "NOT_TESTED" {
		return errors.New("invalid or overclaiming field receipt")
	}
	digest, err := hex.DecodeString(r.ChallengeDigest)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("missing or invalid challenge digest")
	}
	if len(r.Observations) > fieldMaxSamples || r.ExpectedSamples < 1 ||
		r.ExpectedSamples > fieldMaxSamples || len(r.Observations) > r.ExpectedSamples {
		return errors.New("invalid field receipt sample count")
	}
	if peerName == "" || r.Observer != peerName {
		return errors.New("wrong field receipt observer")
	}
	when, err := time.Parse(time.RFC3339Nano, r.CreatedUTC)
	if err != nil || when.After(now.Add(60*time.Second)) || when.Before(now.Add(-24*time.Hour)) {
		return errors.New("receipt timestamp outside accepted interval")
	}
	block, extra := pem.Decode([]byte(env.ObserverCertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(extra) != 0 {
		return errors.New("invalid receipt signer certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, DNSName: peerName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("receipt signer verification: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("unexpected receipt signer public key")
	}
	sig, err := hex.DecodeString(env.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid receipt signature encoding")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("invalid or altered receipt signature")
	}
	seen := make(map[int]bool)
	for _, obs := range r.Observations {
		if obs.Index < 0 || obs.Index >= r.ExpectedSamples || seen[obs.Index] ||
			!obs.Authenticated || obs.PacketSize < fieldMinPacket || obs.PacketSize > fieldMaxPacket ||
			obs.PolicyEpoch == "" || !validDirection(obs.Direction) ||
			validateIP(obs.SourceCandidate, "field_candidates") != nil ||
			net.ParseIP(obs.ActualPacketSource).To4() == nil ||
			obs.SourceMatched != (obs.SourceCandidate == obs.ActualPacketSource) {
			return errors.New("invalid, duplicate or overclaiming observation")
		}
		seen[obs.Index] = true
	}
	return nil
}

func validateFieldSamples(samples []fieldSample, inventory CandidateFile, sender, receiver string) error {
	if inventory.Mode != "field_candidates" || len(samples) == 0 || len(samples) > fieldMaxSamples {
		return errors.New("invalid field candidate inventory or sample count")
	}
	dir, err := roleDirection(sender, receiver)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool, len(inventory.Candidates))
	for _, c := range inventory.Candidates {
		if c.Sender == sender && c.Receiver == receiver && c.Direction == dir {
			allowed[candidateIdentity(c)] = true
		}
	}
	for i, sample := range samples {
		if sample.Index != i || sample.Size < fieldMinPacket || sample.Size > fieldMaxPacket ||
			sample.Epoch == "" || len(sample.Epoch) > 96 {
			return errors.New("invalid signed field sample shape")
		}
		if !allowed[candidateIdentity(sample.Candidate)] {
			return errors.New("sample absent from local exact source allowlist")
		}
		if validateIP(sample.Candidate.IP, "field_candidates") != nil {
			return errors.New("invalid selected source IPv4")
		}
	}
	return nil
}

func certificateRoots(path string) (*x509.CertPool, error) {
	b, err := readSmallRegular(path, 16384)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA certificate")
	}
	return pool, nil
}

func saveNewJSON(path string, v any) error {
	if filepath.Ext(path) != ".json" {
		return errors.New("output must be a .json path")
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func roleName(role string) string {
	if role == "A" {
		return "spoofdiag-a.local"
	}
	if role == "B" {
		return "spoofdiag-b.local"
	}
	return ""
}
