package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	labMinPacket  = 96
	labMaxPacket  = 1200
	labMaxSamples = 128
	labMaxControl = 64 << 10
	labMagic      = "SDG1"
)

type labSample struct {
	Index     int       `json:"index"`
	Candidate Candidate `json:"candidate"`
	Size      int       `json:"packet_size"`
	Epoch     string    `json:"policy_epoch"`
}

type labBegin struct {
	Type          string      `json:"type"`
	SchemaVersion int         `json:"schema_version"`
	RunID         string      `json:"run_id"`
	Key           string      `json:"session_key"`
	ExpiresUnix   int64       `json:"expires_unix"`
	Samples       []labSample `json:"samples"`
}

type labSeen struct {
	Index              int    `json:"index"`
	SourceCandidate    string `json:"source_candidate"`
	ActualPacketSource string `json:"actual_packet_source"`
	PacketSize         int    `json:"packet_size"`
	Direction          string `json:"direction"`
	PolicyEpoch        string `json:"policy_epoch"`
	Authenticated      bool   `json:"authenticated"`
}

type labReceipt struct {
	SchemaVersion      int       `json:"schema_version"`
	Environment        string    `json:"environment"`
	RunID              string    `json:"run_id"`
	Observer           string    `json:"observer"`
	CreatedUTC         string    `json:"created_utc"`
	ExpectedSamples    int       `json:"expected_samples"`
	ChallengeDigest    string    `json:"challenge_digest,omitempty"`
	Observations       []labSeen `json:"observations"`
	EgressStatus       string    `json:"egress_status"`
	CandidateAdmission string    `json:"candidate_admission"`
	ReturnToSender     string    `json:"return_to_sender"`
	PrivateL3          string    `json:"private_l3"`
}

type labEnvelope struct {
	Receipt                labReceipt `json:"receipt"`
	ObserverCertificatePEM string     `json:"observer_certificate_pem"`
	SignatureHex           string     `json:"signature_hex"`
}

func strictJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > labMaxControl {
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

func labEvidenceResult(observed, expected int) string {
	if observed == 0 {
		return "INCONCLUSIVE"
	}
	if observed < expected {
		return "PARTIAL"
	}
	return "AUTHENTICATED_LOOPBACK_PEER_OBSERVED"
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func makeLabPacket(start labBegin, sample labSample) ([]byte, error) {
	key, err := hex.DecodeString(start.Key)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid session key")
	}
	run, err := hex.DecodeString(start.RunID)
	if err != nil || len(run) != 16 {
		return nil, errors.New("invalid run identifier")
	}
	src, err := netip.ParseAddr(sample.Candidate.IP)
	if err != nil || !src.Is4() || !src.IsPrivate() {
		return nil, errors.New("source must be RFC1918")
	}
	if sample.Index < 0 || sample.Index > 65535 || sample.Size < labMinPacket || sample.Size > labMaxPacket {
		return nil, errors.New("invalid sample size or index")
	}
	packet := make([]byte, sample.Size)
	copy(packet[0:4], labMagic)
	copy(packet[4:20], run)
	binary.BigEndian.PutUint16(packet[20:22], uint16(sample.Index))
	a := src.As4()
	copy(packet[22:26], a[:])
	if _, err := rand.Read(packet[26:38]); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(packet[:len(packet)-32])
	copy(packet[len(packet)-32:], mac.Sum(nil))
	return packet, nil
}

func verifyLabPacket(packet []byte, start labBegin, seen map[int]bool) (labSample, bool) {
	if len(packet) < labMinPacket || len(packet) > labMaxPacket || string(packet[0:4]) != labMagic {
		return labSample{}, false
	}
	key, err := hex.DecodeString(start.Key)
	if err != nil || len(key) != 32 {
		return labSample{}, false
	}
	run, err := hex.DecodeString(start.RunID)
	if err != nil || len(run) != 16 || !hmac.Equal(packet[4:20], run) {
		return labSample{}, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(packet[:len(packet)-32])
	if !hmac.Equal(mac.Sum(nil), packet[len(packet)-32:]) {
		return labSample{}, false
	}
	idx := int(binary.BigEndian.Uint16(packet[20:22]))
	if idx >= len(start.Samples) || seen[idx] {
		return labSample{}, false
	}
	sample := start.Samples[idx]
	if sample.Index != idx || len(packet) != sample.Size {
		return labSample{}, false
	}
	ip, err := netip.ParseAddr(sample.Candidate.IP)
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		return labSample{}, false
	}
	a := ip.As4()
	if !hmac.Equal(packet[22:26], a[:]) {
		return labSample{}, false
	}
	seen[idx] = true
	return sample, true
}

func validateLabBegin(begin labBegin, allowed CandidateFile, sender, receiver string, now time.Time) error {
	if begin.Type != "begin" || begin.SchemaVersion != schema {
		return errors.New("invalid begin schema/type")
	}
	run, err := hex.DecodeString(begin.RunID)
	if err != nil || len(run) != 16 {
		return errors.New("invalid run identifier")
	}
	key, err := hex.DecodeString(begin.Key)
	if err != nil || len(key) != 32 {
		return errors.New("invalid session key")
	}
	if begin.ExpiresUnix <= now.Unix() || begin.ExpiresUnix > now.Add(120*time.Second).Unix() {
		return errors.New("expired or excessively long session")
	}
	if allowed.Mode != "private_lab" || len(begin.Samples) == 0 || len(begin.Samples) > labMaxSamples {
		return errors.New("invalid lab sample count/mode")
	}
	dir, err := roleDirection(sender, receiver)
	if err != nil {
		return err
	}
	permitted := make(map[string]bool, len(allowed.Candidates))
	for _, c := range allowed.Candidates {
		if c.Sender == sender && c.Receiver == receiver && c.Direction == dir {
			permitted[c.IP] = true
		}
	}
	for i, s := range begin.Samples {
		if s.Index != i || s.Size < labMinPacket || s.Size > labMaxPacket {
			return errors.New("invalid sample index/size")
		}
		if len(s.Epoch) == 0 || len(s.Epoch) > 96 {
			return errors.New("invalid policy epoch")
		}
		c := s.Candidate
		if c.Sender != sender || c.Receiver != receiver || c.Direction != dir || !permitted[c.IP] {
			return errors.New("sample not on receiver's explicit allowlist")
		}
	}
	return nil
}

func roleDirection(sender, receiver string) (string, error) {
	switch {
	case sender == "A" && receiver == "B":
		return "A_TO_B", nil
	case sender == "B" && receiver == "A":
		return "B_TO_A", nil
	default:
		return "", errors.New("lab requires distinct A/B node roles")
	}
}

func signLabReceipt(receipt labReceipt, cert tls.Certificate) (labEnvelope, error) {
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return labEnvelope{}, errors.New("lab signing requires Ed25519 leaf key")
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return labEnvelope{}, err
	}
	if len(cert.Certificate) == 0 {
		return labEnvelope{}, errors.New("missing signer certificate")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	return labEnvelope{Receipt: receipt, ObserverCertificatePEM: string(pemBytes), SignatureHex: hex.EncodeToString(ed25519.Sign(key, body))}, nil
}

func verifyLabReceipt(env labEnvelope, roots *x509.CertPool, peerName, expectedRun string, now time.Time) error {
	r := env.Receipt
	if r.SchemaVersion != schema || r.Environment != "loopback_transport" || r.RunID != expectedRun ||
		r.EgressStatus != "NOT_TESTED" || r.CandidateAdmission != "NOT_TESTED" ||
		r.ReturnToSender != "NOT_TESTED" || r.PrivateL3 != "NOT_TESTED" {
		return errors.New("invalid or overclaiming receipt")
	}
	if r.ChallengeDigest != "" {
		if digest, err := hex.DecodeString(r.ChallengeDigest); err != nil || len(digest) != sha256.Size {
			return errors.New("invalid challenge digest")
		}
	}
	if len(r.Observations) > labMaxSamples || r.ExpectedSamples < 1 || r.ExpectedSamples > labMaxSamples || len(r.Observations) > r.ExpectedSamples {
		return errors.New("invalid receipt sample count")
	}
	if peerName == "" || r.Observer != peerName {
		return errors.New("wrong receipt observer")
	}
	when, err := time.Parse(time.RFC3339Nano, r.CreatedUTC)
	if err != nil || when.After(now.Add(2*time.Minute)) || when.Before(now.Add(-2*time.Hour)) {
		return errors.New("receipt timestamp outside accepted window")
	}
	block, extra := pem.Decode([]byte(env.ObserverCertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(extra) != 0 {
		return errors.New("invalid signer certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, DNSName: peerName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return fmt.Errorf("signer certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("unexpected signer key type")
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
		return errors.New("tampered receipt signature")
	}
	seen := map[int]bool{}
	for _, s := range r.Observations {
		if s.Index < 0 || s.Index >= r.ExpectedSamples || seen[s.Index] || !s.Authenticated || s.ActualPacketSource != "127.0.0.1" ||
			s.PacketSize < labMinPacket || s.PacketSize > labMaxPacket ||
			s.PolicyEpoch == "" || !validDirection(s.Direction) || validateIP(s.SourceCandidate, "private_lab") != nil {
			return errors.New("invalid or duplicate observation")
		}
		seen[s.Index] = true
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
