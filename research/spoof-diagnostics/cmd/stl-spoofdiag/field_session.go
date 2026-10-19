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
	"net"
	"os"
	"path/filepath"
	"time"
)

// Every challenge binds the exact destination, port, packet count, source
// candidates and peer roles. It does not assert provider source-prefix rights.
type fieldChallenge struct {
	SchemaVersion    int           `json:"schema_version"`
	Environment      string        `json:"environment"`
	RunID            string        `json:"run_id"`
	Sender           string        `json:"sender"`
	Receiver         string        `json:"receiver"`
	DestinationIP    string        `json:"destination_ip"`
	DataPort         int           `json:"data_port"`
	CreatedUTC       string        `json:"created_utc"`
	ExpiresUnix      int64         `json:"expires_unix"`
	SamplesPerSource int           `json:"samples_per_source,omitempty"` // absent in historical plans means 1
	Samples          []fieldSample `json:"samples"`
}

type signedFieldChallenge struct {
	Challenge            fieldChallenge `json:"challenge"`
	SenderCertificatePEM string         `json:"sender_certificate_pem"`
	SignatureHex         string         `json:"signature_hex"`
}

// The independent receiver must explicitly approve the precise signed plan
// before a sender can transmit. A receiver grant is consent by this configured
// cryptographic peer; it is not permission from the network provider.
type fieldGrant struct {
	SchemaVersion   int    `json:"schema_version"`
	RunID           string `json:"run_id"`
	ChallengeDigest string `json:"challenge_digest"`
	Receiver        string `json:"receiver"`
	DestinationIP   string `json:"destination_ip"`
	DataPort        int    `json:"data_port"`
	BindIP          string `json:"receiver_bind_ip,omitempty"`
	CreatedUTC      string `json:"created_utc"`
	ExpiresUnix     int64  `json:"expires_unix"`
}

type signedFieldGrant struct {
	Grant                  fieldGrant `json:"grant"`
	ReceiverCertificatePEM string     `json:"receiver_certificate_pem"`
	SignatureHex           string     `json:"signature_hex"`
}

func fieldChallengeDigest(c fieldChallenge) string {
	b, _ := json.Marshal(c)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func fieldTransportName(name string) bool {
	return name == "field_udp_bound" || name == "field_raw_ipv4"
}

func parseFieldCertificate(pemString string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifyFieldLeaf(cert *x509.Certificate, roots *x509.CertPool, role string, now time.Time, usage x509.ExtKeyUsage) error {
	if roleName(role) == "" {
		return errors.New("unknown field node role")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: roleName(role), CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{usage},
	}); err != nil {
		return fmt.Errorf("untrusted field identity for %s: %w", role, err)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return errors.New("field signing requires Ed25519 public key")
	}
	return nil
}

func signatureFromCredential(payload any, credential tls.Certificate) (string, string, error) {
	private, ok := credential.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(credential.Certificate) == 0 {
		return "", "", errors.New("signed field artifact requires an Ed25519 certificate and private key")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: credential.Certificate[0]})),
		hex.EncodeToString(ed25519.Sign(private, data)), nil
}

func verifyFieldSignature(payload any, pemData, signature string, roots *x509.CertPool,
	role string, now time.Time, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	leaf, err := parseFieldCertificate(pemData)
	if err != nil {
		return nil, err
	}
	if err := verifyFieldLeaf(leaf, roots, role, now, usage); err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature encoding")
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(leaf.PublicKey.(ed25519.PublicKey), payloadBytes, sig) {
		return nil, errors.New("signed field artifact has invalid signature")
	}
	return leaf, nil
}

func validateFieldChallenge(c fieldChallenge, now time.Time, live bool) error {
	if c.SchemaVersion != schema || !fieldTransportName(c.Environment) {
		return errors.New("unknown signed field challenge schema/environment")
	}
	if _, err := roleDirection(c.Sender, c.Receiver); err != nil {
		return err
	}
	run, err := hex.DecodeString(c.RunID)
	if err != nil || len(run) != 16 {
		return errors.New("invalid field run ID")
	}
	if err := validateIP(c.DestinationIP, "field_candidates"); err != nil {
		return fmt.Errorf("invalid exact receiver destination: %w", err)
	}
	if c.DataPort < 1024 || c.DataPort > 65535 {
		return errors.New("destination UDP port must be 1024..65535")
	}
	created, err := time.Parse(time.RFC3339Nano, c.CreatedUTC)
	if err != nil || created.After(now.Add(60*time.Second)) {
		return errors.New("invalid field challenge creation time")
	}
	expires := time.Unix(c.ExpiresUnix, 0)
	if !expires.After(created) || expires.After(created.Add(15*time.Minute)) {
		return errors.New("field challenge validity exceeds maximum 15 minutes")
	}
	if live && (created.Before(now.Add(-15*time.Minute-60*time.Second)) || !expires.After(now)) {
		return errors.New("field challenge is expired or excessively old")
	}
	if len(c.Samples) < 1 || len(c.Samples) > fieldMaxSamples {
		return errors.New("invalid signed field sample count")
	}
	repeats := c.SamplesPerSource
	if repeats == 0 {
		repeats = 1 // safely verify signed plans from before repetitions existed
	}
	if repeats < 1 || repeats > fieldMaxPacketsPerSource {
		return errors.New("invalid signed samples-per-source setting")
	}
	direction, _ := roleDirection(c.Sender, c.Receiver)
	checked := make(map[string]int)
	for i, sample := range c.Samples {
		if sample.Index != i || sample.Size < fieldMinPacket || sample.Size > fieldMaxPacket ||
			sample.Epoch == "" || len(sample.Epoch) > 96 ||
			sample.Candidate.Sender != c.Sender || sample.Candidate.Receiver != c.Receiver ||
			sample.Candidate.Direction != direction ||
			validateIP(sample.Candidate.IP, "field_candidates") != nil {
			return errors.New("signed field challenge contains malformed source sample")
		}
		id := candidateIdentity(sample.Candidate)
		checked[id]++
		if checked[id] > repeats || len(checked) > fieldMaxSelectedSources {
			return errors.New("duplicate or excessive source sample in signed challenge")
		}
	}
	if len(c.Samples) != len(checked)*repeats {
		return errors.New("incomplete per-source repetitions in signed challenge")
	}
	return nil
}

func checkSignedFieldChallenge(env signedFieldChallenge, roots *x509.CertPool, now time.Time, live bool) (*x509.Certificate, error) {
	if err := validateFieldChallenge(env.Challenge, now, live); err != nil {
		return nil, err
	}
	return verifyFieldSignature(env.Challenge, env.SenderCertificatePEM, env.SignatureHex,
		roots, env.Challenge.Sender, now, x509.ExtKeyUsageClientAuth)
}

func readSignedFieldChallenge(path string) (signedFieldChallenge, error) {
	var obj signedFieldChallenge
	data, err := readSmallRegular(path, fieldMaxControl)
	if err != nil {
		return obj, err
	}
	return obj, strictJSON(data, &obj)
}

func readSignedFieldGrant(path string) (signedFieldGrant, error) {
	var obj signedFieldGrant
	data, err := readSmallRegular(path, fieldMaxControl)
	if err != nil {
		return obj, err
	}
	return obj, strictJSON(data, &obj)
}

func checkLocalFieldCredential(certPath, keyPath, caPath, role string, usage x509.ExtKeyUsage) (tls.Certificate, *x509.CertPool, error) {
	var zero tls.Certificate
	cert, err := loadFieldCredential(certPath, keyPath)
	if err != nil {
		return zero, nil, err
	}
	if len(cert.Certificate) == 0 {
		return zero, nil, errors.New("missing node leaf certificate")
	}
	roots, err := certificateRoots(caPath)
	if err != nil {
		return zero, nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return zero, nil, err
	}
	if err := verifyFieldLeaf(leaf, roots, role, time.Now(), usage); err != nil {
		return zero, nil, err
	}
	return cert, roots, nil
}

func newFieldChallenge(o fieldOptions) (signedFieldChallenge, error) {
	var zero signedFieldChallenge
	if _, err := roleDirection(o.Sender, o.Receiver); err != nil {
		return zero, err
	}
	if !fieldTransportName(o.Transport) {
		return zero, errors.New("invalid field transport")
	}
	if err := validateIP(o.DestinationIP, "field_candidates"); err != nil {
		return zero, err
	}
	if o.DataPort < 1024 || o.DataPort > 65535 {
		return zero, errors.New("invalid field destination port")
	}
	if o.PacketSize < fieldMinPacket || o.PacketSize > fieldMaxPacket ||
		o.Epoch == "" || len(o.Epoch) > 96 {
		return zero, errors.New("invalid packet size (128..1200) or policy epoch")
	}
	if o.TTLSeconds < 60 || o.TTLSeconds > 900 {
		return zero, errors.New("field challenge TTL must be 60..900 seconds")
	}
	repeats := o.SamplesPerSource
	if repeats == 0 {
		repeats = 1 // preserve in-process callers predating this option
	}
	if repeats < 1 || repeats > fieldMaxPacketsPerSource {
		return zero, fmt.Errorf("samples per source must be 1..%d", fieldMaxPacketsPerSource)
	}
	inventory, err := readCandidates(o.File)
	if err != nil {
		return zero, err
	}
	direction, _ := roleDirection(o.Sender, o.Receiver)
	selected := make([]Candidate, 0)
	for _, c := range inventory.Candidates {
		if c.Sender == o.Sender && c.Receiver == o.Receiver && c.Direction == direction {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 || len(selected) > fieldMaxSelectedSources {
		return zero, fmt.Errorf("a signed run needs 1..%d selected sources; batch a larger inventory into separate authorized runs", fieldMaxSelectedSources)
	}
	// Interleave rounds so repeated observations cover more of the test window
	// rather than one short burst per source. Each index has a fresh nonce.
	samples := make([]fieldSample, 0, len(selected)*repeats)
	for round := 0; round < repeats; round++ {
		for _, c := range selected {
			samples = append(samples, fieldSample{Index: len(samples), Candidate: c, Size: o.PacketSize, Epoch: o.Epoch})
		}
	}
	if err := validateFieldSamples(samples, inventory, o.Sender, o.Receiver); err != nil {
		return zero, err
	}
	cert, _, err := checkLocalFieldCredential(o.Cert, o.Key, o.CA, o.Sender, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return zero, err
	}
	run, err := randomHex(16)
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	challenge := fieldChallenge{SchemaVersion: schema, Environment: o.Transport, RunID: run,
		Sender: o.Sender, Receiver: o.Receiver, DestinationIP: o.DestinationIP, DataPort: o.DataPort,
		CreatedUTC: now.Format(time.RFC3339Nano), ExpiresUnix: now.Add(time.Duration(o.TTLSeconds) * time.Second).Unix(),
		SamplesPerSource: repeats, Samples: samples}
	signerPEM, sig, err := signatureFromCredential(challenge, cert)
	if err != nil {
		return zero, err
	}
	return signedFieldChallenge{Challenge: challenge, SenderCertificatePEM: signerPEM, SignatureHex: sig}, nil
}

func newFieldGrant(o fieldOptions) (signedFieldGrant, error) {
	return newFieldGrantWithDestinationOwnership(o, localAssignedIPv4)
}

// The injected ownership checker exists for pure future unit tests; the CLI
// always calls newFieldGrant with the actual OS-assigned address checker.
func newFieldGrantWithDestinationOwnership(o fieldOptions, isLocalDestination func(string) error) (signedFieldGrant, error) {
	var zero signedFieldGrant
	env, err := readSignedFieldChallenge(o.Challenge)
	if err != nil {
		return zero, err
	}
	c := env.Challenge
	if c.Sender != o.Sender || c.Receiver != o.Receiver {
		return zero, errors.New("grant roles do not match signed plan")
	}
	cert, roots, err := checkLocalFieldCredential(o.Cert, o.Key, o.CA, c.Receiver, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return zero, err
	}
	if _, err = checkSignedFieldChallenge(env, roots, time.Now(), true); err != nil {
		return zero, err
	}
	// A receiver signs the exact public/advertised destination, and may
	// separately consent to an explicitly configured local DNAT bind. This
	// does NOT configure, detect or assert that any NAT forwarding works.
	if isLocalDestination == nil {
		return zero, errors.New("receiver local-interface checker required")
	}
	bindIP := o.BindIP
	if bindIP == "" {
		bindIP = c.DestinationIP
	}
	if bindIP != c.DestinationIP && !o.ForwardedDestination {
		return zero, errors.New("forwarded destination requires explicit receiver --allow-forwarded-destination")
	}
	if err := validateIP(bindIP, "field_candidates"); err != nil {
		return zero, err
	}
	if err := isLocalDestination(bindIP); err != nil {
		return zero, fmt.Errorf("receiver bind IP is not locally assigned: %w", err)
	}
	allowed, err := readCandidates(o.File)
	if err != nil {
		return zero, err
	}
	if err = validateFieldSamples(c.Samples, allowed, c.Sender, c.Receiver); err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	grant := fieldGrant{SchemaVersion: schema, RunID: c.RunID, ChallengeDigest: fieldChallengeDigest(c),
		Receiver: c.Receiver, DestinationIP: c.DestinationIP, DataPort: c.DataPort,
		BindIP: bindIP, CreatedUTC: now.Format(time.RFC3339Nano),
		ExpiresUnix: c.ExpiresUnix}
	pemData, signature, err := signatureFromCredential(grant, cert)
	if err != nil {
		return zero, err
	}
	return signedFieldGrant{Grant: grant, ReceiverCertificatePEM: pemData, SignatureHex: signature}, nil
}

func checkFieldGrant(env signedFieldGrant, c fieldChallenge, roots *x509.CertPool, now time.Time, live bool) error {
	g := env.Grant
	if g.SchemaVersion != schema || g.RunID != c.RunID ||
		g.ChallengeDigest != fieldChallengeDigest(c) || g.Receiver != c.Receiver ||
		g.DestinationIP != c.DestinationIP || g.DataPort != c.DataPort ||
		g.ExpiresUnix != c.ExpiresUnix {
		return errors.New("field grant is not bound to exact signed challenge")
	}
	if g.BindIP != "" {
		if err := validateIP(g.BindIP, "field_candidates"); err != nil {
			return fmt.Errorf("invalid receiver bound address: %w", err)
		}
	}
	created, err := time.Parse(time.RFC3339Nano, g.CreatedUTC)
	if err != nil || created.After(now.Add(60*time.Second)) ||
		created.Before(time.Unix(c.ExpiresUnix, 0).Add(-15*time.Minute-60*time.Second)) ||
		created.After(time.Unix(c.ExpiresUnix, 0)) {
		return errors.New("invalid grant creation time")
	}
	if live && !time.Unix(g.ExpiresUnix, 0).After(now) {
		return errors.New("receiver grant has expired")
	}
	_, err = verifyFieldSignature(g, env.ReceiverCertificatePEM, env.SignatureHex, roots, c.Receiver, now, x509.ExtKeyUsageServerAuth)
	return err
}

// Every signed sample has its own index and random nonce. A bounded set of
// independent samples is emitted for each exact operator-selected IPv4.
func makeFieldPacket(c fieldChallenge, sample fieldSample, key ed25519.PrivateKey) ([]byte, error) {
	run, err := hex.DecodeString(c.RunID)
	if err != nil || len(run) != 16 || sample.Index < 0 || sample.Index > 65535 ||
		sample.Size < fieldMinPacket || sample.Size > fieldMaxPacket {
		return nil, errors.New("invalid field sample")
	}
	address := net.ParseIP(sample.Candidate.IP).To4()
	if address == nil {
		return nil, errors.New("invalid sample IPv4")
	}
	buf := make([]byte, sample.Size)
	copy(buf[:4], []byte("SDF2"))
	copy(buf[4:20], run)
	binary.BigEndian.PutUint16(buf[20:22], uint16(sample.Index))
	copy(buf[22:26], address)
	if _, err := rand.Read(buf[26:38]); err != nil {
		return nil, err
	}
	copy(buf[len(buf)-ed25519.SignatureSize:], ed25519.Sign(key, buf[:len(buf)-ed25519.SignatureSize]))
	return buf, nil
}

func verifyFieldPacket(packet []byte, c fieldChallenge, pub ed25519.PublicKey, seen map[int]bool) (fieldSample, bool) {
	if len(packet) < fieldMinPacket || len(packet) > fieldMaxPacket || string(packet[:4]) != "SDF2" {
		return fieldSample{}, false
	}
	run, err := hex.DecodeString(c.RunID)
	if err != nil || len(run) != 16 || !hmac.Equal(packet[4:20], run) ||
		!ed25519.Verify(pub, packet[:len(packet)-ed25519.SignatureSize], packet[len(packet)-ed25519.SignatureSize:]) {
		return fieldSample{}, false
	}
	idx := int(binary.BigEndian.Uint16(packet[20:22]))
	if idx >= len(c.Samples) || seen[idx] {
		return fieldSample{}, false
	}
	sample := c.Samples[idx]
	ip := net.ParseIP(sample.Candidate.IP).To4()
	if sample.Index != idx || len(packet) != sample.Size || ip == nil || !hmac.Equal(packet[22:26], ip) {
		return fieldSample{}, false
	}
	seen[idx] = true
	return sample, true
}

func fieldRunLedger(stateDir, run string) error {
	if stateDir == "" {
		return errors.New("private --state-dir is required")
	}
	if err := os.Mkdir(stateDir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	st, err := os.Lstat(stateDir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("unsafe field receiver ledger directory (0700, non-symlink required)")
	}
	file := filepath.Join(stateDir, "consumed-"+run)
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("duplicate or replayed signed run: %w", err)
	}
	if _, err := f.WriteString(time.Now().UTC().Format(time.RFC3339Nano) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Archived verification is signature/consistency evidence, not independent
// network, provider, clock or physical egress proof.
func verifyFieldPair(challengePath, grantPath, receiptPath, caPath string) (map[string]any, error) {
	env, err := readSignedFieldChallenge(challengePath)
	if err != nil {
		return nil, err
	}
	grant, err := readSignedFieldGrant(grantPath)
	if err != nil {
		return nil, err
	}
	data, err := readSmallRegular(receiptPath, fieldMaxControl)
	if err != nil {
		return nil, err
	}
	var signed fieldEnvelope
	if err := strictJSON(data, &signed); err != nil {
		return nil, err
	}
	c := env.Challenge
	receiptTime, err := time.Parse(time.RFC3339Nano, signed.Receipt.CreatedUTC)
	if err != nil {
		return nil, err
	}
	created, err := time.Parse(time.RFC3339Nano, c.CreatedUTC)
	if err != nil {
		return nil, err
	}
	expiry := time.Unix(c.ExpiresUnix, 0)
	if receiptTime.Before(created.Add(-60*time.Second)) || receiptTime.After(expiry.Add(60*time.Second)) ||
		receiptTime.After(time.Now().Add(60*time.Second)) {
		return nil, errors.New("receipt time not consistent with finite signed challenge")
	}
	roots, err := certificateRoots(caPath)
	if err != nil {
		return nil, err
	}
	if _, err = checkSignedFieldChallenge(env, roots, receiptTime, false); err != nil {
		return nil, err
	}
	if err = checkFieldGrant(grant, c, roots, receiptTime, false); err != nil {
		return nil, err
	}
	if err = verifyFieldReceipt(signed, roots, roleName(c.Receiver), c.RunID, receiptTime); err != nil {
		return nil, err
	}
	receipt := signed.Receipt
	if receipt.Environment != c.Environment || receipt.ChallengeDigest != fieldChallengeDigest(c) ||
		receipt.ExpectedSamples != len(c.Samples) {
		return nil, errors.New("field receipt challenge binding mismatch")
	}
	matched := 0
	for _, obs := range receipt.Observations {
		sample := c.Samples[obs.Index]
		if obs.SourceCandidate != sample.Candidate.IP || obs.PacketSize != sample.Size ||
			obs.Direction != sample.Candidate.Direction || obs.PolicyEpoch != sample.Epoch {
			return nil, errors.New("signed observation does not match exact sample")
		}
		if obs.SourceMatched {
			matched++
		}
	}
	perSource := summarizeFieldSourceObservations(c.Samples, receipt.Observations)
	return map[string]any{
		"run_id": c.RunID, "direction": c.Samples[0].Candidate.Direction,
		"sender": roleName(c.Sender), "receiver": roleName(c.Receiver),
		"challenge_signature": "VERIFIED", "receiver_grant_signature": "VERIFIED",
		"receipt_signature": "VERIFIED", "expected_samples": len(c.Samples),
		"samples_per_source":    effectiveFieldRepeats(c.SamplesPerSource),
		"selected_source_count": len(perSource), "per_source": perSource,
		"peer_authenticated_received": len(receipt.Observations),
		"source_matched_at_peer":      matched, "source_mismatched_or_rewritten": len(receipt.Observations) - matched,
		"receiver_status":        receipt.Status,
		"receiver_bind_ip":       grant.Grant.BindIP,
		"submitted_at_sender":    "NOT_INDEPENDENTLY_VERIFIED",
		"sender_physical_egress": "NOT_TESTED", "provider_source_acceptance": "NOT_INDEPENDENTLY_VERIFIED",
		"return_to_sender": "NOT_TESTED", "private_l3": "NOT_TESTED",
		"evidence_scope": "SIGNED_RECEIVER_DECLARATION_NOT_PROVIDER_OR_RETURN_PROOF",
	}, nil
}
