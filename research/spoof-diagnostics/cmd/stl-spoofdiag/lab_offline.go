package main

import (
	"context"
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
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type offlineChallenge struct {
	SchemaVersion int         `json:"schema_version"`
	Environment   string      `json:"environment"`
	RunID         string      `json:"run_id"`
	Sender        string      `json:"sender"`
	Receiver      string      `json:"receiver"`
	DestinationIP string      `json:"destination_ip,omitempty"`
	CreatedUTC    string      `json:"created_utc"`
	ExpiresUnix   int64       `json:"expires_unix"`
	Samples       []labSample `json:"samples"`
}

type signedOfflineChallenge struct {
	Challenge            offlineChallenge `json:"challenge"`
	SenderCertificatePEM string           `json:"sender_certificate_pem"`
	SignatureHex         string           `json:"signature_hex"`
}

func offlineChallengeDigest(c offlineChallenge) string {
	b, _ := json.Marshal(c)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func signedChallengeFor(c offlineChallenge, cert tls.Certificate) (signedOfflineChallenge, error) {
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(cert.Certificate) == 0 {
		return signedOfflineChallenge{}, errors.New("lab challenge requires Ed25519 certificate and private key")
	}
	body, err := json.Marshal(c)
	if err != nil {
		return signedOfflineChallenge{}, err
	}
	return signedOfflineChallenge{Challenge: c,
		SenderCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})),
		SignatureHex:         hex.EncodeToString(ed25519.Sign(key, body)),
	}, nil
}

func challengeSignerCertificate(env signedOfflineChallenge, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	c := env.Challenge
	if c.SchemaVersion != schema || (c.Environment != "loopback_transport" && c.Environment != "isolated_private_raw") {
		return nil, errors.New("invalid offline challenge environment/schema")
	}
	if c.Environment == "isolated_private_raw" && validateIP(c.DestinationIP, "private_lab") != nil {
		return nil, errors.New("isolated private challenge requires exact RFC1918 destination")
	}
	if c.Environment == "loopback_transport" && c.DestinationIP != "" {
		return nil, errors.New("loopback challenge cannot contain a field destination")
	}
	if _, err := roleDirection(c.Sender, c.Receiver); err != nil {
		return nil, err
	}
	run, err := hex.DecodeString(c.RunID)
	if err != nil || len(run) != 16 {
		return nil, errors.New("invalid offline run ID")
	}
	created, err := time.Parse(time.RFC3339Nano, c.CreatedUTC)
	if err != nil || created.After(now.Add(2*time.Minute)) || created.Before(now.Add(-10*time.Minute)) {
		return nil, errors.New("challenge creation timestamp invalid")
	}
	expires := time.Unix(c.ExpiresUnix, 0)
	if !expires.After(now) || expires.After(created.Add(120*time.Second)) || expires.Before(created) {
		return nil, errors.New("challenge expired or outside finite 120s window")
	}
	if len(c.Samples) == 0 || len(c.Samples) > labMaxSamples {
		return nil, errors.New("invalid challenge sample count")
	}
	dir, _ := roleDirection(c.Sender, c.Receiver)
	for idx, s := range c.Samples {
		if s.Index != idx || s.Size < labMinPacket || s.Size > labMaxPacket || s.Candidate.Direction != dir ||
			s.Candidate.Sender != c.Sender || s.Candidate.Receiver != c.Receiver ||
			validateIP(s.Candidate.IP, "private_lab") != nil || s.Epoch == "" || len(s.Epoch) > 96 {
			return nil, errors.New("challenge contains invalid sample")
		}
	}
	block, rest := pem.Decode([]byte(env.SenderCertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, errors.New("invalid challenge signer PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, DNSName: roleName(c.Sender),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, fmt.Errorf("offline challenge signer verification: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("offline signer key must be Ed25519")
	}
	sig, err := hex.DecodeString(env.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid challenge signature")
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, body, sig) {
		return nil, errors.New("offline challenge signature mismatch")
	}
	return cert, nil
}

func readOfflineChallenge(path string) (signedOfflineChallenge, error) {
	var env signedOfflineChallenge
	data, err := readSmallRegular(path, labMaxControl)
	if err != nil {
		return env, err
	}
	if err := strictJSON(data, &env); err != nil {
		return env, err
	}
	return env, nil
}

func newOfflineChallenge(o labOptions) (signedOfflineChallenge, error) {
	var empty signedOfflineChallenge
	allowed, err := checkLabOptions(o, false)
	if err != nil {
		return empty, err
	}
	cert, err := loadLabCredential(o.Cert, o.Key)
	if err != nil {
		return empty, err
	}
	roots, err := certificateRoots(o.CA)
	if err != nil {
		return empty, err
	}
	// Creation must also prove certificate possession and trust before producing a plan.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return empty, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: roleName(o.Sender),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return empty, err
	}
	dir, _ := roleDirection(o.Sender, o.Receiver)
	samples := make([]labSample, 0, len(allowed.Candidates))
	for _, candidate := range allowed.Candidates {
		if candidate.Direction == dir && candidate.Sender == o.Sender && candidate.Receiver == o.Receiver {
			samples = append(samples, labSample{Index: len(samples), Candidate: candidate, Size: o.PacketSize, Epoch: o.Epoch})
			if len(samples) > labMaxSamples {
				return empty, errors.New("offline sample limit exceeded")
			}
		}
	}
	if len(samples) == 0 {
		return empty, errors.New("no candidate for offline direction")
	}
	run, err := randomHex(16)
	if err != nil {
		return empty, err
	}
	now := time.Now().UTC()
	transport := o.Transport
	if transport == "" {
		transport = "loopback_transport"
	}
	if transport != "loopback_transport" && transport != "isolated_private_raw" {
		return empty, errors.New("invalid offline challenge transport")
	}
	if transport == "isolated_private_raw" && validateIP(o.DestinationIP, "private_lab") != nil {
		return empty, errors.New("raw lab challenge needs exact --destination-ip RFC1918")
	}
	if transport == "loopback_transport" && o.DestinationIP != "" {
		return empty, errors.New("loopback challenge may not set destination-ip")
	}
	return signedChallengeFor(offlineChallenge{
		SchemaVersion: schema, Environment: transport, RunID: run,
		Sender: o.Sender, Receiver: o.Receiver, DestinationIP: o.DestinationIP, CreatedUTC: now.Format(time.RFC3339Nano),
		ExpiresUnix: now.Add(90 * time.Second).Unix(), Samples: samples,
	}, cert)
}

func makeOfflinePacket(plan offlineChallenge, sample labSample, key ed25519.PrivateKey) ([]byte, error) {
	run, err := hex.DecodeString(plan.RunID)
	if err != nil || len(run) != 16 {
		return nil, errors.New("invalid run ID")
	}
	if sample.Index < 0 || sample.Index > 65535 || sample.Size < 128 || sample.Size > labMaxPacket {
		return nil, errors.New("invalid signed UDP packet size/index")
	}
	ip, err := net.ParseIP(sample.Candidate.IP).MarshalText()
	if err != nil || len(ip) == 0 {
		return nil, errors.New("invalid source IP")
	}
	ipv4 := net.ParseIP(sample.Candidate.IP).To4()
	if ipv4 == nil {
		return nil, errors.New("invalid IPv4 source")
	}
	packet := make([]byte, sample.Size)
	copy(packet[:4], []byte("SDO1"))
	copy(packet[4:20], run)
	binary.BigEndian.PutUint16(packet[20:22], uint16(sample.Index))
	copy(packet[22:26], ipv4)
	if _, err := rand.Read(packet[26:38]); err != nil {
		return nil, err
	}
	copy(packet[len(packet)-64:], ed25519.Sign(key, packet[:len(packet)-64]))
	return packet, nil
}

func verifyOfflinePacket(packet []byte, plan offlineChallenge, pub ed25519.PublicKey, seen map[int]bool) (labSample, bool) {
	if len(packet) < 128 || len(packet) > labMaxPacket || string(packet[:4]) != "SDO1" {
		return labSample{}, false
	}
	run, err := hex.DecodeString(plan.RunID)
	if err != nil || len(run) != 16 || !hmac.Equal(packet[4:20], run) {
		return labSample{}, false
	}
	if !ed25519.Verify(pub, packet[:len(packet)-64], packet[len(packet)-64:]) {
		return labSample{}, false
	}
	idx := int(binary.BigEndian.Uint16(packet[20:22]))
	if idx < 0 || idx >= len(plan.Samples) || seen[idx] {
		return labSample{}, false
	}
	sample := plan.Samples[idx]
	addr := net.ParseIP(sample.Candidate.IP).To4()
	if addr == nil || sample.Index != idx || len(packet) != sample.Size || !hmac.Equal(addr, packet[22:26]) {
		return labSample{}, false
	}
	seen[idx] = true
	return sample, true
}

func offlineRunLedger(stateDir, run string) error {
	if stateDir == "" {
		return errors.New("private --state-dir required to reject reused challenges")
	}
	err := os.Mkdir(stateDir, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}
	st, err := os.Lstat(stateDir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("unsafe receiver state directory (must be private mode 0700 and no symlink)")
	}
	path := filepath.Join(stateDir, "consumed-"+run)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("duplicate/replayed or ambiguous challenge: %w", err)
	}
	if _, err := f.WriteString(time.Now().UTC().Format(time.RFC3339Nano) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func offlineListen(ctx context.Context, o labOptions, challengePath, stateDir string, window time.Duration, ready chan<- labReady) error {
	return offlineListenBound(ctx, o, challengePath, stateDir, window, ready, net.IPv4(127, 0, 0, 1), "", "loopback_transport")
}

func offlineListenBound(ctx context.Context, o labOptions, challengePath, stateDir string, window time.Duration, ready chan<- labReady, bindIP net.IP, iface, transport string) error {
	if transport == "isolated_private_raw" {
		if err := requireIsolatedPrivateNamespace(iface, bindIP.String()); err != nil {
			return err
		}
	} else if transport != "loopback_transport" || !bindIP.Equal(net.IPv4(127, 0, 0, 1)) {
		return errors.New("offline listen mode must be loopback or proven private lab namespace")
	}
	allowed, err := checkLabOptions(o, true)
	if err != nil {
		return err
	}
	env, err := readOfflineChallenge(challengePath)
	if err != nil {
		return err
	}
	roots, err := certificateRoots(o.CA)
	if err != nil {
		return err
	}
	signer, err := challengeSignerCertificate(env, roots, time.Now())
	if err != nil {
		return err
	}
	plan := env.Challenge
	if plan.Sender != o.Sender || plan.Receiver != o.Receiver || plan.Environment != transport || (transport == "isolated_private_raw" && plan.DestinationIP != bindIP.String()) {
		return errors.New("offline challenge role/transport/owned destination mismatch")
	}
	// Receiver must bind every sample to its own prior exact-IP allowlist.
	begin := labBegin{Type: "begin", SchemaVersion: schema, RunID: plan.RunID, Key: strings.Repeat("0", 64),
		ExpiresUnix: plan.ExpiresUnix, Samples: plan.Samples}
	if err := validateLabBegin(begin, allowed, o.Sender, o.Receiver, time.Now()); err != nil {
		return err
	}
	cert, err := loadLabCredential(o.Cert, o.Key)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: roleName(o.Receiver),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return err
	}
	if window < time.Second || window > 120*time.Second {
		return errors.New("offline listen window outside 1..120 seconds")
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP, Port: o.DataPort})
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := offlineRunLedger(stateDir, plan.RunID); err != nil {
		return err
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			udp.Close()
		case <-stopped:
		}
	}()
	defer close(stopped)
	port := udp.LocalAddr().(*net.UDPAddr).Port
	if ready != nil {
		select {
		case ready <- labReady{Type: "offline_ready", DataPort: port, Transport: transport}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	until := time.Now().Add(window)
	if exp := time.Unix(plan.ExpiresUnix, 0); exp.Before(until) {
		until = exp
	}
	seen := make(map[int]bool)
	observations := make([]labSeen, 0, len(plan.Samples))
	buf := make([]byte, labMaxPacket+1)
	pub := signer.PublicKey.(ed25519.PublicKey)
	for len(seen) < len(plan.Samples) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := udp.SetReadDeadline(until); err != nil {
			return err
		}
		n, addr, err := udp.ReadFromUDP(buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if addr == nil {
			continue
		}
		sample, ok := verifyOfflinePacket(buf[:n], plan, pub, seen)
		if !ok {
			continue
		}
		if (transport == "loopback_transport" && !addr.IP.Equal(net.IPv4(127, 0, 0, 1))) || (transport == "isolated_private_raw" && addr.IP.String() != sample.Candidate.IP) {
			delete(seen, sample.Index)
			continue
		}
		observations = append(observations, labSeen{
			Index: sample.Index, SourceCandidate: sample.Candidate.IP, ActualPacketSource: addr.IP.String(),
			PacketSize: sample.Size, Direction: sample.Candidate.Direction, PolicyEpoch: sample.Epoch, Authenticated: true,
		})
	}
	receipt := labReceipt{
		SchemaVersion: schema, Environment: transport, RunID: plan.RunID, Observer: roleName(o.Receiver), ChallengeDigest: offlineChallengeDigest(plan),
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano), ExpectedSamples: len(plan.Samples),
		Observations: observations, EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
	}
	out, err := signLabReceipt(receipt, cert)
	if err != nil {
		return err
	}
	if o.Output == "" {
		return errors.New("--out is required for offline receiver")
	}
	return saveNewJSON(o.Output, out)
}

func offlineSend(ctx context.Context, o labOptions, challengePath string) (string, error) {
	env, err := readOfflineChallenge(challengePath)
	if err != nil {
		return "", err
	}
	roots, err := certificateRoots(o.CA)
	if err != nil {
		return "", err
	}
	challengeCert, err := challengeSignerCertificate(env, roots, time.Now())
	if err != nil {
		return "", err
	}
	plan := env.Challenge
	if plan.Sender != o.Sender || plan.Receiver != o.Receiver || plan.Environment != "loopback_transport" {
		return "", errors.New("loopback offline send requires matching loopback-only challenge")
	}
	if o.DataPort <= 0 || o.DataPort > 65535 {
		return "", errors.New("explicit --data-port required")
	}
	cert, err := loadLabCredential(o.Cert, o.Key)
	if err != nil {
		return "", err
	}
	own, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", err
	}
	if !own.Equal(challengeCert) {
		return "", errors.New("sender private key does not match signed challenge")
	}
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("sender must use Ed25519")
	}
	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: o.DataPort})
	if err != nil {
		return "", err
	}
	defer udp.Close()
	for _, sample := range plan.Samples {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		p, err := makeOfflinePacket(plan, sample, key)
		if err != nil {
			return "", err
		}
		if _, err := udp.Write(p); err != nil {
			return "", err
		}
		time.Sleep(40 * time.Millisecond)
	}
	return plan.RunID, nil
}

func verifyOfflinePair(challengePath, receiptPath, caPath string) (map[string]any, error) {
	env, err := readOfflineChallenge(challengePath)
	if err != nil {
		return nil, err
	}
	roots, err := certificateRoots(caPath)
	if err != nil {
		return nil, err
	}
	plan := env.Challenge
	if _, err := challengeSignerCertificate(env, roots, time.Now()); err != nil {
		return nil, err
	}
	b, err := readSmallRegular(receiptPath, labMaxControl)
	if err != nil {
		return nil, err
	}
	var response labEnvelope
	if err := strictJSON(b, &response); err != nil {
		return nil, err
	}
	if err := verifyLabReceipt(response, roots, roleName(plan.Receiver), plan.RunID, time.Now()); err != nil {
		return nil, err
	}
	if response.Receipt.ExpectedSamples != len(plan.Samples) || response.Receipt.ChallengeDigest != offlineChallengeDigest(plan) || response.Receipt.Environment != plan.Environment {
		return nil, errors.New("receipt challenge binding mismatch")
	}
	for _, observed := range response.Receipt.Observations {
		s := plan.Samples[observed.Index]
		if s.Candidate.IP != observed.SourceCandidate || s.Size != observed.PacketSize ||
			s.Candidate.Direction != observed.Direction || s.Epoch != observed.PolicyEpoch {
			return nil, errors.New("receipt observation does not match signed challenge")
		}
	}
	return map[string]any{
		"challenge_signature": "VERIFIED", "receipt_signature": "VERIFIED", "control_channel": "NOT_USED",
		"run_id": plan.RunID, "sender": roleName(plan.Sender), "peer": roleName(plan.Receiver),
		"expected_samples": len(plan.Samples), "authenticated_peer_observations": len(response.Receipt.Observations),
		"result":                     labEvidenceResult(len(response.Receipt.Observations), len(plan.Samples), plan.Environment),
		"candidate_source_admission": "NOT_TESTED", "sender_egress": "NOT_TESTED",
		"return_to_sender": "NOT_TESTED", "private_l3": "NOT_TESTED",
	}, nil
}

func offlineCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lab challenge|offline-listen|offline-send|offline-verify")
	}
	op := args[0]
	f := flag.NewFlagSet("lab "+op, flag.ContinueOnError)
	if op == "offline-verify" {
		challenge := f.String("challenge", "", "signed challenge JSON")
		receipt := f.String("receipt", "", "peer signed observations JSON")
		ca := f.String("ca", "", "trusted lab CA PEM")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *challenge == "" || *receipt == "" || *ca == "" {
			return errors.New("--challenge --receipt --ca required")
		}
		v, err := verifyOfflinePair(*challenge, *receipt, *ca)
		if err != nil {
			return err
		}
		return pretty(v)
	}
	o := labOptions{}
	f.StringVar(&o.File, "file", "", "private lab allowlist source JSON/CSV")
	f.StringVar(&o.Cert, "cert", "", "local node certificate")
	f.StringVar(&o.Key, "key", "", "local node private key")
	f.StringVar(&o.CA, "ca", "", "trusted CA")
	f.StringVar(&o.Sender, "sender", "A", "sender role")
	f.StringVar(&o.Receiver, "receiver", "B", "receiver role")
	f.IntVar(&o.DataPort, "data-port", 24002, "127.0.0.1 UDP port")
	f.IntVar(&o.PacketSize, "packet-size", 192, "signed packet size 128..1200")
	f.StringVar(&o.Epoch, "epoch", "local-offline", "declared policy epoch")
	f.StringVar(&o.Transport, "transport", "loopback_transport", "signed challenge type: loopback_transport or isolated_private_raw (NO network on challenge)")
	f.StringVar(&o.DestinationIP, "destination-ip", "", "exact RFC1918 receiver IP for isolated_private_raw challenge")
	f.StringVar(&o.Output, "out", "", "new output JSON file")
	challenge := f.String("challenge", "", "existing signed challenge JSON")
	state := f.String("state-dir", "", "receiver-only private replay-ledger directory")
	window := f.Int("window-seconds", 10, "bounded receiver window")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch op {
	case "challenge":
		if o.Output == "" {
			return errors.New("--out required")
		}
		if o.PacketSize < 128 {
			return errors.New("signed offline packet must be >=128 bytes")
		}
		e, err := newOfflineChallenge(o)
		if err != nil {
			return err
		}
		if err := saveNewJSON(o.Output, e); err != nil {
			return err
		}
		return pretty(map[string]any{"run_id": e.Challenge.RunID, "challenge": o.Output, "samples": len(e.Challenge.Samples), "signature": "ED25519_SIGNED", "transport": "NOT_RUN", "secret_keys_in_export": false})
	case "offline-send":
		if *challenge == "" {
			return errors.New("--challenge required")
		}
		run, err := offlineSend(ctx, o, *challenge)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"run_id": run, "status": "SUBMITTED_ONLY", "peer_observed": "NOT_TESTED", "candidate_admission": "NOT_TESTED", "private_l3": "NOT_TESTED"})
	case "offline-listen":
		if *challenge == "" || o.Output == "" || *state == "" {
			return errors.New("--challenge --out --state-dir required")
		}
		ready := make(chan labReady, 1)
		done := make(chan error, 1)
		go func() { done <- offlineListen(ctx, o, *challenge, *state, time.Duration(*window)*time.Second, ready) }()
		select {
		case r := <-ready:
			if err := pretty(r); err != nil {
				return err
			}
			err := <-done
			if err != nil {
				return err
			}
			return pretty(map[string]any{"status": "RECEIPT_WRITTEN", "path": o.Output, "note": "Peer evidence must be independently verified against the signed challenge"})
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	default:
		return errors.New("unknown offline lab subcommand")
	}
}
