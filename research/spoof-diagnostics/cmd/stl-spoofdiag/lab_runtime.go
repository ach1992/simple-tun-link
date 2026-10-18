package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type labOptions struct {
	File, Cert, Key, CA      string
	Transport, DestinationIP string
	Sender, Receiver         string
	ControlPort, DataPort    int
	PacketSize               int
	Epoch, Output            string
}

type labReady struct {
	Type        string `json:"type"`
	ControlPort int    `json:"control_port"`
	DataPort    int    `json:"data_port"`
	Transport   string `json:"transport"`
}

type labControl struct {
	Type     string `json:"type"`
	DataPort int    `json:"data_port,omitempty"`
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

func checkLabOptions(o labOptions, server bool) (CandidateFile, error) {
	var zero CandidateFile
	if _, err := roleDirection(o.Sender, o.Receiver); err != nil {
		return zero, err
	}
	for _, port := range []int{o.ControlPort, o.DataPort} {
		if port < 0 || port > 65535 {
			return zero, errors.New("invalid local port")
		}
	}
	if o.ControlPort != 0 && o.ControlPort == o.DataPort {
		return zero, errors.New("control and data ports must differ")
	}
	if o.File == "" || o.Cert == "" || o.Key == "" || o.CA == "" {
		return zero, errors.New("--file, --cert, --key, --ca required")
	}
	candidates, err := readCandidates(o.File)
	if err != nil {
		return zero, err
	}
	if candidates.Mode != "private_lab" {
		return zero, errors.New("lab only permits private_lab file")
	}
	if !server && (o.PacketSize < labMinPacket || o.PacketSize > labMaxPacket) {
		return zero, errors.New("packet-size must be 96..1200")
	}
	if !server && (o.Epoch == "" || len(o.Epoch) > 96) {
		return zero, errors.New("policy epoch must be nonempty, <=96 bytes")
	}
	return candidates, nil
}

func serveLab(ctx context.Context, o labOptions, ready chan<- labReady) error {
	allowed, err := checkLabOptions(o, true)
	if err != nil {
		return err
	}
	cert, err := loadLabCredential(o.Cert, o.Key)
	if err != nil {
		return err
	}
	roots, err := certificateRoots(o.CA)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: o.DataPort})
	if err != nil {
		return err
	}
	defer udp.Close()
	listen, err := tls.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.ControlPort)), serverLabTLS(cert, roots, roleName(o.Sender)))
	if err != nil {
		return err
	}
	defer listen.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listen.Close()
			udp.Close()
		case <-done:
		}
	}()
	defer close(done)
	controlPort := listen.Addr().(*net.TCPAddr).Port
	dataPort := udp.LocalAddr().(*net.UDPAddr).Port
	r := labReady{Type: "ready", ControlPort: controlPort, DataPort: dataPort, Transport: "LOOPBACK_ONLY_NO_SOURCE_SPOOF"}
	if ready != nil {
		select {
		case ready <- r:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	conn, err := listen.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("expected TLS connection")
	}
	if err := tconn.HandshakeContext(ctx); err != nil {
		return err
	}
	if err := checkPeerName(tconn.ConnectionState(), roleName(o.Sender)); err != nil {
		return err
	}
	dec := json.NewDecoder(io.LimitReader(conn, labMaxControl))
	dec.DisallowUnknownFields()
	var begin labBegin
	if err := dec.Decode(&begin); err != nil {
		return err
	}
	if err := validateLabBegin(begin, allowed, o.Sender, o.Receiver, time.Now()); err != nil {
		return err
	}
	if err := json.NewEncoder(conn).Encode(labControl{Type: "start", DataPort: dataPort}); err != nil {
		return err
	}
	seen := make(map[int]bool)
	observations := make([]labSeen, 0, len(begin.Samples))
	buf := make([]byte, labMaxPacket+1)
	window := time.Duration(len(begin.Samples))*150*time.Millisecond + 2*time.Second
	if window > 25*time.Second {
		window = 25 * time.Second
	}
	until := time.Now().Add(window)
	for len(seen) < len(begin.Samples) {
		deadline := until
		if expiry := time.Unix(begin.ExpiresUnix, 0); expiry.Before(deadline) {
			deadline = expiry
		}
		if err := udp.SetReadDeadline(deadline); err != nil {
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
		// A loopback transport measurement NEVER verifies a claimed RFC1918 source.
		if addr == nil || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			continue
		}
		sample, ok := verifyLabPacket(buf[:n], begin, seen)
		if !ok {
			continue
		}
		observations = append(observations, labSeen{
			Index: sample.Index, SourceCandidate: sample.Candidate.IP, ActualPacketSource: addr.IP.String(),
			PacketSize: sample.Size, Direction: sample.Candidate.Direction, PolicyEpoch: sample.Epoch,
			Authenticated: true,
		})
	}
	receipt := labReceipt{
		SchemaVersion: schema, Environment: "loopback_transport", RunID: begin.RunID,
		Observer: roleName(o.Receiver), CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: len(begin.Samples), Observations: observations, EgressStatus: "NOT_TESTED",
		CandidateAdmission: "NOT_TESTED", ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
	}
	env, err := signLabReceipt(receipt, cert)
	if err != nil {
		return err
	}
	return json.NewEncoder(conn).Encode(env)
}

func runLab(ctx context.Context, o labOptions) (labEnvelope, error) {
	var empty labEnvelope
	allowed, err := checkLabOptions(o, false)
	if err != nil {
		return empty, err
	}
	samples := make([]labSample, 0, len(allowed.Candidates))
	dir, _ := roleDirection(o.Sender, o.Receiver)
	for _, c := range allowed.Candidates {
		if c.Sender != o.Sender || c.Receiver != o.Receiver || c.Direction != dir {
			continue
		}
		samples = append(samples, labSample{Index: len(samples), Candidate: c, Size: o.PacketSize, Epoch: o.Epoch})
		if len(samples) > labMaxSamples {
			return empty, errors.New("too many samples in one bounded lab run")
		}
	}
	if len(samples) == 0 {
		return empty, errors.New("no explicitly allowed candidates for direction")
	}
	cert, err := loadLabCredential(o.Cert, o.Key)
	if err != nil {
		return empty, err
	}
	roots, err := certificateRoots(o.CA)
	if err != nil {
		return empty, err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return empty, err
	}
	key, err := randomHex(32)
	if err != nil {
		return empty, err
	}
	begin := labBegin{Type: "begin", SchemaVersion: schema, RunID: nonce, Key: key, ExpiresUnix: time.Now().Add(60 * time.Second).Unix(), Samples: samples}
	dial := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dial, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.ControlPort)), clientLabTLS(cert, roots, roleName(o.Receiver)))
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return empty, err
	}
	if err := json.NewEncoder(conn).Encode(begin); err != nil {
		return empty, err
	}
	dec := json.NewDecoder(io.LimitReader(conn, labMaxControl))
	dec.DisallowUnknownFields()
	var start labControl
	if err := dec.Decode(&start); err != nil {
		return empty, fmt.Errorf("server did not start approved lab session: %w", err)
	}
	if start.Type != "start" || start.DataPort < 1 || start.DataPort > 65535 {
		return empty, errors.New("invalid lab start acknowledgement")
	}
	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: start.DataPort})
	if err != nil {
		return empty, err
	}
	for _, s := range samples {
		if ctx.Err() != nil {
			udp.Close()
			return empty, ctx.Err()
		}
		pkt, err := makeLabPacket(begin, s)
		if err != nil {
			udp.Close()
			return empty, err
		}
		if _, err := udp.Write(pkt); err != nil {
			udp.Close()
			return empty, err
		}
		time.Sleep(40 * time.Millisecond)
	}
	udp.Close()
	var env labEnvelope
	if err := dec.Decode(&env); err != nil {
		return empty, fmt.Errorf("missing signed peer receipt: %w", err)
	}
	if err := verifyLabReceipt(env, roots, roleName(o.Receiver), nonce, time.Now()); err != nil {
		return empty, err
	}
	for _, obs := range env.Receipt.Observations {
		s := samples[obs.Index]
		if obs.SourceCandidate != s.Candidate.IP || obs.Direction != s.Candidate.Direction || obs.PacketSize != s.Size || obs.PolicyEpoch != s.Epoch {
			return empty, errors.New("signed observation does not match session plan")
		}
	}
	if o.Output != "" {
		if err := saveNewJSON(o.Output, env); err != nil {
			return empty, err
		}
	}
	return env, nil
}

func labCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lab identity|serve|run|verify (LOOPBACK-ONLY)")
	}
	op := args[0]
	if op == "netns-send" || op == "netns-listen" {
		return rawPrivateCLI(args)
	}
	if op == "challenge" || op == "offline-listen" || op == "offline-send" || op == "offline-verify" {
		return offlineCLI(args)
	}
	f := flag.NewFlagSet("lab "+op, flag.ContinueOnError)
	if op == "identity" {
		dir := f.String("dir", "", "new directory for DISPOSABLE local lab identities (sensitive)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" {
			return errors.New("--dir is required")
		}
		if err := createLabIdentity(*dir); err != nil {
			return err
		}
		return pretty(map[string]any{"identity_dir": *dir, "CA": "DISPOSABLE_LAB_ONLY", "note": "DO NOT copy ca.key or both node private keys to a field server"})
	}
	if op == "verify" {
		file := f.String("file", "", "signed receipt JSON")
		ca := f.String("ca", "", "trusted CA certificate")
		peer := f.String("peer", "", "expected signer DNS identity (spoofdiag-a.local or spoofdiag-b.local)")
		run := f.String("run", "", "expected run ID from operator's independent record")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *file == "" || *ca == "" || *peer == "" || *run == "" {
			return errors.New("--file --ca --peer --run required")
		}
		data, err := readSmallRegular(*file, 256<<10)
		if err != nil {
			return err
		}
		var env labEnvelope
		if err := strictJSON(data, &env); err != nil {
			return err
		}
		roots, err := certificateRoots(*ca)
		if err != nil {
			return err
		}
		if err := verifyLabReceipt(env, roots, *peer, *run, time.Now()); err != nil {
			return err
		}
		return pretty(map[string]any{"receipt_signature": "VERIFIED", "signer": *peer, "run_id": *run, "verified_peer_samples": len(env.Receipt.Observations), "candidate_source_admission": "NOT_TESTED", "private_l3": "NOT_TESTED"})
	}
	if op != "serve" && op != "run" {
		return errors.New("unknown lab command")
	}
	o := labOptions{}
	f.StringVar(&o.File, "file", "", "private candidate JSON/CSV manifest (receiver allowlist)")
	f.StringVar(&o.Cert, "cert", "", "node certificate PEM")
	f.StringVar(&o.Key, "key", "", "node private key PEM")
	f.StringVar(&o.CA, "ca", "", "trusted CA PEM")
	f.StringVar(&o.Sender, "sender", "A", "sender role A or B")
	f.StringVar(&o.Receiver, "receiver", "B", "receiver role A or B")
	f.IntVar(&o.ControlPort, "control-port", 24001, "local TLS port (127.0.0.1 only)")
	f.IntVar(&o.DataPort, "data-port", 24002, "local UDP port (127.0.0.1 only)")
	f.IntVar(&o.PacketSize, "packet-size", 192, "UDP diagnostic payload in bytes")
	f.StringVar(&o.Epoch, "epoch", "local-loopback", "operator-declared local policy epoch")
	f.StringVar(&o.Output, "out", "", "write a new signed JSON receipt")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if op == "serve" {
		ready := make(chan labReady, 1)
		result := make(chan error, 1)
		go func() { result <- serveLab(ctx, o, ready) }()
		select {
		case r := <-ready:
			if err := pretty(r); err != nil {
				return err
			}
			return <-result
		case err := <-result:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if o.ControlPort == 0 {
		return errors.New("run requires explicit nonzero control port")
	}
	env, err := runLab(ctx, o)
	if err != nil {
		return err
	}
	return pretty(map[string]any{
		"run_id":              env.Receipt.RunID,
		"peer_signed_receipt": "VERIFIED", "peer_observer": env.Receipt.Observer,
		"expected_samples": env.Receipt.ExpectedSamples, "peer_observed": len(env.Receipt.Observations),
		"result":                     labEvidenceResult(len(env.Receipt.Observations), env.Receipt.ExpectedSamples, env.Receipt.Environment),
		"transport":                  "127.0.0.1 mTLS-control + authenticated UDP",
		"source_candidate_admission": "NOT_TESTED", "sender_egress": "NOT_TESTED",
		"return_to_sender": "NOT_TESTED", "private_l3": "NOT_TESTED",
		"receipt_export": o.Output,
	})
}
