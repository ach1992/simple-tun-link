package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type fieldOptions struct {
	File, Cert, Key, CA                                               string
	Sender, Receiver                                                  string
	DestinationIP, BindIP                                             string
	Transport, Interface                                              string
	DataPort, PacketSize, TTLSeconds, WindowSeconds, SamplesPerSource int
	Epoch, Output, Challenge, Grant, StateDir, ReadyOutput, ReadyFile string
	ProviderAuthorized, ForwardedDestination                          bool
}

// The source IP used by the ordinary UDP transport must actually be assigned
// to the sender's interfaces. It is NOT a way to forge public source IPs.
func localAssignedIPv4(candidate string) error {
	ip := net.ParseIP(candidate).To4()
	if ip == nil {
		return errors.New("invalid local IPv4 candidate")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var assigned net.IP
			switch item := addr.(type) {
			case *net.IPNet:
				assigned = item.IP
			case *net.IPAddr:
				assigned = item.IP
			}
			if assigned != nil && assigned.To4() != nil && assigned.To4().Equal(ip) {
				return nil
			}
		}
	}
	return fmt.Errorf("SOURCE_NOT_ASSIGNED: %s is not an IPv4 assigned to an active non-loopback interface; normal UDP cannot spoof it", candidate)
}

func readPreparedField(o fieldOptions) (signedFieldChallenge, signedFieldGrant, *x509.CertPool, error) {
	var emptyC signedFieldChallenge
	var emptyG signedFieldGrant
	c, err := readSignedFieldChallenge(o.Challenge)
	if err != nil {
		return emptyC, emptyG, nil, err
	}
	roots, err := certificateRoots(o.CA)
	if err != nil {
		return emptyC, emptyG, nil, err
	}
	if _, err = checkSignedFieldChallenge(c, roots, time.Now(), true); err != nil {
		return emptyC, emptyG, nil, err
	}
	g, err := readSignedFieldGrant(o.Grant)
	if err != nil {
		return emptyC, emptyG, nil, err
	}
	if err = checkFieldGrant(g, c.Challenge, roots, time.Now(), true); err != nil {
		return emptyC, emptyG, nil, err
	}
	if c.Challenge.Sender != o.Sender || c.Challenge.Receiver != o.Receiver {
		return emptyC, emptyG, nil, errors.New("field sender/receiver roles mismatch signed plan")
	}
	if c.Challenge.DestinationIP != o.DestinationIP || c.Challenge.DataPort != o.DataPort {
		return emptyC, emptyG, nil, errors.New("destination and UDP port must match signed receiver grant exactly")
	}
	return c, g, roots, nil
}

// The receiver's automatic window includes the full 5 packets/second signed
// plan duration, plus a 45-second grant-transfer/startup margin. It never extends beyond 120 seconds.
// A short default can expire during secure, manually coordinated A/B grant transfer.
func automaticFieldWindowSeconds(plannedSamples int) int {
	window := 45 + (plannedSamples+4)/5
	if window > 120 {
		return 120
	}
	return window
}

func fieldListen(ctx context.Context, o fieldOptions, ready chan<- map[string]any) error {
	if o.Challenge == "" || o.Grant == "" || o.Output == "" || o.StateDir == "" {
		return errors.New("field listen requires --challenge --grant --out --state-dir")
	}
	if o.WindowSeconds < 0 || o.WindowSeconds > 120 {
		return errors.New("receiver window must be auto (0) or 1..120 seconds")
	}
	if o.BindIP == "" {
		return errors.New("receiver must specify a locally assigned --bind-ip")
	}
	if err := validateIP(o.BindIP, "field_candidates"); err != nil {
		return err
	}
	if err := localAssignedIPv4(o.BindIP); err != nil {
		return err
	}
	c, g, roots, err := readPreparedField(o)
	if err != nil {
		return err
	}
	expectedBind := g.Grant.BindIP
	if expectedBind == "" {
		expectedBind = c.Challenge.DestinationIP // historical direct-address grant
	}
	if o.BindIP != expectedBind || (o.BindIP != o.DestinationIP && !o.ForwardedDestination) {
		return errors.New("listener bind IP differs from signed receiver grant or forwarded-destination consent")
	}
	windowSeconds := o.WindowSeconds
	recommended := automaticFieldWindowSeconds(len(c.Challenge.Samples))
	if windowSeconds == 0 {
		windowSeconds = recommended
	}
	if windowSeconds < recommended || time.Until(time.Unix(c.Challenge.ExpiresUnix, 0)) < time.Duration(recommended+5)*time.Second {
		return errors.New("receiver window/challenge TTL too short for bounded signed run; create a fresh challenge")
	}
	if _, err := fieldPreflight(o, "receiver"); err != nil {
		return fmt.Errorf("receiver prerequisites: %w", err)
	}
	allowed, err := receiverSourceSelection(c.Challenge, o.File)
	if err != nil {
		return err
	}
	if err = validateFieldSamples(c.Challenge.Samples, allowed, o.Sender, o.Receiver); err != nil {
		return err
	}
	cert, _, err := checkLocalFieldCredential(o.Cert, o.Key, o.CA, o.Receiver, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return err
	}
	grantLeaf, err := parseFieldCertificate(g.ReceiverCertificatePEM)
	if err != nil {
		return err
	}
	localLeaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if !localLeaf.Equal(grantLeaf) {
		return errors.New("receiver private key/certificate differs from signed approval grant")
	}
	senderLeaf, err := checkSignedFieldChallenge(c, roots, time.Now(), true)
	if err != nil {
		return err
	}
	senderPub := senderLeaf.PublicKey.(ed25519.PublicKey)
	if fi, err := os.Lstat(o.Output); err == nil {
		return fmt.Errorf("refusing to overwrite existing receipt output %q: %s", o.Output, fi.Name())
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(o.BindIP), Port: o.DataPort})
	if err != nil {
		return err
	}
	defer listener.Close()
	// Publish a signed zero-observation IN_PROGRESS receipt before consuming
	// the replay ledger. After this point every verified observation is
	// durably snapshotted; an abrupt stop can never erase earlier evidence.
	receipt := fieldReceipt{
		SchemaVersion: schema, Environment: c.Challenge.Environment, RunID: c.Challenge.RunID,
		Observer: roleName(o.Receiver), ChallengeDigest: fieldChallengeDigest(c.Challenge),
		ExpectedSamples: len(c.Challenge.Samples), Observations: []fieldSeen{},
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED",
		ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED", Status: "IN_PROGRESS",
	}
	snapshot := func(replace bool) error {
		receipt.CreatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		signed, signErr := signFieldReceipt(receipt, cert)
		if signErr != nil {
			return signErr
		}
		return writeStagedJSON(o.Output, signed, replace)
	}
	if err := snapshot(false); err != nil {
		return err
	}
	if err = fieldRunLedger(o.StateDir, c.Challenge.RunID); err != nil {
		_ = os.Remove(o.Output) // only the newly created, unconsumed receipt
		return err
	}
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-closed:
		}
	}()
	defer close(closed)
	expiry := time.Unix(c.Challenge.ExpiresUnix, 0)
	minimumRecommended := automaticFieldWindowSeconds(len(c.Challenge.Samples))
	windowMayTruncate := windowSeconds < minimumRecommended ||
		time.Until(expiry) < time.Duration(minimumRecommended)*time.Second
	deadline := time.Now().Add(time.Duration(windowSeconds) * time.Second)
	if expiry.Before(deadline) {
		deadline = expiry
	}
	if o.ReadyOutput != "" {
		signedReady, err := newSignedFieldReady(c.Challenge, g.Grant, o.BindIP, deadline, cert)
		if err != nil {
			return err
		}
		if err := saveNewJSON(o.ReadyOutput, signedReady); err != nil {
			return fmt.Errorf("receiver cannot publish signed readiness after binding: %w", err)
		}
	}
	if ready != nil {
		select {
		case ready <- map[string]any{"status": "FIELD_RECEIVER_READY_UNVALIDATED", "bind_ip": o.BindIP,
			"port": o.DataPort, "run_id": c.Challenge.RunID, "transport": c.Challenge.Environment,
			"planned_samples": len(c.Challenge.Samples), "receiver_window_seconds": windowSeconds,
			"window_may_end_before_all_samples": windowMayTruncate}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	seen := make(map[int]bool)
	buf := make([]byte, fieldMaxPacket+1)
	for len(seen) < len(c.Challenge.Samples) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := listener.SetReadDeadline(deadline); err != nil {
			return err
		}
		n, peer, err := listener.ReadFromUDP(buf)
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if peer == nil || peer.IP.To4() == nil {
			continue
		}
		sample, okay := verifyFieldPacket(buf[:n], c.Challenge, senderPub, seen)
		if !okay {
			continue
		}
		// NAT/proxy/source filtering may change the observed on-wire address:
		// preserve BOTH values, never convert signed identity into source proof.
		actual := peer.IP.To4().String()
		receipt.Observations = append(receipt.Observations, fieldSeen{
			Index: sample.Index, SourceCandidate: sample.Candidate.IP, ActualPacketSource: actual,
			SourceMatched: actual == sample.Candidate.IP, PacketSize: sample.Size,
			Direction: sample.Candidate.Direction, PolicyEpoch: sample.Epoch, Authenticated: true,
			ReceivedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		})
		if err := snapshot(true); err != nil {
			return fmt.Errorf("receiver evidence persistence failed (run consumed): %w", err)
		}
	}
	// COMPLETE means the finite receiver observation window ended, not that
	// every planned datagram was sent, received or admitted by a provider.
	receipt.Status = "COMPLETE"
	return snapshot(true)
}

func fieldSend(ctx context.Context, o fieldOptions) (map[string]any, error) {
	if o.Challenge == "" || o.Grant == "" || o.File == "" || o.DestinationIP == "" || o.Output == "" {
		return nil, errors.New("field send requires signed artifacts, inventory, destination and a new --out JSON")
	}
	c, grant, _, err := readPreparedField(o)
	if err != nil {
		return nil, err
	}
	if o.ReadyFile != "" {
		if _, err := verifySignedFieldReady(o.ReadyFile, c.Challenge, grant, o.CA, time.Now()); err != nil {
			return nil, fmt.Errorf("receiver readiness not authenticated/current: %w", err)
		}
	}
	selected, err := readCandidates(o.File)
	if err != nil {
		return nil, err
	}
	if err := validateFieldSamples(c.Challenge.Samples, selected, o.Sender, o.Receiver); err != nil {
		return nil, err
	}
	cert, _, err := checkLocalFieldCredential(o.Cert, o.Key, o.CA, o.Sender, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	localLeaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	senderLeaf, err := parseFieldCertificate(c.SenderCertificatePEM)
	if err != nil {
		return nil, err
	}
	if !localLeaf.Equal(senderLeaf) {
		return nil, errors.New("sender private key/certificate does not match signed challenge")
	}
	if c.Challenge.Environment == "field_raw_ipv4" && (!o.ProviderAuthorized || strings.TrimSpace(o.Interface) == "") {
		return nil, errors.New("BLOCKED_BY_PERMISSION: raw forged-source send needs independently verified Owner/provider permission, --provider-authorized and --interface")
	}
	destination := net.ParseIP(c.Challenge.DestinationIP).To4()
	if destination == nil {
		return nil, errors.New("invalid signed destination")
	}
	if _, err := fieldPreflight(o, "sender"); err != nil {
		return nil, fmt.Errorf("sender prerequisites: %w", err)
	}
	if c.Challenge.Environment == "field_udp_bound" {
		for _, sample := range c.Challenge.Samples {
			if err := localAssignedIPv4(sample.Candidate.IP); err != nil {
				return nil, err
			}
		}
	}
	var raw *rawFieldSocket
	if c.Challenge.Environment == "field_raw_ipv4" {
		raw, err = openRawFieldSocket(o.Interface)
		if err != nil {
			return nil, err
		}
		defer raw.Close()
	}
	ev := newSenderEvidence(c.Challenge)
	if err := signedSenderSnapshot(o.Output, ev, cert, false); err != nil {
		return nil, err
	}
	submit := func(sample fieldSample, payload []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if raw != nil {
			return raw.Send(sample.Candidate.IP, c.Challenge.DestinationIP, c.Challenge.DataPort, payload)
		}
		local := &net.UDPAddr{IP: net.ParseIP(sample.Candidate.IP), Port: 0}
		remote := &net.UDPAddr{IP: destination, Port: c.Challenge.DataPort}
		conn, err := net.DialUDP("udp4", local, remote)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		_, err = conn.Write(payload)
		return err
	}
	pace := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return nil
		}
	}
	sent, sendErr := submitFieldRun(c.Challenge, &ev, cert, o.Output, submit, pace)
	result := map[string]any{
		"run_id": c.Challenge.RunID, "status": ev.Status,
		"signed_sender_evidence":   o.Output,
		"transport":                c.Challenge.Environment,
		"selected_candidate_count": len(c.Challenge.Samples) / effectiveFieldRepeats(c.Challenge.SamplesPerSource),
		"samples_per_source":       effectiveFieldRepeats(c.Challenge.SamplesPerSource),
		"planned_samples":          len(c.Challenge.Samples),
		"send_syscalls_succeeded":  sent,
		"peer_ingress":             "NOT_TESTED", "physical_egress": "NOT_TESTED",
		"provider_source_acceptance": "NOT_TESTED", "return_to_sender": "NOT_TESTED",
		"private_l3": "NOT_TESTED",
	}
	if sendErr != nil {
		result["error"] = sendErr.Error()
	}
	return result, sendErr
}
