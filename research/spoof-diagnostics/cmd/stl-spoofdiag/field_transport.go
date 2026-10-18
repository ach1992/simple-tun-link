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
	File, Cert, Key, CA                             string
	Sender, Receiver                                string
	DestinationIP, BindIP                           string
	Transport, Interface                            string
	DataPort, PacketSize, TTLSeconds, WindowSeconds int
	Epoch, Output, Challenge, Grant, StateDir       string
	ProviderAuthorized                              bool
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

func fieldListen(ctx context.Context, o fieldOptions, ready chan<- map[string]any) error {
	if o.Challenge == "" || o.Grant == "" || o.File == "" || o.Output == "" || o.StateDir == "" {
		return errors.New("field listen requires --challenge --grant --file --out --state-dir")
	}
	if o.WindowSeconds < 1 || o.WindowSeconds > 120 {
		return errors.New("receiver window must be 1..120 seconds")
	}
	if o.BindIP == "" || o.BindIP != o.DestinationIP {
		return errors.New("receiver must bind the exact signed destination IPv4")
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
	allowed, err := readCandidates(o.File)
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
	if err = fieldRunLedger(o.StateDir, c.Challenge.RunID); err != nil {
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
	if ready != nil {
		select {
		case ready <- map[string]any{"status": "FIELD_RECEIVER_READY_UNVALIDATED", "bind_ip": o.BindIP,
			"port": o.DataPort, "run_id": c.Challenge.RunID, "transport": c.Challenge.Environment}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	deadline := time.Now().Add(time.Duration(o.WindowSeconds) * time.Second)
	expiry := time.Unix(c.Challenge.ExpiresUnix, 0)
	if expiry.Before(deadline) {
		deadline = expiry
	}
	seen := make(map[int]bool)
	observed := make([]fieldSeen, 0, len(c.Challenge.Samples))
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
		observed = append(observed, fieldSeen{
			Index: sample.Index, SourceCandidate: sample.Candidate.IP, ActualPacketSource: actual,
			SourceMatched: actual == sample.Candidate.IP, PacketSize: sample.Size,
			Direction: sample.Candidate.Direction, PolicyEpoch: sample.Epoch, Authenticated: true,
		})
	}
	receipt := fieldReceipt{
		SchemaVersion: schema, Environment: c.Challenge.Environment, RunID: c.Challenge.RunID,
		Observer: roleName(o.Receiver), ChallengeDigest: fieldChallengeDigest(c.Challenge),
		CreatedUTC:      time.Now().UTC().Format(time.RFC3339Nano),
		ExpectedSamples: len(c.Challenge.Samples), Observations: observed,
		EgressStatus: "NOT_TESTED", CandidateAdmission: "NOT_TESTED", ReturnToSender: "NOT_TESTED", PrivateL3: "NOT_TESTED",
	}
	signed, err := signFieldReceipt(receipt, cert)
	if err != nil {
		return err
	}
	return saveNewJSON(o.Output, signed)
}

func fieldSend(ctx context.Context, o fieldOptions) (map[string]any, error) {
	if o.Challenge == "" || o.Grant == "" || o.File == "" || o.DestinationIP == "" {
		return nil, errors.New("field send requires --challenge --grant --file --destination-ip")
	}
	c, g, _, err := readPreparedField(o)
	if err != nil {
		return nil, err
	}
	selected, err := readCandidates(o.File)
	if err != nil {
		return nil, err
	}
	if err = validateFieldSamples(c.Challenge.Samples, selected, o.Sender, o.Receiver); err != nil {
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
	_ = g // Grant signature and binding have already been checked in readPreparedField.
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("sender must hold matching Ed25519 key")
	}
	if c.Challenge.Environment == "field_raw_ipv4" && (!o.ProviderAuthorized || strings.TrimSpace(o.Interface) == "") {
		return nil, errors.New("BLOCKED_BY_PERMISSION: raw forged-source field send needs explicit verified owner/provider permission, --provider-authorized and --interface; the flag itself is not independent authorization")
	}
	destination := net.ParseIP(c.Challenge.DestinationIP).To4()
	if destination == nil {
		return nil, errors.New("invalid signed field destination")
	}
	// Preflight every selected ordinary UDP source before sending the first
	// packet: a later invalid source must not cause partial unanticipated sends.
	if c.Challenge.Environment == "field_udp_bound" {
		for _, sample := range c.Challenge.Samples {
			if err := localAssignedIPv4(sample.Candidate.IP); err != nil {
				return nil, err
			}
		}
	}
	sent := 0
	var raw *rawFieldSocket
	if c.Challenge.Environment == "field_raw_ipv4" {
		raw, err = openRawFieldSocket(o.Interface)
		if err != nil {
			return nil, err
		}
		defer raw.Close()
	}
	for _, sample := range c.Challenge.Samples {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !time.Unix(c.Challenge.ExpiresUnix, 0).After(time.Now()) {
			return nil, errors.New("signed field challenge expired during bounded sender run")
		}
		payload, err := makeFieldPacket(c.Challenge, sample, key)
		if err != nil {
			return nil, err
		}
		if raw != nil {
			err = raw.Send(sample.Candidate.IP, c.Challenge.DestinationIP, c.Challenge.DataPort, payload)
		} else {
			// Standard UDP can select ONLY locally assigned IPv4 addresses.
			// Each sample obtains a separately bound socket.
			local := &net.UDPAddr{IP: net.ParseIP(sample.Candidate.IP), Port: 0}
			remote := &net.UDPAddr{IP: destination, Port: c.Challenge.DataPort}
			var conn *net.UDPConn
			conn, err = net.DialUDP("udp4", local, remote)
			if err == nil {
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, err = conn.Write(payload)
				conn.Close()
			}
		}
		if err != nil {
			return nil, fmt.Errorf("bounded send sample %d: %w", sample.Index, err)
		}
		sent++
		// 5 or fewer diagnostic datagrams per second, never a flood or scan.
		if idx := sample.Index; idx+1 < len(c.Challenge.Samples) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return map[string]any{
		"run_id": c.Challenge.RunID, "status": "SUBMITTED_ONLY",
		"transport": c.Challenge.Environment, "selected_candidate_count": len(c.Challenge.Samples),
		"send_syscalls_succeeded": sent, "peer_ingress": "NOT_TESTED",
		"provider_source_acceptance": "NOT_TESTED", "physical_egress": "NOT_TESTED",
		"return_to_sender": "NOT_TESTED", "private_l3": "NOT_TESTED",
	}, nil
}
