package main

// Offline-first UDP observation for disconnected A/B research. The receiver
// deliberately has no sender source list, Challenge, Grant or Ready dependency.
// Incoming SDF2-looking datagrams are UNVERIFIED until a signed sender plan
// and its public trust root are manually provided to the offline correlator.
// This does not send packets, claim peer permission or establish a return path.

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	passiveCaptureFormat    = "sdx-passive-v1"
	passiveMaxPackets       = 2048
	passiveMaxWindowSeconds = 4 * 60 * 60
	passiveMaxFile          = 8 << 20
)

type passivePacket struct {
	Sequence           int    `json:"sequence"`
	ReceivedUTC        string `json:"received_utc"`
	ActualPacketSource string `json:"actual_packet_source"`
	PacketBase64       string `json:"packet_base64"`
}

type passiveCapture struct {
	Format        string          `json:"format"`
	CaptureID     string          `json:"capture_id"`
	Observer      string          `json:"observer"`
	BindIP        string          `json:"bind_ip"`
	DataPort      int             `json:"data_port"`
	WindowSeconds int             `json:"window_seconds"`
	PacketLimit   int             `json:"packet_limit"`
	StartedUTC    string          `json:"started_utc"`
	UpdatedUTC    string          `json:"updated_utc"`
	Status        string          `json:"status"`
	StopReason    string          `json:"stop_reason,omitempty"`
	Observations  []passivePacket `json:"observations"`
}

type signedPassiveCapture struct {
	Capture                passiveCapture `json:"capture"`
	ObserverCertificatePEM string         `json:"observer_certificate_pem"`
	SignatureHex           string         `json:"signature_hex"`
}

func newPassiveCapture(observer, bind string, port, window, limit int) (passiveCapture, error) {
	var empty passiveCapture
	if observer != "A" && observer != "B" {
		return empty, errors.New("passive observer must be A or B")
	}
	if net.ParseIP(bind).To4() == nil || port < 1024 || port > 65535 {
		return empty, errors.New("passive receiver requires exact IPv4 bind and port 1024..65535")
	}
	if window < 1 || window > passiveMaxWindowSeconds || limit < 1 || limit > passiveMaxPackets {
		return empty, errors.New("passive receiver requires finite duration 1..14400 seconds and packet ceiling 1..2048")
	}
	id, err := randomHex(16)
	if err != nil {
		return empty, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return passiveCapture{
		Format: passiveCaptureFormat, CaptureID: id, Observer: observer,
		BindIP: bind, DataPort: port, WindowSeconds: window, PacketLimit: limit,
		StartedUTC: now, UpdatedUTC: now, Status: "IN_PROGRESS",
		Observations: []passivePacket{},
	}, nil
}

func passiveSnapshot(path string, capture passiveCapture, credential tls.Certificate, replace bool) error {
	// Size and safe regular-file ownership enforced by writeStagedJSON.
	pem, sig, err := signatureFromCredential(capture, credential)
	if err != nil {
		return err
	}
	return writeStagedJSON(path, signedPassiveCapture{
		Capture: capture, ObserverCertificatePEM: pem, SignatureHex: sig,
	}, replace)
}

func passiveAppend(c *passiveCapture, packet []byte, actualSource string, at time.Time) (bool, error) {
	if len(packet) < fieldMinPacket || len(packet) > fieldMaxPacket || string(packet[:4]) != "SDF2" {
		return false, nil
	}
	if net.ParseIP(actualSource).To4() == nil {
		return false, errors.New("passive source is not IPv4")
	}
	if len(c.Observations) >= c.PacketLimit {
		return false, errors.New("finite passive packet ceiling reached")
	}
	c.Observations = append(c.Observations, passivePacket{
		Sequence: len(c.Observations), ReceivedUTC: at.UTC().Format(time.RFC3339Nano),
		ActualPacketSource: actualSource, PacketBase64: base64.StdEncoding.EncodeToString(packet),
	})
	c.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	return true, nil
}

// fieldPassiveObserve is a finite local operation, not a background daemon.
// A separate supervised execution mode can detach this exact command from SSH.
func fieldPassiveObserve(ctx context.Context, o fieldOptions, maxPackets int) (map[string]any, error) {
	if o.Output == "" || o.BindIP == "" || o.WindowSeconds < 1 {
		return nil, errors.New("field observe requires --out --bind-ip --window-seconds")
	}
	if err := localAssignedIPv4(o.BindIP); err != nil {
		return nil, err
	}
	c, err := newPassiveCapture(o.Receiver, o.BindIP, o.DataPort, o.WindowSeconds, maxPackets)
	if err != nil {
		return nil, err
	}
	credential, _, err := checkLocalFieldCredential(o.Cert, o.Key, o.CA, c.Observer, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(o.Output); err == nil {
		return nil, os.ErrExist
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(o.BindIP), Port: o.DataPort})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := passiveSnapshot(o.Output, c, credential, false); err != nil {
		return nil, err
	}
	end := time.Now().Add(time.Duration(o.WindowSeconds) * time.Second)
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-closed:
		}
	}()
	defer close(closed)
	buf := make([]byte, fieldMaxPacket+1)
	var stopReason string
	for len(c.Observations) < c.PacketLimit {
		if ctx.Err() != nil {
			stopReason = "OPERATOR_INTERRUPTED"
			break
		}
		if err := conn.SetReadDeadline(end); err != nil {
			stopReason = "READ_ERROR"
			break
		}
		n, peer, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				stopReason = "WINDOW_ENDED"
				break
			}
			if ctx.Err() != nil {
				stopReason = "OPERATOR_INTERRUPTED"
			} else {
				stopReason = "READ_ERROR"
			}
			break
		}
		if peer == nil || peer.IP.To4() == nil {
			continue
		}
		recorded, appendErr := passiveAppend(&c, buf[:n], peer.IP.To4().String(), time.Now())
		if appendErr != nil {
			stopReason = "CAPTURE_ERROR"
			break
		}
		if recorded {
			if err := passiveSnapshot(o.Output, c, credential, true); err != nil {
				return nil, fmt.Errorf("signed passive observation persistence failed: %w", err)
			}
		}
	}
	if stopReason == "" {
		stopReason = "PACKET_CEILING_REACHED"
	}
	c.StopReason = stopReason
	c.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if stopReason == "OPERATOR_INTERRUPTED" || stopReason == "READ_ERROR" || stopReason == "CAPTURE_ERROR" {
		c.Status = "PARTIAL"
	} else {
		c.Status = "COMPLETE"
	}
	if err := passiveSnapshot(o.Output, c, credential, true); err != nil {
		return nil, err
	}
	result := map[string]any{"status": c.Status, "capture_id": c.CaptureID,
		"signed_observation": o.Output, "observed_unverified": len(c.Observations),
		"stop_reason": stopReason, "peer_authenticated": "NOT_YET_VERIFIED",
		"network_return_path": "NOT_TESTED",
	}
	if c.Status == "PARTIAL" {
		return result, fmt.Errorf("passive observation interrupted: %s", stopReason)
	}
	return result, nil
}

func readAndVerifyPassive(path, ca, role string) (passiveCapture, error) {
	var empty passiveCapture
	data, err := readSmallRegular(path, passiveMaxFile)
	if err != nil {
		return empty, err
	}
	var signed signedPassiveCapture
	if err = json.Unmarshal(data, &signed); err != nil {
		return empty, err
	}
	c := signed.Capture
	if c.Format != passiveCaptureFormat || c.CaptureID == "" || c.Observer != role ||
		(c.Observer != "A" && c.Observer != "B") || net.ParseIP(c.BindIP).To4() == nil ||
		c.DataPort < 1024 || c.DataPort > 65535 || c.WindowSeconds < 1 ||
		c.WindowSeconds > passiveMaxWindowSeconds || c.PacketLimit < 1 || c.PacketLimit > passiveMaxPackets ||
		len(c.Observations) > c.PacketLimit ||
		(c.Status != "IN_PROGRESS" && c.Status != "PARTIAL" && c.Status != "COMPLETE") {
		return empty, errors.New("invalid passive capture scope or status")
	}
	start, err := time.Parse(time.RFC3339Nano, c.StartedUTC)
	if err != nil {
		return empty, err
	}
	updated, err := time.Parse(time.RFC3339Nano, c.UpdatedUTC)
	if err != nil || updated.Before(start) || updated.After(time.Now().Add(60*time.Second)) ||
		updated.After(start.Add(time.Duration(c.WindowSeconds)*time.Second+2*time.Minute)) {
		return empty, errors.New("invalid passive observation timestamp window")
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		return empty, err
	}
	if _, err = verifyFieldSignature(c, signed.ObserverCertificatePEM, signed.SignatureHex,
		roots, c.Observer, updated, x509.ExtKeyUsageServerAuth); err != nil {
		return empty, err
	}
	for i, p := range c.Observations {
		when, err := time.Parse(time.RFC3339Nano, p.ReceivedUTC)
		if err != nil || when.Before(start.Add(-60*time.Second)) || when.After(updated.Add(60*time.Second)) {
			return empty, errors.New("passive record timestamp outside signed capture")
		}
		if p.Sequence != i || net.ParseIP(p.ActualPacketSource).To4() == nil {
			return empty, errors.New("passive record sequence or source invalid")
		}
		decoded, err := base64.StdEncoding.DecodeString(p.PacketBase64)
		if err != nil || len(decoded) < fieldMinPacket || len(decoded) > fieldMaxPacket || string(decoded[:4]) != "SDF2" {
			return empty, errors.New("invalid passive diagnostic frame")
		}
	}
	return c, nil
}

// Correlate only after manual artifact handoff. B's signed capture asserts
// its local socket observation; matching with A's verified packet signature
// does not establish NIC egress, provider acceptance or return connectivity.
func correlatePassive(challengePath, capturePath, senderReport, ca string) (map[string]any, error) {
	ch, err := readSignedFieldChallenge(challengePath)
	if err != nil {
		return nil, err
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		return nil, err
	}
	leaf, err := checkSignedFieldChallenge(ch, roots, time.Now(), false)
	if err != nil {
		return nil, err
	}
	c := ch.Challenge
	capture, err := readAndVerifyPassive(capturePath, ca, c.Receiver)
	if err != nil {
		return nil, err
	}
	if capture.DataPort != c.DataPort || capture.BindIP != c.DestinationIP {
		return nil, errors.New("passive observation endpoint differs from signed sender plan")
	}
	senderState := "NOT_PROVIDED"
	var sender map[string]any
	if senderReport != "" {
		sender, err = verifySenderEvidence(senderReport, c, ca)
		if err != nil {
			return nil, err
		}
		senderState = "SIGNED_SENDER_EVIDENCE_VERIFIED"
	}
	seen := make(map[int]bool)
	var observations []map[string]any
	matched, rewritten, unpaired := 0, 0, 0
	created, err := time.Parse(time.RFC3339Nano, c.CreatedUTC)
	if err != nil {
		return nil, err
	}
	validAfter := created.Add(-60 * time.Second)
	validBefore := time.Unix(c.ExpiresUnix, 0).Add(60 * time.Second)
	for _, item := range capture.Observations {
		observedAt, err := time.Parse(time.RFC3339Nano, item.ReceivedUTC)
		if err != nil {
			return nil, err
		}
		if observedAt.Before(validAfter) || observedAt.After(validBefore) {
			unpaired++ // a signed old/replayed packet is not current-Run reachability proof
			continue
		}
		buf, decodeErr := base64.StdEncoding.DecodeString(item.PacketBase64)
		if decodeErr != nil {
			return nil, decodeErr
		}
		sample, valid := verifyFieldPacket(buf, c, leaf.PublicKey.(ed25519.PublicKey), seen)
		if !valid {
			unpaired++
			continue
		}
		match := sample.Candidate.IP == item.ActualPacketSource
		if match {
			matched++
		} else {
			rewritten++
		}
		observations = append(observations, map[string]any{
			"sample_index": sample.Index, "candidate_source_ip": sample.Candidate.IP,
			"actual_observed_source_ip": item.ActualPacketSource, "source_matched": match,
			"receiver_observed_utc": item.ReceivedUTC, "status": "AUTHENTICATED_PEER_OBSERVATION",
		})
	}
	result := map[string]any{
		"status": "SIGNED_ONE_WAY_EVIDENCE_NOT_RETURN_PATH_PROOF",
		"run_id": c.RunID, "capture_id": capture.CaptureID, "direction": func() string { d, _ := roleDirection(c.Sender, c.Receiver); return d }(),
		"planned_samples": len(c.Samples), "authenticated_observed": len(observations),
		"source_matched": matched, "source_rewritten": rewritten,
		"unmatched_or_duplicate_frames": unpaired,
		"not_observed":                  len(c.Samples) - len(observations),
		"receiver_capture_status":       capture.Status, "receiver_stop_reason": capture.StopReason,
		"sender_evidence_state": senderState, "sender_evidence": sender,
		"observations":        observations,
		"not_observed_reason": "INCONCLUSIVE_NOT_PROVEN_BLOCKED",
		"return_to_sender":    "NOT_TESTED", "private_L3": "NOT_TESTED",
	}
	return result, nil
}
