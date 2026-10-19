package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// Receiver readiness is signed only AFTER a finite listener has successfully
// bound a socket. It is an operational coordination statement, not proof the
// listener remains alive or that network delivery or permission is available.
type fieldReady struct {
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id"`
	ChallengeHash string `json:"challenge_digest"`
	Receiver      string `json:"receiver"`
	DestinationIP string `json:"destination_ip"`
	BindIP        string `json:"receiver_bind_ip"`
	DataPort      int    `json:"data_port"`
	StartedUTC    string `json:"started_utc"`
	ExpiresUnix   int64  `json:"expires_unix"`
}

type signedFieldReady struct {
	Ready                  fieldReady `json:"ready"`
	ReceiverCertificatePEM string     `json:"receiver_certificate_pem"`
	SignatureHex           string     `json:"signature_hex"`
}

func newSignedFieldReady(c fieldChallenge, grant fieldGrant, bindIP string, until time.Time, cert tls.Certificate) (signedFieldReady, error) {
	if bindIP == "" || bindIP != grantBindIP(c, grant) || until.IsZero() ||
		until.After(time.Unix(c.ExpiresUnix, 0)) || !until.After(time.Now()) {
		return signedFieldReady{}, errors.New("invalid receiver ready interval/bind")
	}
	ready := fieldReady{SchemaVersion: schema, RunID: c.RunID,
		ChallengeHash: fieldChallengeDigest(c), Receiver: c.Receiver,
		DestinationIP: c.DestinationIP, BindIP: bindIP, DataPort: c.DataPort,
		StartedUTC: time.Now().UTC().Format(time.RFC3339Nano), ExpiresUnix: until.Unix()}
	pem, sig, err := signatureFromCredential(ready, cert)
	if err != nil {
		return signedFieldReady{}, err
	}
	return signedFieldReady{Ready: ready, ReceiverCertificatePEM: pem, SignatureHex: sig}, nil
}

func grantBindIP(c fieldChallenge, g fieldGrant) string {
	if g.BindIP != "" {
		return g.BindIP
	}
	return c.DestinationIP // legacy direct-assigned destination
}

func verifySignedFieldReady(path string, c fieldChallenge, g signedFieldGrant, ca string, now time.Time) (map[string]any, error) {
	content, err := readSmallRegular(path, fieldMaxControl)
	if err != nil {
		return nil, err
	}
	var envelope signedFieldReady
	if err := strictJSON(content, &envelope); err != nil {
		return nil, err
	}
	ready := envelope.Ready
	if ready.SchemaVersion != schema || ready.RunID != c.RunID ||
		ready.ChallengeHash != fieldChallengeDigest(c) || ready.Receiver != c.Receiver ||
		ready.DestinationIP != c.DestinationIP || ready.DataPort != c.DataPort ||
		ready.BindIP != grantBindIP(c, g.Grant) || net.ParseIP(ready.BindIP).To4() == nil {
		return nil, errors.New("receiver ready artifact mismatched signed challenge/grant")
	}
	started, err := time.Parse(time.RFC3339Nano, ready.StartedUTC)
	expires := time.Unix(ready.ExpiresUnix, 0)
	if err != nil || started.After(now.Add(60*time.Second)) ||
		started.Before(time.Unix(c.ExpiresUnix, 0).Add(-16*time.Minute)) ||
		!expires.After(started) || expires.After(started.Add(120*time.Second)) ||
		expires.After(time.Unix(c.ExpiresUnix, 0)) || !expires.After(now) {
		return nil, errors.New("receiver readiness is expired or outside signed bounded window")
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		return nil, err
	}
	leaf, err := verifyFieldSignature(ready, envelope.ReceiverCertificatePEM,
		envelope.SignatureHex, roots, c.Receiver, now, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, fmt.Errorf("signed receiver readiness: %w", err)
	}
	grantSigner, err := parseFieldCertificate(g.ReceiverCertificatePEM)
	if err != nil || !leaf.Equal(grantSigner) {
		return nil, errors.New("receiver ready signer differs from approved receiver grant")
	}
	return map[string]any{"status": "SIGNED_RECEIVER_LISTENER_REPORTED_READY",
		"run_id": c.RunID, "receiver_bind_ip": ready.BindIP,
		"ready_until_unix": ready.ExpiresUnix,
		"reachability":     "NOT_PROVEN_BY_READY_FILE"}, nil
}
