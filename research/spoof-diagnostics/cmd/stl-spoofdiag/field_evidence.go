package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// A snapshot is published atomically after each material state change. If the
// process or machine stops, the latest signed evidence remains usable. An
// ATTEMPTED_UNKNOWN syscall is deliberately not counted as delivered.
type fieldSendRecord struct {
	Index int    `json:"index"`
	State string `json:"state"`
	UTC   string `json:"utc"`
	Error string `json:"error,omitempty"`
}

type fieldSenderEvidence struct {
	SchemaVersion int               `json:"schema_version"`
	Environment   string            `json:"environment"`
	RunID         string            `json:"run_id"`
	Sender        string            `json:"sender"`
	ChallengeHash string            `json:"challenge_digest"`
	CreatedUTC    string            `json:"created_utc"`
	Status        string            `json:"status"`
	Reason        string            `json:"reason,omitempty"`
	Records       []fieldSendRecord `json:"records"`
}

type signedFieldSenderEvidence struct {
	Evidence             fieldSenderEvidence `json:"evidence"`
	SenderCertificatePEM string              `json:"sender_certificate_pem"`
	SignatureHex         string              `json:"signature_hex"`
}

func signSenderEvidence(ev fieldSenderEvidence, cred tls.Certificate) (signedFieldSenderEvidence, error) {
	pem, sig, err := signatureFromCredential(ev, cred)
	if err != nil {
		return signedFieldSenderEvidence{}, err
	}
	return signedFieldSenderEvidence{Evidence: ev, SenderCertificatePEM: pem, SignatureHex: sig}, nil
}

func verifySenderEvidence(path string, c fieldChallenge, ca string) (map[string]any, error) {
	data, err := readSmallRegular(path, fieldMaxControl)
	if err != nil {
		return nil, err
	}
	var signed signedFieldSenderEvidence
	if err := strictJSON(data, &signed); err != nil {
		return nil, err
	}
	ev := signed.Evidence
	if ev.SchemaVersion != schema || ev.Environment != c.Environment || ev.RunID != c.RunID ||
		ev.Sender != c.Sender || ev.ChallengeHash != fieldChallengeDigest(c) ||
		(ev.Status != "IN_PROGRESS" && ev.Status != "PARTIAL" && ev.Status != "COMPLETE") ||
		len(ev.Records) > len(c.Samples) {
		return nil, errors.New("sender evidence is not bound to the signed plan")
	}
	when, err := time.Parse(time.RFC3339Nano, ev.CreatedUTC)
	if err != nil || when.Before(time.Unix(c.ExpiresUnix, 0).Add(-15*time.Minute-60*time.Second)) ||
		when.After(time.Unix(c.ExpiresUnix, 0).Add(60*time.Second)) {
		return nil, errors.New("sender evidence time outside challenge interval")
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		return nil, err
	}
	if _, err := verifyFieldSignature(ev, signed.SenderCertificatePEM, signed.SignatureHex,
		roots, c.Sender, when, x509.ExtKeyUsageClientAuth); err != nil {
		return nil, err
	}
	submitted, unknown, failed := 0, 0, 0
	for i, record := range ev.Records {
		if record.Index != i || record.UTC == "" {
			return nil, errors.New("sender evidence indices not sequential")
		}
		switch record.State {
		case "ATTEMPTED_UNKNOWN":
			unknown++
		case "SUBMITTED":
			submitted++
		case "FAILED":
			failed++
		default:
			return nil, errors.New("unknown sender evidence state")
		}
		if record.State != "FAILED" && record.Error != "" {
			return nil, errors.New("sender evidence error/state mismatch")
		}
		if _, err := time.Parse(time.RFC3339Nano, record.UTC); err != nil {
			return nil, err
		}
	}
	if ev.Status == "COMPLETE" && (len(ev.Records) != len(c.Samples) || submitted != len(c.Samples)) {
		return nil, errors.New("sender COMPLETE claimed without all submitted syscalls")
	}
	return map[string]any{"status": ev.Status, "syscalls_succeeded": submitted,
		"attempted_unknown": unknown, "failed": failed,
		"not_attempted": len(c.Samples) - len(ev.Records),
		"evidence":      "SIGNED_SENDER_SYSCALL_DECLARATION_NOT_NIC_OR_PROVIDER_PROOF"}, nil
}

// saveNewJSON and updateOwnedJSON use only regular files, sync their content,
// then publish with exclusive hard link or atomic rename, respectively.
// An interrupted write never exposes a truncated or unsigned final artifact.
func jsonBytes(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("artifact too large: %d bytes", len(data))
	}
	return data, nil
}

func writeStagedJSON(path string, v any, replace bool) error {
	if filepath.Ext(path) != ".json" {
		return errors.New("output must be a .json path")
	}
	data, err := jsonBytes(v)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if replace {
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return errors.New("refusing to replace an unsafe evidence file")
		}
	} else if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(dir, ".spoofdiag-atomic-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if replace {
		err = os.Rename(f.Name(), path)
	} else {
		err = os.Link(f.Name(), path) // O_EXCL behavior: never overwrite
	}
	if err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		defer d.Close()
		if err := d.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func signedSenderSnapshot(path string, ev fieldSenderEvidence, cred tls.Certificate, replace bool) error {
	env, err := signSenderEvidence(ev, cred)
	if err != nil {
		return err
	}
	return writeStagedJSON(path, env, replace)
}

func senderRecordUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// sampleSubmitFunc is deliberately injected only at the bounded syscall edge,
// permitting fault-injection without opening sockets or sending packets.
type sampleSubmitFunc func(fieldSample, []byte) error

func submitFieldRun(c fieldChallenge, ev *fieldSenderEvidence, cert tls.Certificate, path string, submit sampleSubmitFunc, pace func() error) (int, error) {
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return 0, errors.New("sender requires an Ed25519 private key")
	}
	submitted := 0
	fail := func(err error) (int, error) {
		ev.Status, ev.Reason, ev.CreatedUTC = "PARTIAL", err.Error(), senderRecordUTC()
		if snapshotErr := signedSenderSnapshot(path, *ev, cert, true); snapshotErr != nil {
			return submitted, fmt.Errorf("%v (failed to preserve terminal evidence: %w)", err, snapshotErr)
		}
		return submitted, err
	}
	for i, sample := range c.Samples {
		if time.Now().Unix() >= c.ExpiresUnix {
			return fail(errors.New("signed challenge expired while sending"))
		}
		payload, err := makeFieldPacket(c, sample, key)
		if err != nil {
			return fail(err)
		}
		ev.Records = append(ev.Records, fieldSendRecord{Index: sample.Index, State: "ATTEMPTED_UNKNOWN", UTC: senderRecordUTC()})
		ev.CreatedUTC = senderRecordUTC()
		if err := signedSenderSnapshot(path, *ev, cert, true); err != nil {
			return submitted, err // no syscall occurred for this sample
		}
		err = submit(sample, payload)
		ev.Records[i].UTC = senderRecordUTC()
		ev.CreatedUTC = senderRecordUTC()
		if err != nil {
			ev.Records[i].State, ev.Records[i].Error = "FAILED", err.Error()
			return fail(err)
		}
		ev.Records[i].State = "SUBMITTED"
		if err := signedSenderSnapshot(path, *ev, cert, true); err != nil {
			return submitted, err // persisted ATTEMPTED_UNKNOWN; cannot claim send success
		}
		submitted++
		if i+1 < len(c.Samples) {
			if err := pace(); err != nil {
				return fail(err)
			}
		}
	}
	ev.Status, ev.CreatedUTC = "COMPLETE", senderRecordUTC()
	if err := signedSenderSnapshot(path, *ev, cert, true); err != nil {
		return submitted, err
	}
	return submitted, nil
}

func newSenderEvidence(c fieldChallenge) fieldSenderEvidence {
	return fieldSenderEvidence{SchemaVersion: schema, Environment: c.Environment,
		RunID: c.RunID, Sender: c.Sender, ChallengeHash: fieldChallengeDigest(c),
		CreatedUTC: senderRecordUTC(), Status: "IN_PROGRESS", Records: []fieldSendRecord{}}
}

// Exact hash is useful for immutable batches and audit trails, not proof of
// third-party/provider permission.
func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
