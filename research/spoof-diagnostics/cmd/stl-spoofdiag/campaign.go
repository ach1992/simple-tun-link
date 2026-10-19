package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// A campaign is a finite, offline-prepared sequence of exact operator-provided
// IPv4 batches. It never discovers addresses, generates forged traffic, runs a
// daemon, skips receiver grants or auto-retries a possibly consumed run.
type campaignBatch struct {
	Number int    `json:"number"`
	File   string `json:"file"`
	Digest string `json:"sha256"`
	Count  int    `json:"count"`
}

type campaignManifest struct {
	SchemaVersion    int             `json:"schema_version"`
	CampaignID       string          `json:"campaign_id"`
	CreatedUTC       string          `json:"created_utc"`
	SourceDigest     string          `json:"source_sha256"`
	Direction        string          `json:"direction"`
	Sender           string          `json:"sender"`
	Receiver         string          `json:"receiver"`
	DestinationIP    string          `json:"destination_ip"`
	Transport        string          `json:"transport"`
	DataPort         int             `json:"data_port"`
	PacketSize       int             `json:"packet_size"`
	SamplesPerSource int             `json:"samples_per_source"`
	TTLSeconds       int             `json:"ttl_seconds"`
	Epoch            string          `json:"policy_epoch"`
	BatchSize        int             `json:"batch_size"`
	SourceCount      int             `json:"source_count"`
	Batches          []campaignBatch `json:"batches"`
}

func campaignCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: campaign create|next|receive|send|report|status|pause|resume|stop|adopt")
	}
	op := args[0]
	f := flag.NewFlagSet("campaign "+op, flag.ContinueOnError)
	dir := f.String("dir", "", "private new/existing campaign directory")
	file := f.String("file", "", "exact candidate TXT (SDX-IP-LIST v1), JSON or CSV")
	direction := f.String("direction", "", "A_TO_B or B_TO_A; default uses the file direction, A_TO_B for a mixed inventory")
	destination := f.String("destination-ip", "", "one exact receiver public/advertised IPv4")
	transport := f.String("transport", "field_udp_bound", "field_udp_bound or field_raw_ipv4")
	batchSize := f.Int("batch-size", fieldMaxSelectedSources, "1..32 distinct candidate IPs per signed run")
	samples := f.Int("samples-per-source", 5, "1..10 per source and signed run")
	packetSize := f.Int("packet-size", 192, "128..1200 signed UDP payload bytes")
	port := f.Int("data-port", 24572, "receiver UDP port")
	ttl := f.Int("ttl-seconds", 600, "signed grant/challenge TTL 60..900s")
	epoch := f.String("epoch", "operator-declared", "operator-assigned policy epoch")
	cert := f.String("cert", "", "local sender certificate used for just-in-time challenge")
	key := f.String("key", "", "local sender key used for just-in-time challenge")
	ca := f.String("ca", "", "trusted CA certificate")
	retryExpired := f.Bool("retry-expired", false, "create a NEW separately consented run only after previous challenge expires")
	hintChallenge := f.String("hint-challenge", "", "signed A_TO_B sender plan for offline reverse prioritization")
	hintCapture := f.String("hint-capture", "", "signed passive A_TO_B receiver observations")
	hintSender := f.String("hint-sender", "", "optional A_TO_B signed sender syscall evidence")
	priorityOut := f.String("out", "", "new ordered B_TO_A inventory .json")
	bind := f.String("bind-ip", "", "campaign receive: B's locally assigned destination IP (defaults to advertised destination)")
	stateDir := f.String("state-dir", "", "campaign receive: private receiver replay-ledger directory (defaults inside campaign)")
	forwarded := f.Bool("allow-forwarded-destination", false, "campaign receive: explicit B consent to previously configured DNAT")
	iface := f.String("interface", "", "campaign send: explicitly authorized raw egress interface")
	providerApproved := f.Bool("provider-authorized", false, "campaign send: operator acknowledgement, not independent provider permission")
	controlReason := f.String("reason", "", "operator reason for local pause/resume/stop")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if op == "prioritize" {
		audit, err := prepareReversePriority(*file, *hintChallenge, *hintCapture, *hintSender, *ca, *priorityOut)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "PROVISIONAL_ORDER_ONLY_NO_REVERSE_PROOF_NO_NETWORK",
			"ordered_file": *priorityOut, "audit": (*priorityOut)[:len(*priorityOut)-5] + ".ranking.json",
			"source_count": len(audit.Candidates), "confidence": audit.Confidence})
	}
	if *dir == "" {
		return errors.New("campaign --dir is required")
	}
	switch op {
	case "status":
		result, err := campaignControlStatus(*dir, *ca)
		if err != nil {
			return err
		}
		return pretty(result)
	case "pause", "resume", "stop", "adopt":
		result, err := changeCampaignControl(*dir, op, *controlReason)
		if err != nil {
			return err
		}
		return pretty(result)
	case "create":
		if *file == "" || *destination == "" {
			return errors.New("campaign create requires --file --dir --destination-ip")
		}
		manifest, err := createCampaign(*file, *dir, campaignManifest{
			Direction: *direction, DestinationIP: *destination, Transport: *transport,
			BatchSize: *batchSize, SamplesPerSource: *samples, PacketSize: *packetSize,
			DataPort: *port, TTLSeconds: *ttl, Epoch: *epoch,
		})
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "PREPARED_OFFLINE_NO_PACKETS",
			"campaign_id": manifest.CampaignID, "source_count": manifest.SourceCount,
			"batch_count": len(manifest.Batches), "directory": *dir,
			"next": "campaign next --dir DIR --cert SENDER.crt --key SENDER.key --ca ca.crt"})
	case "next":
		result, err := campaignNext(*dir, *cert, *key, *ca, *retryExpired)
		if result != nil {
			if printErr := pretty(result); printErr != nil {
				return printErr
			}
		}
		return err
	case "receive":
		if *cert == "" || *key == "" || *ca == "" {
			return errors.New("campaign receive requires receiver --cert --key --ca; --file is optional")
		}
		return campaignReceive(*dir, *file, *cert, *key, *ca, *bind, *stateDir, *forwarded)
	case "send":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		result, err := campaignSend(ctx, *dir, *cert, *key, *ca, *iface, *providerApproved)
		if result != nil {
			if printErr := pretty(result); printErr != nil {
				return printErr
			}
		}
		return err
	case "report":
		result, err := campaignReport(*dir, *ca)
		if err != nil {
			return err
		}
		return pretty(result)
	default:
		return errors.New("usage: campaign create|next|receive|send|report")
	}
}

// campaignReceive uses the existing signed Field engine for one operator-approved
// batch. B validates A's challenge and optionally applies an extra local
// allowlist; no second copy of A's list is needed on B. No socket is opened
// until the authenticated Field accept/listen path succeeds.
func campaignReceive(dir, receiverAllowlist, cert, key, ca, bind, stateDir string, forwarded bool) error {
	m, err := readCampaign(dir)
	if err != nil {
		return err
	}

	if stateDir == "" {
		stateDir = filepath.Join(dir, "receiver-ledger")
	}
	if bind == "" {
		bind = m.DestinationIP
	}
	if bind != m.DestinationIP && !forwarded {
		return errors.New("campaign receiver forwarded endpoint requires explicit --allow-forwarded-destination")
	}
	for _, batch := range m.Batches {
		number, path, err := latestCampaignAttempt(dir, batch.Number)
		if err != nil {
			return err
		}
		if number == 0 {
			return pretty(map[string]any{"status": "AWAITING_SENDER_SIGNED_BATCH", "batch": batch.Number})
		}
		challengePath := filepath.Join(path, "challenge.json")
		ch, err := readSignedFieldChallenge(challengePath)
		if err != nil {
			return err
		}
		if err := validateCampaignChallenge(dir, m, batch, ch, ca); err != nil {
			return err
		}
		allowed, err := receiverSourceSelection(ch.Challenge, receiverAllowlist)
		if err != nil {
			return err
		}
		if err := validateFieldSamples(ch.Challenge.Samples, allowed, m.Sender, m.Receiver); err != nil {
			return fmt.Errorf("receiver selection disagrees with signed batch: %w", err)
		}
		receiptPath, grantPath := filepath.Join(path, "receipt.json"), filepath.Join(path, "grant.json")
		if _, err := os.Lstat(receiptPath); err == nil {
			got, err := verifyFieldPair(challengePath, grantPath, receiptPath, ca)
			if err != nil {
				return err
			}
			if got["receiver_status"] == "COMPLETE" || got["receiver_status"] == "" {
				continue
			}
			return pretty(map[string]any{"batch": batch.Number,
				"status":  "RECEIVER_RUN_ALREADY_STARTED_OR_INTERRUPTED_DO_NOT_REPLAY",
				"receipt": receiptPath})
		} else if !os.IsNotExist(err) {
			return err
		}
		op := "accept"
		args := []string{op, "--cert", cert, "--key", key, "--ca", ca,
			"--sender", m.Sender, "--receiver", m.Receiver, "--challenge", challengePath,
			"--destination-ip", m.DestinationIP, "--data-port", fmt.Sprint(m.DataPort),
			"--bind-ip", bind, "--out", receiptPath, "--ready-out", filepath.Join(path, "ready.json"),
			"--state-dir", stateDir}
		if receiverAllowlist != "" {
			args = append(args, "--file", receiverAllowlist)
		}
		if forwarded {
			args = append(args, "--allow-forwarded-destination")
		}
		if _, err := os.Lstat(grantPath); err == nil {
			args[0] = "listen"
			args = append(args, "--grant", grantPath)
		} else if os.IsNotExist(err) {
			args = append(args, "--grant-out", grantPath)
		} else {
			return err
		}
		// Starts a foreground listener, one independently approved run only.
		return fieldCLI(args)
	}
	return pretty(map[string]any{"status": "NO_PREPARED_RECEIVER_BATCH", "campaign_id": m.CampaignID})
}

func createCampaign(source, dir string, settings campaignManifest) (campaignManifest, error) {
	var empty campaignManifest
	inventory, err := exchangeReadSourceAnyName(source)
	if err != nil {
		return empty, err
	}
	// A one-direction ip.txt (or JSON/CSV) already declares the role.
	// Preserve the legacy A_TO_B default for a mixed-direction inventory.
	if settings.Direction == "" {
		settings.Direction = inventory.Candidates[0].Direction
		for _, candidate := range inventory.Candidates[1:] {
			if candidate.Direction != settings.Direction {
				settings.Direction = "A_TO_B"
				break
			}
		}
	}
	if settings.Direction != "A_TO_B" && settings.Direction != "B_TO_A" {
		return empty, errors.New("campaign direction must be A_TO_B or B_TO_A")
	}
	sender, receiver := "A", "B"
	if settings.Direction == "B_TO_A" {
		sender, receiver = "B", "A"
	}
	if err := validateIP(settings.DestinationIP, "field_candidates"); err != nil {
		return empty, err
	}
	if !fieldTransportName(settings.Transport) || settings.BatchSize < 1 || settings.BatchSize > fieldMaxSelectedSources ||
		settings.PacketSize < fieldMinPacket || settings.PacketSize > fieldMaxPacket ||
		settings.SamplesPerSource < 1 || settings.SamplesPerSource > fieldMaxPacketsPerSource ||
		settings.DataPort < 1024 || settings.DataPort > 65535 ||
		settings.TTLSeconds < 60 || settings.TTLSeconds > 900 ||
		settings.Epoch == "" || len(settings.Epoch) > 96 {
		return empty, errors.New("invalid finite campaign settings")
	}
	selected := make([]Candidate, 0)
	for _, c := range inventory.Candidates {
		if c.Direction == settings.Direction && c.Sender == sender && c.Receiver == receiver {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		return empty, errors.New("no exact candidates for campaign direction")
	}
	content, err := readSmallRegular(source, 4<<20)
	if err != nil {
		return empty, err
	}
	id, err := randomHex(16)
	if err != nil {
		return empty, err
	}
	settings.SchemaVersion = schema
	settings.CampaignID = id
	settings.CreatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	settings.SourceDigest = digestBytes(content)
	settings.Sender, settings.Receiver = sender, receiver
	settings.SourceCount = len(selected)
	if err := os.Mkdir(dir, 0700); err != nil {
		return empty, err // strict new directory; no overwrite of earlier campaign
	}
	batchesDir := filepath.Join(dir, "batches")
	if err := os.Mkdir(batchesDir, 0700); err != nil {
		return empty, err
	}
	if err := os.Mkdir(filepath.Join(dir, "runs"), 0700); err != nil {
		return empty, err
	}
	for i := 0; i < len(selected); i += settings.BatchSize {
		end := i + settings.BatchSize
		if end > len(selected) {
			end = len(selected)
		}
		seq := len(settings.Batches) + 1
		name := fmt.Sprintf("batch-%05d.json", seq)
		rel := filepath.Join("batches", name)
		batch := CandidateFile{SchemaVersion: schema, Mode: "field_candidates", Candidates: selected[i:end]}
		if err := saveNewJSON(filepath.Join(dir, rel), batch); err != nil {
			return empty, err
		}
		b, err := readSmallRegular(filepath.Join(dir, rel), fieldMaxControl)
		if err != nil {
			return empty, err
		}
		settings.Batches = append(settings.Batches, campaignBatch{
			Number: seq, File: rel, Digest: digestBytes(b), Count: end - i})
	}
	if err := saveNewJSON(filepath.Join(dir, "campaign.json"), settings); err != nil {
		return empty, err
	}
	// Persist the initial control record. A missing or unparseable control
	// file is always fail-closed, including after a terminal operator STOP.
	// Crashes between these writes produce a non-runnable partial Campaign.
	if err := initializeCampaignControl(dir, settings, "NEW_CAMPAIGN_INITIALIZED"); err != nil {
		return empty, fmt.Errorf("failed to initialize mandatory Campaign state: %w", err)
	}
	return settings, nil
}

func readCampaign(dir string) (campaignManifest, error) {
	var m campaignManifest
	info, err := os.Lstat(dir)
	if err != nil {
		return m, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return m, errors.New("campaign directory must be private (0700; no symlink)")
	}
	data, err := readSmallRegular(filepath.Join(dir, "campaign.json"), 8<<20)
	if err != nil {
		return m, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return m, errors.New("extra campaign manifest data")
	}
	id, hexErr := hex.DecodeString(m.CampaignID)
	if hexErr != nil || len(id) != 16 {
		return m, errors.New("invalid campaign ID")
	}
	if m.SchemaVersion != schema ||
		!fieldTransportName(m.Transport) || m.BatchSize < 1 || m.BatchSize > fieldMaxSelectedSources ||
		m.SamplesPerSource < 1 || m.SamplesPerSource > fieldMaxPacketsPerSource ||
		m.PacketSize < fieldMinPacket || m.PacketSize > fieldMaxPacket ||
		m.TTLSeconds < 60 || m.TTLSeconds > 900 || m.DataPort < 1024 || m.DataPort > 65535 ||
		m.Epoch == "" || len(m.Epoch) > 96 || len(m.Batches) == 0 ||
		len(m.Batches) > m.SourceCount || m.SourceCount < 1 {
		return m, errors.New("invalid campaign manifest settings")
	}
	if err := validateIP(m.DestinationIP, "field_candidates"); err != nil {
		return m, err
	}
	if dirFromRoles, err := roleDirection(m.Sender, m.Receiver); err != nil || dirFromRoles != m.Direction {
		return m, errors.New("campaign sender/receiver direction mismatch")
	}
	sumCount := 0
	identities := make(map[string]bool, m.SourceCount)
	for i, batch := range m.Batches {
		expected := filepath.Join("batches", fmt.Sprintf("batch-%05d.json", i+1))
		if batch.Number != i+1 || batch.File != expected || batch.Count < 1 || batch.Count > m.BatchSize ||
			len(batch.Digest) != 64 {
			return m, errors.New("campaign manifest contains unexpected batch")
		}
		file := filepath.Join(dir, expected)
		content, err := readSmallRegular(file, fieldMaxControl)
		if err != nil || digestBytes(content) != batch.Digest {
			return m, fmt.Errorf("campaign batch %d missing or modified: %w", i+1, errors.Join(err, errors.New("digest mismatch")))
		}
		candidates, err := readCandidates(file)
		if err != nil || len(candidates.Candidates) != batch.Count {
			return m, fmt.Errorf("campaign batch %d invalid: %w", i+1, errors.Join(err, errors.New("candidate count mismatch")))
		}
		for _, c := range candidates.Candidates {
			if c.Direction != m.Direction || c.Sender != m.Sender || c.Receiver != m.Receiver ||
				identities[candidateIdentity(c)] {
				return m, errors.New("campaign batch direction or global uniqueness violation")
			}
			identities[candidateIdentity(c)] = true
		}
		sumCount += batch.Count
	}
	if sumCount != m.SourceCount {
		return m, errors.New("campaign source count mismatch")
	}
	return m, nil
}

func campaignAttemptDir(dir string, number, attempt int) string {
	return filepath.Join(dir, "runs", fmt.Sprintf("batch-%05d", number), fmt.Sprintf("attempt-%04d", attempt))
}

func latestCampaignAttempt(dir string, number int) (int, string, error) {
	parent := filepath.Dir(campaignAttemptDir(dir, number, 1))
	if st, err := os.Lstat(parent); err == nil {
		if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return 0, "", errors.New("unsafe campaign batch run directory")
		}
	} else if !os.IsNotExist(err) {
		return 0, "", err
	}
	for attempt := 1; attempt < 100000; attempt++ {
		path := campaignAttemptDir(dir, number, attempt)
		st, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return attempt - 1, campaignAttemptDir(dir, number, attempt-1), nil
		}
		if err != nil {
			return 0, "", err
		}
		if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return 0, "", errors.New("unsafe campaign attempt directory")
		}
	}
	return 0, "", errors.New("campaign attempt count exceeds filesystem safety limit")
}

// campaignMutate serializes local next/send operations for a campaign. The
// immutable manifest is used only as a lock inode; its contents never change.
func campaignMutate(dir string, action func() (map[string]any, error)) (map[string]any, error) {
	lockFile, err := os.Open(filepath.Join(dir, "campaign.json"))
	if err != nil {
		return nil, err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("campaign is already being advanced/sent: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	return action()
}

func campaignNewAttempt(dir string, m campaignManifest, batch campaignBatch, attempt int, cert, key, ca string) (map[string]any, error) {
	if cert == "" || key == "" || ca == "" {
		return nil, errors.New("campaign next needs --cert --key --ca to sign the new batch challenge")
	}
	parent := filepath.Dir(campaignAttemptDir(dir, batch.Number, attempt))
	if err := os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	st, err := os.Lstat(parent)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe or foreign campaign batch run directory")
	}
	path := campaignAttemptDir(dir, batch.Number, attempt)
	if _, err := os.Lstat(path); err == nil {
		return nil, os.ErrExist
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Build a complete challenge in a private staging directory. A crash
	// before publication leaves no apparently valid attempt number.
	stage, err := os.MkdirTemp(parent, ".spoofdiag-new-attempt-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage) // this call created the unpredictable owned stage
	if err := os.Chmod(stage, 0700); err != nil {
		return nil, err
	}
	sources := filepath.Join(dir, batch.File)
	challenge, err := newFieldChallenge(fieldOptions{File: sources, Cert: cert, Key: key, CA: ca,
		Sender: m.Sender, Receiver: m.Receiver, DestinationIP: m.DestinationIP, DataPort: m.DataPort,
		Transport: m.Transport, PacketSize: m.PacketSize, SamplesPerSource: m.SamplesPerSource,
		TTLSeconds: m.TTLSeconds, Epoch: m.Epoch})
	if err != nil {
		return nil, err
	}
	if err := saveNewJSON(filepath.Join(stage, "challenge.json"), challenge); err != nil {
		return nil, err
	}
	if f, err := os.Open(stage); err == nil {
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
	}
	if err := os.Rename(stage, path); err != nil {
		return nil, err
	}
	if f, err := os.Open(parent); err == nil {
		_ = f.Sync()
		f.Close()
	}
	return campaignPendingSummary(m, batch, path, attempt, "AWAITING_INDEPENDENT_RECEIVER_GRANT"), nil
}

func campaignPendingSummary(m campaignManifest, batch campaignBatch, path string, attempt int, state string) map[string]any {
	return map[string]any{
		"campaign_id": m.CampaignID, "batch": batch.Number, "total_batches": len(m.Batches),
		"batch_sources": batch.Count, "attempt": attempt, "status": state,
		"batch_file": filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "batches", fmt.Sprintf("batch-%05d.json", batch.Number)),
		"challenge":  filepath.Join(path, "challenge.json"), "grant": filepath.Join(path, "grant.json"),
		"sender_report": filepath.Join(path, "sender.json"), "receiver_receipt": filepath.Join(path, "receipt.json"),
		"receiver_ready": filepath.Join(path, "ready.json"),
		"next_step":      "B independently signs grant; start B listener; A sends this ONE bounded signed run after grant and readiness; transfer B receipt to A. No traffic is auto-sent.",
	}
}

func campaignNext(dir, cert, key, ca string, retryExpired bool) (map[string]any, error) {
	return campaignMutate(dir, func() (map[string]any, error) {
		return campaignNextLocked(dir, cert, key, ca, retryExpired)
	})
}

func campaignNextLocked(dir, cert, key, ca string, retryExpired bool) (map[string]any, error) {
	if ca == "" {
		return nil, errors.New("campaign next requires --ca to verify previous signed runs")
	}
	m, err := readCampaign(dir)
	if err != nil {
		return nil, err
	}
	if err := requireCampaignActive(dir, m); err != nil {
		return nil, err
	}
	for _, batch := range m.Batches {
		attempt, path, err := latestCampaignAttempt(dir, batch.Number)
		if err != nil {
			return nil, err
		}
		if attempt == 0 {
			return campaignNewAttempt(dir, m, batch, 1, cert, key, ca)
		}
		challengePath := filepath.Join(path, "challenge.json")
		ch, err := readSignedFieldChallenge(challengePath)
		if err != nil {
			return nil, err
		}
		if err := validateCampaignChallenge(dir, m, batch, ch, ca); err != nil {
			return nil, fmt.Errorf("campaign batch %d challenge invalid: %w", batch.Number, err)
		}
		receiptPath := filepath.Join(path, "receipt.json")
		if _, err := os.Lstat(receiptPath); err == nil {
			result, err := verifyFieldPair(challengePath, filepath.Join(path, "grant.json"), receiptPath, ca)
			if err != nil {
				return nil, fmt.Errorf("campaign batch %d invalid signed receipt: %w", batch.Number, err)
			}
			if result["receiver_status"] == "COMPLETE" || result["receiver_status"] == "" {
				senderFile := filepath.Join(path, "sender.json")
				if _, err := os.Lstat(senderFile); err == nil {
					sender, err := verifySenderEvidence(senderFile, ch.Challenge, ca)
					if err != nil {
						return nil, fmt.Errorf("invalid signed sender evidence for batch %d: %w", batch.Number, err)
					}
					if sender["status"] == "COMPLETE" && sender["syscalls_succeeded"] == len(ch.Challenge.Samples) {
						continue
					}
				} else if !os.IsNotExist(err) {
					return nil, err
				}
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		expired := time.Now().Unix() >= ch.Challenge.ExpiresUnix
		if expired && retryExpired {
			return campaignNewAttempt(dir, m, batch, attempt+1, cert, key, ca)
		}
		state := "AWAITING_SIGNED_SENDER_AND_RECEIVER_EVIDENCE"
		if expired {
			state = "EXPIRED_REVIEW_EVIDENCE_THEN_RETRY_EXPLICITLY"
		}
		return campaignPendingSummary(m, batch, path, attempt, state), nil
	}
	return map[string]any{"campaign_id": m.CampaignID,
		"status": "ALL_BATCHES_HAVE_SIGNED_SENDER_AND_RECEIVER_EVIDENCE", "batch_count": len(m.Batches),
		"qualification": "NOT_PROVIDER_OR_RETURN_PATH_PROOF"}, nil
}

type campaignSourceTotal struct {
	Candidate       Candidate `json:"candidate"`
	Planned         int       `json:"planned_samples_in_completed_runs"`
	PeerObserved    int       `json:"authenticated_peer_observations"`
	ExactSource     int       `json:"exact_source_observations"`
	RewrittenSource int       `json:"rewritten_source_observations"`
	CompletedRuns   int       `json:"verified_runs"`
}

func campaignReport(dir, ca string) (map[string]any, error) {
	m, err := readCampaign(dir)
	if err != nil {
		return nil, err
	}
	if ca == "" {
		return nil, errors.New("campaign report needs --ca to verify B's independent signature")
	}
	byKey := make(map[string]*campaignSourceTotal)
	for _, batch := range m.Batches {
		sources, err := readCandidates(filepath.Join(dir, batch.File))
		if err != nil {
			return nil, err
		}
		for _, candidate := range sources.Candidates {
			copyCandidate := candidate
			byKey[candidateIdentity(candidate)] = &campaignSourceTotal{Candidate: copyCandidate}
		}
	}
	var runs []map[string]any
	completed, pending, partial := 0, 0, 0
	for _, batch := range m.Batches {
		latest, _, err := latestCampaignAttempt(dir, batch.Number)
		if err != nil {
			return nil, err
		}
		if latest == 0 {
			pending++
			continue
		}
		batchComplete := false
		for i := 1; i <= latest; i++ {
			path := campaignAttemptDir(dir, batch.Number, i)
			challengePath := filepath.Join(path, "challenge.json")
			grantPath := filepath.Join(path, "grant.json")
			receiptPath := filepath.Join(path, "receipt.json")
			if _, err := os.Lstat(receiptPath); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return nil, err
			}
			ch, err := readSignedFieldChallenge(challengePath)
			if err != nil {
				return nil, err
			}
			if err := validateCampaignChallenge(dir, m, batch, ch, ca); err != nil {
				return nil, fmt.Errorf("campaign batch %d invalid challenge: %w", batch.Number, err)
			}
			result, err := verifyFieldPair(challengePath, grantPath, receiptPath, ca)
			if err != nil {
				return nil, fmt.Errorf("batch %d attempt %d: %w", batch.Number, i, err)
			}
			r := map[string]any{"batch": batch.Number, "attempt": i, "run_id": ch.Challenge.RunID,
				"receiver_status": result["receiver_status"], "observed": result["peer_authenticated_received"]}
			if _, err := os.Lstat(filepath.Join(path, "sender.json")); err == nil {
				sender, err := verifySenderEvidence(filepath.Join(path, "sender.json"), ch.Challenge, ca)
				if err != nil {
					return nil, fmt.Errorf("invalid sender evidence: %w", err)
				}
				r["sender_evidence"] = sender
			} else if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			runs = append(runs, r)
			if result["receiver_status"] != "" && result["receiver_status"] != "COMPLETE" {
				partial++
				continue
			}
			if sender, ok := r["sender_evidence"].(map[string]any); !ok ||
				sender["status"] != "COMPLETE" || sender["syscalls_succeeded"] != len(ch.Challenge.Samples) {
				partial++
				continue
			}
			batchComplete = true
			for _, entry := range result["per_source"].([]fieldSourceObservation) {
				t := byKey[candidateIdentity(entry.Candidate)]
				t.Planned += entry.PlannedSamples
				t.PeerObserved += entry.AuthenticatedPeerObservations
				t.ExactSource += entry.ExactSourceObserved
				t.RewrittenSource += entry.RewrittenSourceObserved
				t.CompletedRuns++
			}
		}
		if batchComplete {
			completed++
		} else {
			pending++
		}
	}
	out := make([]campaignSourceTotal, 0, len(byKey))
	for _, value := range byKey {
		out = append(out, *value)
	}
	sort.Slice(out, func(i, j int) bool {
		// Untested/pending IPs last, never infer a blocked path from absence.
		if (out[i].Planned > 0) != (out[j].Planned > 0) {
			return out[i].Planned > 0
		}
		if out[i].Planned > 0 && out[j].Planned > 0 {
			a := out[i].ExactSource * out[j].Planned
			b := out[j].ExactSource * out[i].Planned
			if a != b {
				return a > b
			}
		}
		return out[i].Candidate.IP < out[j].Candidate.IP
	})
	return map[string]any{"campaign_id": m.CampaignID, "direction": m.Direction,
		"destination_ip": m.DestinationIP, "transport": m.Transport,
		"source_count": m.SourceCount, "batch_count": len(m.Batches),
		"completed_batches": completed, "pending_batches": pending, "partial_signed_receipts": partial,
		"runs": runs, "sources_ordered_by_observation_fraction": out,
		"source_order_is_exploratory_not_a_reachability_guarantee": true,
		"ordering_not_evidence_of_return_or_tunnel":                true,
		"provider_source_acceptance":                               "NOT_INDEPENDENTLY_VERIFIED", "return_path": "NOT_TESTED",
		"private_l3": "NOT_TESTED", "network_calls_in_report": "NONE"}, nil
}

// A field challenge's direction is derived from authenticated peer roles,
// never accepted as a free-text alternative to the signed sender and receiver.
func (c fieldChallenge) Direction() string {
	d, _ := roleDirection(c.Sender, c.Receiver)
	return d
}

// A campaign may only advance from the originally selected immutable batch,
// never from a validly signed but different source set or endpoint. The signer
// signature is verified at creation time, permitting archival checks later.
func validateCampaignChallenge(dir string, m campaignManifest, batch campaignBatch, env signedFieldChallenge, ca string) error {
	c := env.Challenge
	if c.Direction() != m.Direction || c.Sender != m.Sender || c.Receiver != m.Receiver ||
		c.DestinationIP != m.DestinationIP || c.Environment != m.Transport ||
		c.DataPort != m.DataPort || c.SamplesPerSource != m.SamplesPerSource ||
		len(c.Samples) != batch.Count*m.SamplesPerSource {
		return errors.New("campaign challenge settings/source count mismatch")
	}
	created, err := time.Parse(time.RFC3339Nano, c.CreatedUTC)
	if err != nil {
		return err
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		return err
	}
	if _, err := checkSignedFieldChallenge(env, roots, created, false); err != nil {
		return err
	}
	inv, err := readCandidates(filepath.Join(dir, batch.File))
	if err != nil {
		return err
	}
	if err := validateFieldSamples(c.Samples, inv, m.Sender, m.Receiver); err != nil {
		return err
	}
	seen := make(map[string]int)
	for _, sample := range c.Samples {
		if sample.Size != m.PacketSize || sample.Epoch != m.Epoch {
			return errors.New("campaign challenge packet/epoch mismatch")
		}
		seen[candidateIdentity(sample.Candidate)]++
	}
	if len(seen) != batch.Count {
		return errors.New("campaign challenge does not contain every selected IP")
	}
	for _, candidate := range inv.Candidates {
		if seen[candidateIdentity(candidate)] != m.SamplesPerSource {
			return errors.New("campaign source not repeated exact number of times")
		}
	}
	return nil
}

// One explicitly invoked send for ONE signed and independently granted
// campaign batch. It does not loop through the campaign, create B approval,
// retry a consumed session or bypass the field sender's permission checks.
func campaignSend(ctx context.Context, dir, cert, key, ca, iface string, providerApproved bool) (map[string]any, error) {
	return campaignMutate(dir, func() (map[string]any, error) {
		return campaignSendLocked(ctx, dir, cert, key, ca, iface, providerApproved)
	})
}

func campaignSendLocked(ctx context.Context, dir, cert, key, ca, iface string, providerApproved bool) (map[string]any, error) {
	m, err := readCampaign(dir)
	if err != nil {
		return nil, err
	}
	if err := requireCampaignActive(dir, m); err != nil {
		return nil, err
	}
	if cert == "" || key == "" || ca == "" {
		return nil, errors.New("campaign send requires A/B-role sender --cert --key --ca")
	}
	if m.Transport == "field_raw_ipv4" && (!providerApproved || iface == "") {
		return nil, errors.New("BLOCKED_BY_PERMISSION: raw campaign send needs separately verified Owner/provider permission, acknowledgement and selected interface")
	}
	for _, batch := range m.Batches {
		last, path, err := latestCampaignAttempt(dir, batch.Number)
		if err != nil {
			return nil, err
		}
		if last == 0 {
			return nil, errors.New("campaign has no signed next challenge; run campaign next first")
		}
		challengePath := filepath.Join(path, "challenge.json")
		ch, err := readSignedFieldChallenge(challengePath)
		if err != nil {
			return nil, err
		}
		if err := validateCampaignChallenge(dir, m, batch, ch, ca); err != nil {
			return nil, err
		}
		receiptPath := filepath.Join(path, "receipt.json")
		if _, err := os.Lstat(receiptPath); err == nil {
			result, err := verifyFieldPair(challengePath, filepath.Join(path, "grant.json"), receiptPath, ca)
			if err != nil {
				return nil, err
			}
			if result["receiver_status"] == "COMPLETE" || result["receiver_status"] == "" {
				senderPath := filepath.Join(path, "sender.json")
				if _, err := os.Lstat(senderPath); err == nil {
					summary, err := verifySenderEvidence(senderPath, ch.Challenge, ca)
					if err != nil {
						return nil, err
					}
					if summary["status"] == "COMPLETE" && summary["syscalls_succeeded"] == len(ch.Challenge.Samples) {
						continue
					}
				} else if !os.IsNotExist(err) {
					return nil, err
				}
				return campaignPendingSummary(m, batch, path, last, "RECEIVER_COMPLETE_SENDER_PROOF_MISSING_OR_PARTIAL"), nil
			}
			// A live receiver writes a signed IN_PROGRESS snapshot before
			// transmitting its signed ready artifact. That is not a reason
			// to refuse the first approved sender submission.
			if result["receiver_status"] != "IN_PROGRESS" {
				return campaignPendingSummary(m, batch, path, last, "PARTIAL_RECEIVER_RECEIPT_REQUIRES_REVIEW"), nil
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		grantPath := filepath.Join(path, "grant.json")
		if _, err := os.Lstat(grantPath); os.IsNotExist(err) {
			return campaignPendingSummary(m, batch, path, last, "WAITING_FOR_RECEIVER_SIGNED_GRANT"), nil
		} else if err != nil {
			return nil, err
		}
		readyPath := filepath.Join(path, "ready.json")
		if _, err := os.Lstat(readyPath); os.IsNotExist(err) {
			return campaignPendingSummary(m, batch, path, last, "WAITING_FOR_SIGNED_RECEIVER_READY"), nil
		} else if err != nil {
			return nil, err
		}
		signedGrant, err := readSignedFieldGrant(grantPath)
		if err != nil {
			return nil, err
		}
		if _, err := verifySignedFieldReady(readyPath, ch.Challenge, signedGrant, ca, time.Now()); err != nil {
			return nil, fmt.Errorf("campaign receiver readiness not valid: %w", err)
		}
		senderPath := filepath.Join(path, "sender.json")
		if _, err := os.Lstat(senderPath); err == nil {
			summary, err := verifySenderEvidence(senderPath, ch.Challenge, ca)
			if err != nil {
				return nil, err
			}
			return map[string]any{"status": "SENDER_ALREADY_ATTEMPTED_NO_AUTOMATIC_RETRY",
				"batch": batch.Number, "sender_evidence": summary}, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		return fieldSend(ctx, fieldOptions{File: filepath.Join(dir, batch.File),
			Cert: cert, Key: key, CA: ca, Sender: m.Sender, Receiver: m.Receiver,
			DestinationIP: m.DestinationIP, DataPort: m.DataPort, Challenge: challengePath, Grant: grantPath,
			Output: senderPath, ReadyFile: readyPath, Interface: iface, ProviderAuthorized: providerApproved})
	}
	return map[string]any{"status": "NO_PENDING_APPROVED_BATCH", "campaign_id": m.CampaignID}, nil
}
