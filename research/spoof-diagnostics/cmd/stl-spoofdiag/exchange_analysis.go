package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type exchangeInputList []string

func (l *exchangeInputList) String() string { return strings.Join(*l, ",") }
func (l *exchangeInputList) Set(v string) error {
	if v == "" {
		return errors.New("bundle file path cannot be blank")
	}
	*l = append(*l, v)
	return nil
}

func exchangeCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: exchange init|new-case|export|inspect|import|analyze (all offline)")
	}
	op := args[0]
	f := flag.NewFlagSet("exchange "+op, flag.ContinueOnError)
	base := f.String("base", exchangeDefaultBase, "private exchange root (0700)")
	id := f.String("case-id", "", "32-character case ID shared between directional campaigns")
	campaignDir := f.String("campaign-dir", "", "existing private campaign directory")
	role := f.String("role", "", "sender or receiver; signs only its own evidence")
	cert := f.String("cert", "", "local node public signing certificate")
	key := f.String("key", "", "local node signing private key; never packed")
	ca := f.String("ca", "", "trusted public CA certificate (never extracted from input)")
	out := f.String("out", "", "new output ZIP; defaults to outbox/bundle-name")
	inbox := f.String("inbox", "", "inbox directory to discover bundles, independent of file names")
	reports := f.String("reports", "", "private report directory; defaults to base/reports")
	var paths exchangeInputList
	f.Var(&paths, "file", "portable bundle path; repeat in any order (1..4 or more)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	switch op {
	case "init":
		if err := exchangeCreateBase(*base); err != nil {
			return err
		}
		return pretty(map[string]string{"status": "PRIVATE_EXCHANGE_READY_NO_NETWORK", "base": *base})
	case "new-case":
		if *id != "" {
			return errors.New("new-case generates a new random ID; omit --case-id")
		}
		r, err := randomHex(16)
		if err != nil {
			return err
		}
		return pretty(map[string]string{"case_id": r, "status": "OPERATOR_CASE_LABEL_ONLY",
			"note": "transfer Case ID securely by operator; this is not independent peer authorization"})
	case "export":
		if *id == "" || *campaignDir == "" || *role == "" || *cert == "" || *key == "" || *ca == "" {
			return errors.New("export requires --case-id --campaign-dir --role --cert --key --ca")
		}
		m, err := readCampaign(*campaignDir)
		if err != nil {
			return err
		}
		node, _, err := exchangeSlot(m.Direction, *role)
		if err != nil {
			return err
		}
		if *out == "" {
			*out = filepath.Join(*base, "outbox", exchangeBundleName(exchangeManifest{
				CaseID: *id, Direction: m.Direction, Node: node, Role: *role,
			}))
		}
		b, err := exchangeSignBundle(*id, *campaignDir, *role, *cert, *key, *ca, *out)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "SIGNED_OFFLINE_BUNDLE_EXPORTED_NO_NETWORK",
			"case_id": b.CaseID, "direction": b.Direction, "node": b.Node, "role": b.Role,
			"file": *out, "files": len(b.Files), "runtime_case_binding": "POST_RUN_EXPORT_ONLY"})
	case "inspect":
		if len(paths) != 1 || *ca == "" {
			return errors.New("inspect requires exactly one --file and --ca")
		}
		bundle, err := exchangeOpenBundle(paths[0], *ca)
		if err != nil {
			return err
		}
		if err := exchangeValidateBundleContent(bundle, *ca); err != nil {
			return err
		}
		return pretty(map[string]any{"status": "SIGNED_ARCHIVE_AND_PRESENT_RUN_PROOFS_VALIDATED",
			"manifest": bundle.Manifest, "sha256": bundle.Digest,
			"missing_run_evidence": "may exist; use analyze for completeness",
			"network_calls":        "NONE"})
	case "import":
		if *ca == "" {
			return errors.New("import requires --ca")
		}
		found := []string(paths)
		if *inbox != "" || len(found) == 0 {
			where := *inbox
			if where == "" {
				where = filepath.Join(*base, "inbox")
			}
			discovered, err := exchangeDiscoverFiles(where)
			if err != nil {
				return err
			}
			found = append(found, discovered...)
		}
		sort.Strings(found)
		result, err := exchangeImport(*base, *ca, found, *id)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "EXPLICIT_IMPORT_COMPLETED_NO_NETWORK", "inputs": result,
			"note": "inbox files left unchanged; verified copies archived; invalid copies quarantined as data only"})
	case "analyze":
		if *ca == "" || !exchangeIDPattern.MatchString(*id) {
			return errors.New("analyze requires --case-id and --ca")
		}
		found := []string(paths)
		if *inbox != "" || len(found) == 0 {
			where := *inbox
			if where == "" {
				where = filepath.Join(*base, "inbox")
			}
			discovered, err := exchangeDiscoverFiles(where)
			if err != nil {
				return err
			}
			found = append(found, discovered...)
		}
		if *reports == "" {
			*reports = filepath.Join(*base, "reports")
		}
		r, err := exchangeAnalyze(*id, *ca, found)
		if err != nil {
			return err
		}
		if err := exchangeSaveReports(*reports, r); err != nil {
			return err
		}
		return pretty(map[string]any{"case_id": r.CaseID, "status": r.Status,
			"missing_slots": r.MissingSlots, "conflicts": r.Conflicts,
			"reports": *reports, "received_bundle_count": len(r.Inputs),
			"network_calls": "NONE"})
	default:
		return errors.New("usage: exchange init|new-case|export|inspect|import|analyze")
	}
}

// Filenames have no authority: every regular inbox entry is evaluated using
// its internal authenticated manifest, regardless of name or extension.
func exchangeDiscoverFiles(dir string) ([]string, error) {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("inbox must be an existing private directory (0700)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > exchangeMaxEntries {
		return nil, errors.New("inbox contains too many files")
	}
	result := []string{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("inbox has nonregular/symlink entry: %q", entry.Name())
		}
		result = append(result, filepath.Join(dir, entry.Name()))
	}
	sort.Strings(result)
	return result, nil
}

func exchangeStageFiles(root string, files map[string][]byte) error {
	for name, content := range files {
		if !exchangeValidPath(name, "sender") && !exchangeValidPath(name, "receiver") {
			return fmt.Errorf("unsafe staged path %q", name)
		}
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err := f.Write(content); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func exchangeValidateBundleContent(b *exchangeBundle, ca string) error {
	// The ZIP never dictates a destination path: only the fixed set of JSON
	// evidence paths can be created under an exclusive temporary 0700 root.
	root, err := os.MkdirTemp("", "spoofdiag-exchange-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	if err := exchangeStageFiles(root, b.Files); err != nil {
		return err
	}
	m, err := readCampaign(root)
	if err != nil {
		return err
	}
	if m.CampaignID != b.Manifest.CampaignID || m.Direction != b.Manifest.Direction {
		return errors.New("immutable campaign does not match signed bundle")
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		return err
	}
	// Each individual present sender/receiver proof is validated against its
	// signed challenge and grant, not just against ZIP entry checksums.
	for _, batch := range m.Batches {
		last, _, err := latestCampaignAttempt(root, batch.Number)
		if err != nil {
			return err
		}
		for attempt := 1; attempt <= last; attempt++ {
			runPath := campaignAttemptDir(root, batch.Number, attempt)
			chPath := filepath.Join(runPath, "challenge.json")
			if _, err := os.Lstat(chPath); os.IsNotExist(err) {
				return errors.New("run proof without an independently verifiable signed challenge")
			} else if err != nil {
				return err
			}
			ch, err := readSignedFieldChallenge(chPath)
			if err != nil {
				return err
			}
			if err := validateCampaignChallenge(root, m, batch, ch, ca); err != nil {
				return err
			}
			gPath := filepath.Join(runPath, "grant.json")
			if _, err := os.Lstat(gPath); err == nil {
				grant, err := readSignedFieldGrant(gPath)
				if err != nil {
					return err
				}
				when, err := time.Parse(time.RFC3339Nano, grant.Grant.CreatedUTC)
				if err != nil {
					return err
				}
				if err := checkFieldGrant(grant, ch.Challenge, roots, when, false); err != nil {
					return err
				}
			} else if !os.IsNotExist(err) {
				return err
			}
			proofName := "sender.json"
			if b.Manifest.Role == "receiver" {
				proofName = "receipt.json"
			}
			proof := filepath.Join(runPath, proofName)
			if _, err := os.Lstat(proof); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return err
			}
			if b.Manifest.Role == "sender" {
				if _, err := verifySenderEvidence(proof, ch.Challenge, ca); err != nil {
					return err
				}
			} else {
				if _, err := os.Lstat(gPath); os.IsNotExist(err) {
					return errors.New("receiver receipt supplied without signed grant; cannot authenticate observed samples")
				} else if err != nil {
					return err
				}
				if _, err := verifyFieldPair(chPath, gPath, proof, ca); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type exchangeProvenance struct {
	Slot                     string `json:"slot"`
	SHA256                   string `json:"sha256"`
	CampaignID               string `json:"campaign_id"`
	Files                    int    `json:"files"`
	SignedManifestSHA256     string `json:"signed_manifest_sha256"`
	SigningCertificateSHA256 string `json:"signing_certificate_sha256"`
}

type exchangeSourceResult struct {
	Direction                string `json:"direction"`
	CampaignID               string `json:"campaign_id"`
	SourceIP                 string `json:"source_ip"`
	Planned                  int    `json:"planned"`
	Submitted                int    `json:"submitted_syscalls"`
	ObservedWithSubmitted    int    `json:"observed_with_submitted_syscall"`
	ObservedWithoutSubmitted int    `json:"observed_without_submitted_syscall"`
	AttemptedUnknown         int    `json:"attempted_unknown"`
	Failed                   int    `json:"failed_syscalls"`
	Observed                 int    `json:"receiver_authenticated_observations"`
	SourceMatched            int    `json:"source_matched"`
	SourceRewritten          int    `json:"source_rewritten"`
}

type exchangeDirectionReport struct {
	Direction  string                 `json:"direction"`
	CampaignID string                 `json:"campaign_id,omitempty"`
	Status     string                 `json:"status"`
	Runs       []exchangeRunResult    `json:"runs"`
	Sources    []exchangeSourceResult `json:"sources"`
}

type exchangeSampleResult struct {
	Index         int    `json:"index"`
	SourceIP      string `json:"source_ip"`
	SenderState   string `json:"sender_state"`
	ReceiverState string `json:"receiver_state"`
	ActualSource  string `json:"actual_source,omitempty"`
	SourceMatched bool   `json:"source_matched,omitempty"`
}

type exchangeRunResult struct {
	Batch                    int                    `json:"batch"`
	Attempt                  int                    `json:"attempt"`
	RunID                    string                 `json:"run_id,omitempty"`
	Status                   string                 `json:"status"`
	Sender                   string                 `json:"sender_evidence"`
	Receiver                 string                 `json:"receiver_evidence"`
	Planned                  int                    `json:"planned_samples"`
	Submitted                int                    `json:"submitted_syscalls"`
	Observed                 int                    `json:"peer_observed_samples"`
	ObservedWithoutSubmitted int                    `json:"observed_without_submitted_syscall"`
	Samples                  []exchangeSampleResult `json:"samples"`
}

type exchangeCaseReport struct {
	Format                string                    `json:"format"`
	TrustAnchorFileSHA256 string                    `json:"trust_anchor_file_sha256"`
	CaseID                string                    `json:"case_id"`
	Status                string                    `json:"status"`
	Inputs                []exchangeProvenance      `json:"inputs"`
	MissingSlots          []string                  `json:"missing_slots"`
	Conflicts             []string                  `json:"conflicts"`
	Rejected              []string                  `json:"rejected_inputs"`
	Directions            []exchangeDirectionReport `json:"directions"`
	Limitations           []string                  `json:"limitations"`
}

func exchangeSlotID(direction, role string) string { return direction + "/" + role }

func exchangeAnalyze(caseID, ca string, sources []string) (exchangeCaseReport, error) {
	report := exchangeCaseReport{Format: exchangeFormat, CaseID: caseID, Status: "INCOMPLETE",
		Inputs: []exchangeProvenance{}, MissingSlots: []string{}, Conflicts: []string{},
		Rejected: []string{}, Directions: []exchangeDirectionReport{},
		Limitations: []string{
			"POST_RUN_CASE_ASSOCIATION: Case ID was signed on export, not inside legacy challenge/grant.",
			"SENDER_SUBMITTED: successful syscall is not independent physical NIC or provider egress proof.",
			"OBSERVED_WITHOUT_SUBMITTED: signed declarations disagree or sender evidence is missing; source and timing require independent review.",
			"RECEIVER_OBSERVED: peer signed a declaration, not independent NIC capture.",
			"ABSENCE_INCONCLUSIVE: missing observation cannot establish packet loss or source blocking.",
			"TWO_ONE_WAY_OBSERVATIONS_DO_NOT_PROVE_SAME_FLOW_RETURN_PATH",
			"PROVIDER_PERMISSION_AND_PRIVATE_L3_NOT_TESTED",
		}}
	if !exchangeIDPattern.MatchString(caseID) {
		return report, errors.New("case ID must be 32 lowercase hexadecimal characters")
	}
	if _, err := certificateRoots(ca); err != nil {
		return report, err
	}
	caBytes, err := readSmallRegular(ca, 16384)
	if err != nil {
		return report, err
	}
	report.TrustAnchorFileSHA256 = exchangeSHA(caBytes)
	sources = append([]string(nil), sources...)
	sort.Strings(sources) // discovery and supplied order cannot affect results
	bundles := map[string]*exchangeBundle{}
	conflicted := map[string]bool{}
	for _, filename := range sources {
		b, err := exchangeOpenBundle(filename, ca)
		if err != nil {
			report.Rejected = append(report.Rejected, filepath.Base(filename)+": "+err.Error())
			continue
		}
		if b.Manifest.CaseID != caseID {
			// The inbox may contain archived or unrelated cases.
			continue
		}
		if err := exchangeValidateBundleContent(b, ca); err != nil {
			report.Rejected = append(report.Rejected, filepath.Base(filename)+": "+err.Error())
			continue
		}
		slot := exchangeSlotID(b.Manifest.Direction, b.Manifest.Role)
		if conflicted[slot] {
			continue
		}
		if previous, ok := bundles[slot]; ok {
			if previous.Identity != b.Identity {
				report.Conflicts = append(report.Conflicts, slot+": distinct authenticated manifests for the same logical slot")
				delete(bundles, slot)
				conflicted[slot] = true
			} else if b.Digest < previous.Digest {
				// Equivalent signed content, alternative ZIP packaging.
				bundles[slot] = b
			}
			continue
		}
		bundles[slot] = b
	}
	for _, direction := range []string{"A_TO_B", "B_TO_A"} {
		for _, role := range []string{"sender", "receiver"} {
			slot := exchangeSlotID(direction, role)
			if _, found := bundles[slot]; !found {
				report.MissingSlots = append(report.MissingSlots, slot)
			}
		}
		dr, err := exchangeAnalyzeDirection(direction, bundles[exchangeSlotID(direction, "sender")],
			bundles[exchangeSlotID(direction, "receiver")], ca)
		if err != nil {
			report.Conflicts = append(report.Conflicts, direction+": "+err.Error())
			dr.Status = "CONFLICT"
		}
		report.Directions = append(report.Directions, dr)
	}
	if report.Directions[0].CampaignID != "" && report.Directions[0].CampaignID == report.Directions[1].CampaignID {
		report.Conflicts = append(report.Conflicts, "two directions must use independently scoped Campaign IDs")
	}
	allRuns := make(map[string]string)
	for _, dir := range report.Directions {
		for _, run := range dir.Runs {
			if run.RunID == "" {
				continue
			}
			if earlier, exists := allRuns[run.RunID]; exists {
				report.Conflicts = append(report.Conflicts, "reused signed Run ID across "+earlier+" and "+dir.Direction)
			} else {
				allRuns[run.RunID] = dir.Direction
			}
		}
	}
	for _, slot := range []string{"A_TO_B/sender", "A_TO_B/receiver", "B_TO_A/sender", "B_TO_A/receiver"} {
		if b := bundles[slot]; b != nil {
			report.Inputs = append(report.Inputs, exchangeProvenance{
				Slot: slot, SHA256: b.Digest, CampaignID: b.Manifest.CampaignID, Files: len(b.Files),
				SignedManifestSHA256: b.Identity, SigningCertificateSHA256: b.SignerSHA256})
		}
	}
	if len(report.MissingSlots) == 0 && len(report.Conflicts) == 0 && len(report.Rejected) == 0 {
		allComplete := true
		for _, dir := range report.Directions {
			if dir.Status != "COMPLETE_SIGNED_EVIDENCE" {
				allComplete = false
			}
		}
		if allComplete {
			report.Status = "COMPLETE_SIGNED_EVIDENCE_NOT_CONNECTIVITY_PROOF"
		}
	}
	return report, nil
}

func exchangeAnalyzeDirection(direction string, sender, receiver *exchangeBundle, ca string) (exchangeDirectionReport, error) {
	dr := exchangeDirectionReport{Direction: direction, Status: "INCOMPLETE",
		Runs: []exchangeRunResult{}, Sources: []exchangeSourceResult{}}
	if sender == nil || receiver == nil {
		return dr, nil
	}
	if sender.Manifest.CampaignID != receiver.Manifest.CampaignID ||
		sender.Manifest.CampaignSHA256 != receiver.Manifest.CampaignSHA256 {
		return dr, errors.New("opposite endpoint bundles refer to different immutable campaigns")
	}
	dr.CampaignID = sender.Manifest.CampaignID
	combined := make(map[string][]byte, len(sender.Files)+len(receiver.Files))
	for _, b := range []*exchangeBundle{sender, receiver} {
		for name, data := range b.Files {
			if previous, ok := combined[name]; ok && !bytes.Equal(previous, data) {
				return dr, fmt.Errorf("conflicting %s in two independently signed bundles", name)
			}
			combined[name] = data
		}
	}
	root, err := os.MkdirTemp("", "spoofdiag-case-compare-*")
	if err != nil {
		return dr, err
	}
	defer os.RemoveAll(root)
	if err := exchangeStageFiles(root, combined); err != nil {
		return dr, err
	}
	m, err := readCampaign(root)
	if err != nil {
		return dr, err
	}
	byIP := make(map[string]*exchangeSourceResult)
	for _, batch := range m.Batches {
		inv, err := readCandidates(filepath.Join(root, filepath.FromSlash(batch.File)))
		if err != nil {
			return dr, err
		}
		for _, c := range inv.Candidates {
			if _, has := byIP[c.IP]; !has {
				byIP[c.IP] = &exchangeSourceResult{Direction: direction, CampaignID: m.CampaignID, SourceIP: c.IP}
			}
		}
	}
	completedBatches := 0
	anyDiscrepancy := false
	seenRunID := make(map[string]bool)
	for _, batch := range m.Batches {
		last, _, err := latestCampaignAttempt(root, batch.Number)
		if err != nil {
			return dr, err
		}
		batchComplete := false
		for attempt := 1; attempt <= last; attempt++ {
			p := campaignAttemptDir(root, batch.Number, attempt)
			run := exchangeRunResult{Batch: batch.Number, Attempt: attempt, Status: "INCOMPLETE",
				Sender: "MISSING", Receiver: "MISSING"}
			chPath := filepath.Join(p, "challenge.json")
			if _, err := os.Lstat(chPath); os.IsNotExist(err) {
				dr.Runs = append(dr.Runs, run)
				continue
			} else if err != nil {
				return dr, err
			}
			ch, err := readSignedFieldChallenge(chPath)
			if err != nil {
				return dr, err
			}
			if err := validateCampaignChallenge(root, m, batch, ch, ca); err != nil {
				return dr, fmt.Errorf("invalid challenge in batch %d attempt %d: %w", batch.Number, attempt, err)
			}
			if seenRunID[ch.Challenge.RunID] {
				return dr, errors.New("run ID reused across campaign attempts")
			}
			seenRunID[ch.Challenge.RunID] = true
			run.RunID, run.Planned = ch.Challenge.RunID, len(ch.Challenge.Samples)
			run.Samples = make([]exchangeSampleResult, len(ch.Challenge.Samples))
			for i, sample := range ch.Challenge.Samples {
				run.Samples[i] = exchangeSampleResult{Index: i, SourceIP: sample.Candidate.IP,
					SenderState: "NO_DECLARED_ATTEMPT", ReceiverState: "NOT_OBSERVED"}
			}
			senderPath := filepath.Join(p, "sender.json")
			if _, err := os.Lstat(senderPath); err == nil {
				if _, err := verifySenderEvidence(senderPath, ch.Challenge, ca); err != nil {
					return dr, err
				}
				b, err := readSmallRegular(senderPath, fieldMaxControl)
				if err != nil {
					return dr, err
				}
				var s signedFieldSenderEvidence
				if err := strictJSON(b, &s); err != nil {
					return dr, err
				}
				run.Sender = s.Evidence.Status
				for _, record := range s.Evidence.Records {
					run.Samples[record.Index].SenderState = record.State
					k := ch.Challenge.Samples[record.Index].Candidate.IP
					switch record.State {
					case "SUBMITTED":
						run.Submitted++
						byIP[k].Submitted++
					case "FAILED":
						byIP[k].Failed++
					case "ATTEMPTED_UNKNOWN":
						byIP[k].AttemptedUnknown++
					}
				}
			} else if !os.IsNotExist(err) {
				return dr, err
			}
			receiptPath := filepath.Join(p, "receipt.json")
			grantPath := filepath.Join(p, "grant.json")
			if _, err := os.Lstat(receiptPath); err == nil {
				if _, err := os.Stat(grantPath); os.IsNotExist(err) {
					run.Receiver = "UNVERIFIABLE_WITHOUT_GRANT"
				} else if err != nil {
					return dr, err
				} else {
					verified, err := verifyFieldPair(chPath, grantPath, receiptPath, ca)
					if err != nil {
						return dr, err
					}
					run.Receiver, _ = verified["receiver_status"].(string)
					if run.Receiver == "" {
						run.Receiver = "LEGACY_STATUS_UNDECLARED"
					}
					receiptData, err := readSmallRegular(receiptPath, fieldMaxControl)
					if err != nil {
						return dr, err
					}
					var signed fieldEnvelope
					if err := strictJSON(receiptData, &signed); err != nil {
						return dr, err
					}
					run.Observed = len(signed.Receipt.Observations)
					for _, obs := range signed.Receipt.Observations {
						run.Samples[obs.Index].ReceiverState = "AUTHENTICATED_OBSERVED"
						run.Samples[obs.Index].ActualSource = obs.ActualPacketSource
						run.Samples[obs.Index].SourceMatched = obs.SourceMatched
						a := byIP[obs.SourceCandidate]
						a.Observed++
						if obs.SourceMatched {
							a.SourceMatched++
						} else {
							a.SourceRewritten++
						}
					}
				}
			} else if !os.IsNotExist(err) {
				return dr, err
			}
			for _, sample := range ch.Challenge.Samples {
				byIP[sample.Candidate.IP].Planned++
			}
			for _, sample := range run.Samples {
				if sample.ReceiverState != "AUTHENTICATED_OBSERVED" {
					continue
				}
				if sample.SenderState == "SUBMITTED" {
					byIP[sample.SourceIP].ObservedWithSubmitted++
				} else {
					byIP[sample.SourceIP].ObservedWithoutSubmitted++
					run.ObservedWithoutSubmitted++
					anyDiscrepancy = true
				}
			}
			if run.Sender == "COMPLETE" && (run.Receiver == "COMPLETE" || run.Receiver == "LEGACY_STATUS_UNDECLARED") {
				run.Status = "COMPLETE_SIGNED_EVIDENCE_NOT_NETWORK_PROOF"
				batchComplete = true
			}
			if run.ObservedWithoutSubmitted > 0 {
				run.Status = "UNPAIRED_OBSERVATION_NEEDS_REVIEW"
			}
			dr.Runs = append(dr.Runs, run)
		}
		if batchComplete {
			completedBatches++
		}
	}
	for _, v := range byIP {
		dr.Sources = append(dr.Sources, *v)
	}
	sort.Slice(dr.Sources, func(i, j int) bool {
		return dr.Sources[i].SourceIP < dr.Sources[j].SourceIP
	})
	if completedBatches == len(m.Batches) && !anyDiscrepancy {
		dr.Status = "COMPLETE_SIGNED_EVIDENCE"
	}
	return dr, nil
}

func exchangeSanitizeCSV(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@\t\r\n") {
		return "'" + s
	}
	return s
}

func exchangeSaveReports(dir string, report exchangeCaseReport) error {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("report directory must exist and be private (0700)")
	}
	prefix := "SDX-" + report.CaseID
	targets := []string{filepath.Join(dir, prefix+"-verified.json"),
		filepath.Join(dir, prefix+"-results.csv"), filepath.Join(dir, prefix+"-final.html")}
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	jsonData = append(jsonData, '\n')
	var csvBuf bytes.Buffer
	writer := csv.NewWriter(&csvBuf)
	if err := writer.Write([]string{"direction", "campaign_id", "source_ip", "planned", "submitted_syscalls",
		"attempted_unknown", "failed_syscalls", "receiver_observed", "source_matched", "source_rewritten"}); err != nil {
		return err
	}
	for _, d := range report.Directions {
		for _, s := range d.Sources {
			row := []string{s.Direction, s.CampaignID, s.SourceIP, fmt.Sprint(s.Planned), fmt.Sprint(s.Submitted),
				fmt.Sprint(s.AttemptedUnknown), fmt.Sprint(s.Failed), fmt.Sprint(s.Observed),
				fmt.Sprint(s.SourceMatched), fmt.Sprint(s.SourceRewritten)}
			for i := range row {
				row[i] = exchangeSanitizeCSV(row[i])
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	const htmlBody = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>SDX {{.CaseID}}</title>
<style>body{font:16px system-ui,sans-serif;max-width:1024px;margin:2rem auto;padding:0 1rem;line-height:1.5}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #aaa;padding:.35rem;text-align:left}
small{color:#555}th{background:#eef}code{overflow-wrap:anywhere}</style></head>
<body><h1>Offline signed evidence: <code>{{.CaseID}}</code></h1><p><strong>{{.Status}}</strong></p>
<p>Packet receipt is not proof of physical egress, provider permission, return path or a private L3 tunnel.</p>
<h2>Four authenticated roles</h2><table><tr><th>Slot</th><th>ZIP SHA-256</th><th>Campaign</th></tr>
{{range .Inputs}}<tr><td>{{.Slot}}</td><td><code>{{.SHA256}}</code></td><td>{{.CampaignID}}</td></tr>{{end}}</table>
<h2>Missing slots</h2><p>{{range .MissingSlots}}{{.}}; {{else}}None{{end}}</p>
<h2>Conflicts / rejected</h2><p>{{range .Conflicts}}{{.}}; {{end}}{{range .Rejected}}{{.}}; {{end}}</p>
{{range .Directions}}<h2>{{.Direction}} — {{.Status}}</h2>
<table><tr><th>Source IP</th><th>Planned</th><th>Submitted syscall</th><th>Authenticated peer observed</th><th>Exact source</th></tr>
{{range .Sources}}<tr><td>{{.SourceIP}}</td><td>{{.Planned}}</td><td>{{.Submitted}}</td><td>{{.Observed}}</td><td>{{.SourceMatched}}</td></tr>{{end}}</table>{{end}}
<h2>Evidence limits</h2><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
<small>This report is reproducible from the four immutable signed bundles and the trusted CA public certificate.</small>
</body></html>`
	page := template.Must(template.New("case").Parse(htmlBody))
	var html bytes.Buffer
	if err := page.Execute(&html, report); err != nil {
		return err
	}
	// Compute all outputs first; verify prior output identity before creating
	// any of them. Repeating an identical analysis repairs interrupted
	// multi-file publication without ever replacing different user content.
	contents := [][]byte{jsonData, csvBuf.Bytes(), html.Bytes()}
	for i, target := range targets {
		if st, err := os.Lstat(target); err == nil {
			if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("unsafe existing report %s", target)
			}
			existing, err := readSmallRegular(target, exchangeMaxTotal)
			if err != nil || !bytes.Equal(existing, contents[i]) {
				return fmt.Errorf("refusing to change conflicting existing report %s", target)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for i, target := range targets {
		if _, err := os.Lstat(target); os.IsNotExist(err) {
			if err := exchangeWriteNew(target, contents[i]); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

func exchangeWriteNew(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".sdx-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), path); err != nil {
		return err
	}
	if df, err := os.Open(dir); err == nil {
		defer df.Close()
		if err := df.Sync(); err != nil {
			return err
		}
	}
	return nil
}
