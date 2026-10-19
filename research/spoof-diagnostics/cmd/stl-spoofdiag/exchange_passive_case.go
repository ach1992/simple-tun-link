package main

// Stage-3 report for one independently executed run in each direction.
// The six raw input files are supplied via manual operator handoff, not
// through any A/B control channel. Only verified signed endpoint evidence
// contributes observation fields; untested campaign batches stay unknown.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type passiveInputFile struct {
	Slot   string `json:"slot"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

func passiveCaseDirection(direction, challenge, capture, sender, ca string) (exchangeDirectionReport, string, string, error) {
	empty := exchangeDirectionReport{Direction: direction, Status: "INCOMPLETE"}
	if challenge == "" || capture == "" || sender == "" {
		return empty, "", "", errors.New("stage-3 case requires signed sender plan, signed sender evidence and passive receiver capture for each direction")
	}
	ch, err := readSignedFieldChallenge(challenge)
	if err != nil {
		return empty, "", "", err
	}
	realDirection, err := roleDirection(ch.Challenge.Sender, ch.Challenge.Receiver)
	if err != nil || realDirection != direction {
		return empty, "", "", errors.New("signed challenge role/direction mismatch")
	}
	correlated, err := correlatePassive(challenge, capture, sender, ca)
	if err != nil {
		return empty, "", "", err
	}
	// correlatePassive verifies both signed run/capture proofs and the public CA.
	senderRaw, err := readSmallRegular(sender, fieldMaxControl)
	if err != nil {
		return empty, "", "", err
	}
	var signed signedFieldSenderEvidence
	if err := strictJSON(senderRaw, &signed); err != nil {
		return empty, "", "", err
	}
	run := exchangeRunResult{Batch: 1, Attempt: 1, RunID: ch.Challenge.RunID,
		Status: "SIGNED_PER_RUN_EVIDENCE_NOT_RETURN_PROOF", Sender: signed.Evidence.Status,
		Receiver: fmt.Sprint(correlated["receiver_capture_status"]),
		Planned:  len(ch.Challenge.Samples),
		Samples:  make([]exchangeSampleResult, len(ch.Challenge.Samples))}
	bySource := map[string]*exchangeSourceResult{}
	for i, sample := range ch.Challenge.Samples {
		ip := sample.Candidate.IP
		row := bySource[ip]
		if row == nil {
			row = &exchangeSourceResult{Direction: direction, SourceIP: ip}
			bySource[ip] = row
		}
		row.Planned++
		run.Samples[i] = exchangeSampleResult{Index: i, SourceIP: ip,
			SenderState: "NO_DECLARED_ATTEMPT", ReceiverState: "NOT_OBSERVED"}
	}
	for _, record := range signed.Evidence.Records {
		if record.Index < 0 || record.Index >= len(run.Samples) {
			return empty, "", "", errors.New("sender record index outside signed plan")
		}
		s := &run.Samples[record.Index]
		s.SenderState = record.State
		row := bySource[s.SourceIP]
		switch record.State {
		case "SUBMITTED":
			row.Submitted++
			run.Submitted++
		case "FAILED":
			row.Failed++
		case "ATTEMPTED_UNKNOWN":
			row.AttemptedUnknown++
		default:
			return empty, "", "", errors.New("unsupported signed sender state")
		}
	}
	v, ok := correlated["observations"].([]map[string]any)
	if !ok {
		return empty, "", "", errors.New("invalid correlation output")
	}
	for _, item := range v {
		index, ok := item["sample_index"].(int)
		if !ok || index < 0 || index >= len(run.Samples) {
			return empty, "", "", errors.New("correlated observation index mismatch")
		}
		s := &run.Samples[index]
		s.ReceiverState = "AUTHENTICATED_OBSERVED"
		s.ActualSource, _ = item["actual_observed_source_ip"].(string)
		s.SourceMatched, _ = item["source_matched"].(bool)
		row := bySource[s.SourceIP]
		row.Observed++
		run.Observed++
		if s.SourceMatched {
			row.SourceMatched++
		} else {
			row.SourceRewritten++
		}
		if s.SenderState == "SUBMITTED" {
			row.ObservedWithSubmitted++
		} else {
			row.ObservedWithoutSubmitted++
			run.ObservedWithoutSubmitted++
		}
	}
	report := exchangeDirectionReport{Direction: direction, Status: "SIGNED_BOUNDED_RUN_NOT_CONNECTIVITY_PROOF",
		Runs: []exchangeRunResult{run}, Sources: []exchangeSourceResult{}}
	for _, item := range bySource {
		report.Sources = append(report.Sources, *item)
	}
	sort.Slice(report.Sources, func(i, j int) bool { return report.Sources[i].SourceIP < report.Sources[j].SourceIP })
	if run.Sender != "COMPLETE" || run.Receiver != "COMPLETE" || run.ObservedWithoutSubmitted > 0 {
		report.Status = "PARTIAL_OR_DISCREPANT_SIGNED_EVIDENCE"
	}
	return report, ch.Challenge.RunID, fmt.Sprint(correlated["capture_id"]), nil
}

func passiveCaseAnalyze(caseID, ca, reports string,
	abPlan, abSender, abCapture, baPlan, baSender, baCapture string) (exchangeCaseReport, error) {
	report := exchangeCaseReport{Format: "sdx-disconnected-passive-case-v1",
		CaseID: caseID, Status: "INCOMPLETE",
		Inputs: []exchangeProvenance{}, MissingSlots: []string{}, Conflicts: []string{},
		Rejected: []string{}, Directions: []exchangeDirectionReport{},
		Limitations: []string{
			"NO_LIVE_A_B_CONTROL_CHANNEL: both endpoints performed independent local runs.",
			"POST_RUN_OPERATOR_CASE_ASSOCIATION: Case ID labels validated files; it was not signed into original packets.",
			"PER_RUN_ONLY: this report covers one signed Run per direction; no unprovided campaign batches are assumed tested.",
			"OBSERVATIONS_SIGNED_BY_RECEIVER: claims of local UDP socket readings are not independent NIC/provider proof.",
			"SENDER_SUBMITTED_IS_ONLY_A_SYSCALL_DECLARATION",
			"ABSENCE_IS_INCONCLUSIVE_NOT_PROVEN_PACKET_LOSS_OR_FILTERING",
			"TWO_ONE_WAY_OBSERVATIONS_DO_NOT_PROVE_SAME_FLOW_RETURN_PATH",
			"PUBLIC_SOURCE_RIGHTS_AND_PRIVATE_L3_ARE_NOT_ESTABLISHED",
		}}
	if !exchangeIDPattern.MatchString(caseID) {
		return report, errors.New("case-id must be 32 lowercase hexadecimal digits")
	}
	if _, err := certificateRoots(ca); err != nil {
		return report, err
	}
	bytes, err := readSmallRegular(ca, 16384)
	if err != nil {
		return report, err
	}
	report.TrustAnchorFileSHA256 = digestBytes(bytes)
	locations := []struct{ dir, plan, sender, capture string }{
		{"A_TO_B", abPlan, abSender, abCapture},
		{"B_TO_A", baPlan, baSender, baCapture}}
	ids := map[string]bool{}
	captures := map[string]bool{}
	for _, entry := range locations {
		direction, runID, captureID, err := passiveCaseDirection(entry.dir, entry.plan, entry.capture, entry.sender, ca)
		if err != nil {
			return report, fmt.Errorf("%s: %w", entry.dir, err)
		}
		if ids[runID] || captures[captureID] {
			return report, errors.New("duplicate signed run/capture ID across directions")
		}
		ids[runID], captures[captureID] = true, true
		report.Directions = append(report.Directions, direction)
		for _, file := range []struct{ kind, path string }{{"signed_sender_challenge", entry.plan}, {"signed_sender_syscalls", entry.sender}, {"signed_passive_receiver_capture", entry.capture}} {
			payload, err := readSmallRegular(file.path, passiveMaxFile)
			if err != nil {
				return report, err
			}
			report.PassiveInputFiles = append(report.PassiveInputFiles, passiveInputFile{Slot: entry.dir, Kind: file.kind, SHA256: digestBytes(payload)})
		}
		for _, item := range []struct{ role, path string }{
			{"sender", entry.sender}, {"receiver", entry.capture},
		} {
			payload, err := readSmallRegular(item.path, passiveMaxFile)
			if err != nil {
				return report, err
			}
			report.Inputs = append(report.Inputs, exchangeProvenance{
				Slot: entry.dir + "/" + item.role, SHA256: digestBytes(payload),
				CampaignID: "", Files: 1, SignedManifestSHA256: "",
				SigningCertificateSHA256: "",
			})
		}
	}
	report.Status = "TWO_SIGNED_ONE_WAY_RUNS_NOT_RETURN_PATH_PROOF"
	for _, d := range report.Directions {
		if d.Status != "SIGNED_BOUNDED_RUN_NOT_CONNECTIVITY_PROOF" {
			report.Status = "PARTIAL_SIGNED_ONE_WAY_EVIDENCE_NOT_RETURN_PATH_PROOF"
		}
	}
	return report, exchangeSaveReports(reports, report)
}

// The CLI checks paths, trust and contents before creating any report files.
func exchangePassiveCLI(caseID, ca, reportDir, abPlan, abSender, abCapture, baPlan, baSender, baCapture string) error {
	st, err := os.Lstat(reportDir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("private report directory (0700) must exist")
	}
	if !filepath.IsAbs(reportDir) {
		return errors.New("offline case reports require absolute report path")
	}
	r, err := passiveCaseAnalyze(caseID, ca, reportDir, abPlan, abSender, abCapture, baPlan, baSender, baCapture)
	if err != nil {
		return err
	}
	return pretty(map[string]any{"status": r.Status, "case_id": caseID,
		"reports": reportDir, "verified_input_artifacts": len(r.Inputs),
		"network_calls": "NONE", "return_path": "NOT_TESTED"})
}
