package main

// These routines only inspect signed files that the operator has already
// collected. They do not create runs or communicate with either endpoint.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type offlineSeen struct {
	Source    string
	Ambiguous bool
}

func offlineRunEvidence(challengePath, senderPath, ca string, captures []string) (exchangeRunResult, error) {
	var empty exchangeRunResult
	signed, err := readSignedFieldChallenge(challengePath)
	if err != nil {
		return empty, err
	}
	roots, err := certificateRoots(ca)
	if err != nil {
		return empty, err
	}
	if _, err = checkSignedFieldChallenge(signed, roots, time.Now(), false); err != nil {
		return empty, err
	}
	ch := signed.Challenge
	run := exchangeRunResult{RunID: ch.RunID, Status: "SIGNED_PLAN_ONLY", Sender: "NOT_PROVIDED",
		Receiver: "NO_MATCHING_OBSERVATION", Planned: len(ch.Samples),
		Samples: make([]exchangeSampleResult, len(ch.Samples))}
	for i, sample := range ch.Samples {
		run.Samples[i] = exchangeSampleResult{Index: sample.Index, SourceIP: sample.Candidate.IP,
			SenderState: "NO_DECLARED_ATTEMPT", ReceiverState: "NOT_OBSERVED"}
	}
	if _, e := os.Lstat(senderPath); e == nil {
		if _, e := verifySenderEvidence(senderPath, ch, ca); e != nil {
			return empty, e
		}
		raw, e := readSmallRegular(senderPath, fieldMaxControl)
		if e != nil {
			return empty, e
		}
		var signedSender signedFieldSenderEvidence
		if e = strictJSON(raw, &signedSender); e != nil {
			return empty, e
		}
		run.Sender = signedSender.Evidence.Status
		for _, record := range signedSender.Evidence.Records {
			run.Samples[record.Index].SenderState = record.State
			if record.State == "SUBMITTED" {
				run.Submitted++
			}
		}
	} else if !os.IsNotExist(e) {
		return empty, e
	}
	observed := make(map[int]offlineSeen)
	for _, capture := range captures {
		summary, e := correlatePassive(challengePath, capture, "", ca)
		if e != nil {
			return empty, fmt.Errorf("invalid offline observation: %w", e)
		}
		matches, ok := summary["observations"].([]map[string]any)
		if !ok {
			return empty, errors.New("invalid signed observation summary")
		}
		for _, item := range matches {
			i, ok := item["sample_index"].(int)
			if !ok || i < 0 || i >= len(run.Samples) {
				return empty, errors.New("signed observation index outside Run")
			}
			source, ok := item["actual_observed_source_ip"].(string)
			if !ok || source == "" {
				return empty, errors.New("signed observation has no actual source")
			}
			previous, exists := observed[i]
			if exists && previous.Source != source {
				previous.Ambiguous = true
				observed[i] = previous
			} else if exists {
				run.DuplicateObservations++
			} else {
				observed[i] = offlineSeen{Source: source}
			}
		}
	}
	for i, sighting := range observed {
		sample := &run.Samples[i]
		if sighting.Ambiguous {
			sample.ReceiverState = "CONFLICTING_SIGNED_OBSERVATIONS"
			run.ConflictingObservations++
			continue
		}
		sample.ReceiverState = "AUTHENTICATED_OBSERVED"
		sample.ActualSource = sighting.Source
		sample.SourceMatched = sample.SourceIP == sighting.Source
		run.Observed++
		if sample.SenderState != "SUBMITTED" {
			run.ObservedWithoutSubmitted++
		}
	}
	if len(captures) == 0 {
		run.Receiver = "NO_MATCHING_SIGNED_RECEIVER_FRAME_IN_IMPORTED_CAPTURES"
	}
	if run.Sender == "COMPLETE" {
		run.Status = "LOCAL_SENDER_COMPLETE_PEER_OBSERVATIONS_QUALIFIED"
	} else if run.Sender == "NOT_PROVIDED" {
		run.Status = "SIGNED_PLAN_NO_SENDER_EVIDENCE"
	} else {
		run.Status = "PARTIAL_OR_INTERRUPTED_SENDER"
	}
	if run.ObservedWithoutSubmitted > 0 {
		run.Status = "SENDER_RECEIVER_EVIDENCE_DISCREPANCY"
	}
	for _, s := range run.Samples {
		if s.ReceiverState == "CONFLICTING_SIGNED_OBSERVATIONS" {
			run.Status = "CONFLICTING_SIGNED_OBSERVATIONS"
		}
	}
	return run, nil
}

func offlineCampaignDirection(dir, captureDir, ca, expected string) (exchangeDirectionReport, []passiveBatchCoverage, []passiveInputFile, error) {
	dr := exchangeDirectionReport{Direction: expected, Status: "INCOMPLETE",
		Runs: []exchangeRunResult{}, Sources: []exchangeSourceResult{}}
	manifest, err := readCampaign(dir)
	if err != nil {
		return dr, nil, nil, err
	}
	if manifest.Direction != expected {
		return dr, nil, nil, errors.New("sender campaign direction is not the expected direction")
	}
	dr.CampaignID = manifest.CampaignID
	capturePaths, captureInputs, err := validatedCapturePaths(captureDir, ca, manifest)
	if err != nil {
		return dr, nil, nil, err
	}
	captureIndex, err := indexedCaptureRunPaths(capturePaths, ca, manifest.Receiver)
	if err != nil {
		return dr, nil, nil, err
	}
	inputs := append([]passiveInputFile{}, captureInputs...)
	manifestFile := filepath.Join(dir, "campaign.json")
	digest, err := offlineDigestFile(manifestFile, expected, "operator_campaign_manifest")
	if err != nil {
		return dr, nil, nil, err
	}
	inputs = append(inputs, digest)
	sources := map[string]*exchangeSourceResult{}
	coverage := []passiveBatchCoverage{}
	seenRuns := map[string]bool{}
	totalAttempts := 0
	allSubmitted := true
	observedTotal := 0
	captureTerminal := true
	for _, capturePath := range capturePaths {
		capture, e := readAndVerifyPassive(capturePath, ca, manifest.Receiver)
		if e != nil {
			return dr, nil, nil, e
		}
		if capture.Status != "COMPLETE" {
			captureTerminal = false
		}
	}
	for _, batch := range manifest.Batches {
		sourceFile := filepath.Join(dir, batch.File)
		inventory, err := readCandidates(sourceFile)
		if err != nil {
			return dr, nil, nil, err
		}
		input, err := offlineDigestFile(sourceFile, expected, "source_batch_inventory")
		if err != nil {
			return dr, nil, nil, err
		}
		inputs = append(inputs, input)
		for _, candidate := range inventory.Candidates {
			if _, exists := sources[candidate.IP]; exists {
				return dr, nil, nil, errors.New("duplicate candidate across campaign batches")
			}
			sources[candidate.IP] = &exchangeSourceResult{
				Direction: expected, CampaignID: manifest.CampaignID, SourceIP: candidate.IP,
			}
		}
		latest, _, err := latestCampaignAttempt(dir, batch.Number)
		if err != nil {
			return dr, nil, nil, err
		}
		covered := passiveBatchCoverage{Direction: expected, CampaignID: manifest.CampaignID,
			Batch: batch.Number, Attempts: latest, Candidates: batch.Count, State: "NOT_TESTED"}
		batchSubmittedComplete := latest > 0
		if latest == 0 {
			allSubmitted = false
		}
		for attempt := 1; attempt <= latest; attempt++ {
			totalAttempts++
			if totalAttempts > 2048 {
				return dr, nil, nil, errors.New("offline campaign has too many attempts to analyze safely")
			}
			path := campaignAttemptDir(dir, batch.Number, attempt)
			challenge := filepath.Join(path, "challenge.json")
			envelope, err := readSignedFieldChallenge(challenge)
			if err != nil {
				return dr, nil, nil, err
			}
			if err = validateCampaignChallenge(dir, manifest, batch, envelope, ca); err != nil {
				return dr, nil, nil, err
			}
			if seenRuns[envelope.Challenge.RunID] {
				return dr, nil, nil, errors.New("signed Run ID reused in same campaign")
			}
			seenRuns[envelope.Challenge.RunID] = true
			digest, err := offlineDigestFile(challenge, expected, "signed_run_plan")
			if err != nil {
				return dr, nil, nil, err
			}
			inputs = append(inputs, digest)
			senderPath := filepath.Join(path, "sender.json")
			if st, e := os.Lstat(senderPath); e == nil {
				if !st.Mode().IsRegular() {
					return dr, nil, nil, errors.New("sender evidence must be regular file")
				}
				digest, e := offlineDigestFile(senderPath, expected, "signed_sender_evidence")
				if e != nil {
					return dr, nil, nil, e
				}
				inputs = append(inputs, digest)
			} else if !os.IsNotExist(e) {
				return dr, nil, nil, e
			}
			run, err := offlineRunEvidence(challenge, senderPath, ca, captureIndex[envelope.Challenge.RunID])
			if err != nil {
				return dr, nil, nil, fmt.Errorf("batch %d attempt %d: %w", batch.Number, attempt, err)
			}
			run.Batch = batch.Number
			run.Attempt = attempt
			covered.Planned += run.Planned
			covered.Submitted += run.Submitted
			covered.Observed += run.Observed
			observedTotal += run.Observed
			covered.Duplicate += run.DuplicateObservations
			covered.Ambiguous += run.ConflictingObservations
			if run.Sender != "COMPLETE" || run.ObservedWithoutSubmitted > 0 || run.ConflictingObservations > 0 {
				allSubmitted = false
				batchSubmittedComplete = false
			}
			for _, sample := range run.Samples {
				row := sources[sample.SourceIP]
				if row == nil {
					return dr, nil, nil, errors.New("run includes source outside this campaign")
				}
				row.Planned++
				switch sample.SenderState {
				case "SUBMITTED":
					row.Submitted++
				case "ATTEMPTED_UNKNOWN":
					row.AttemptedUnknown++
				case "FAILED":
					row.Failed++
				case "NO_DECLARED_ATTEMPT":
				default:
					return dr, nil, nil, errors.New("unknown signed sender evidence state")
				}
				if sample.ReceiverState == "AUTHENTICATED_OBSERVED" {
					row.Observed++
					if sample.SourceMatched {
						row.SourceMatched++
					} else {
						row.SourceRewritten++
					}
					if sample.SenderState == "SUBMITTED" {
						row.ObservedWithSubmitted++
					} else {
						row.ObservedWithoutSubmitted++
					}
				} else if sample.ReceiverState == "CONFLICTING_SIGNED_OBSERVATIONS" {
					row.Ambiguous++
				}
			}
			dr.Runs = append(dr.Runs, run)
		}
		// Untested means no signed claim of a sender attempt or a valid peer
		// observation for this candidate in any available attempt.
		for _, candidate := range inventory.Candidates {
			row := sources[candidate.IP]
			if row.Submitted == 0 && row.AttemptedUnknown == 0 && row.Failed == 0 && row.Observed == 0 && row.Ambiguous == 0 {
				row.NotTested = manifest.SamplesPerSource
				covered.NotTested += manifest.SamplesPerSource
			}
		}
		switch {
		case latest == 0:
			covered.State = "NOT_TESTED"
		case covered.NotTested > 0 || covered.Ambiguous > 0 || !batchSubmittedComplete:
			covered.State = "PARTIAL_OR_UNTESTED"
		default:
			covered.State = "LOCAL_ATTEMPTS_RECORDED_NO_RETURN_PATH_PROOF"
		}
		coverage = append(coverage, covered)
	}
	for _, row := range sources {
		dr.Sources = append(dr.Sources, *row)
	}
	sort.Slice(dr.Sources, func(i, j int) bool { return dr.Sources[i].SourceIP < dr.Sources[j].SourceIP })
	switch {
	case allSubmitted && captureTerminal && observedTotal > 0:
		dr.Status = "AUTHENTICATED_ONE_WAY_OBSERVATIONS_NOT_RETURN_PATH_PROOF"
	case allSubmitted && observedTotal == 0:
		dr.Status = "NO_AUTHENTICATED_RECEIVER_OBSERVATION_INCONCLUSIVE"
	default:
		dr.Status = "PARTIAL_OR_UNTESTED"
	}
	return dr, coverage, inputs, nil
}

func offlineDigestFile(path, slot, kind string) (passiveInputFile, error) {
	b, err := readSmallRegular(path, passiveMaxFile)
	if err != nil {
		return passiveInputFile{}, err
	}
	return passiveInputFile{Slot: slot, Kind: kind, SHA256: digestBytes(b)}, nil
}
