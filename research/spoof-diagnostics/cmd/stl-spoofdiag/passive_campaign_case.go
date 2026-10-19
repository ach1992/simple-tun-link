package main

// Final or checkpointed offline summary of two independently collected
// campaigns. Source lists and final Case labels are operator-provided; they
// do not establish provider permission or two-way connectivity.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func passiveCampaignPreview(senderDir, captureDir, ca string) (map[string]any, error) {
	campaign, err := readCampaign(senderDir)
	if err != nil {
		return nil, err
	}
	direction, coverage, digests, err := offlineCampaignDirection(senderDir, captureDir, ca, campaign.Direction)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"status":    "PROVISIONAL_OFFLINE_CHECKPOINT_ONLY",
		"direction": direction.Direction, "campaign_id": direction.CampaignID,
		"campaign_state": direction.Status, "sources": direction.Sources, "batches": coverage,
		"signed_input_digests": digests, "network_calls": "NONE",
		"missing_observation_is_inconclusive": true,
		"return_path":                         "NOT_TESTED",
	}, nil
}

func passiveCampaignCase(caseID, ca, reportDir,
	abCampaign, abCaptures, baCampaign, baCaptures string) (exchangeCaseReport, error) {
	result := exchangeCaseReport{
		Format: "sdx-disconnected-multi-batch-case-v1", CaseID: caseID, Status: "INCOMPLETE",
		Inputs: []exchangeProvenance{}, PassiveInputFiles: []passiveInputFile{},
		PassiveBatchCoverage: []passiveBatchCoverage{},
		Directions:           []exchangeDirectionReport{}, MissingSlots: []string{},
		Conflicts: []string{}, Rejected: []string{},
		Limitations: []string{
			"NO_A_B_CONTROL_CHANNEL: operator manually moved the signed endpoint evidence.",
			"CAMPAIGN_MANIFEST_AND_UNTESTED_IPS_ARE_OPERATOR_SCOPED_NOT_PEER_SIGNED.",
			"SENDER_SUBMITTED_IS_A_LOCAL_SYSCALL_DECLARATION_NOT_PROVEN_NETWORK_EGRESS.",
			"RECEIVER_SIGNED_CAPTURE_IS_A_HOST_SOCKET_OBSERVATION_NOT_AN_INDEPENDENT_NIC_TRACE.",
			"MISSING_OBSERVATION_IS_INCONCLUSIVE_NOT_PROVEN_FILTERING.",
			"EARLY_STOP_OR_UNTESTED_SOURCES_MUST_NOT_BE_GENERALIZED_TO_UNTESTED_IPS.",
			"TWO_ONE_WAY_RUNS_DO_NOT_PROVE_SAME_FLOW_RETURN_PATH_OR_TUNNEL.",
		},
	}
	if !exchangeIDPattern.MatchString(caseID) {
		return result, errors.New("case-id must be 32 lowercase hexadecimal digits")
	}
	if err := privatePassiveReportDir(reportDir); err != nil {
		return result, err
	}
	if _, err := certificateRoots(ca); err != nil {
		return result, err
	}
	trust, err := readSmallRegular(ca, 16384)
	if err != nil {
		return result, err
	}
	result.TrustAnchorFileSHA256 = digestBytes(trust)
	locations := []struct{ direction, sender, captures string }{
		{"A_TO_B", abCampaign, abCaptures},
		{"B_TO_A", baCampaign, baCaptures},
	}
	runIDs := map[string]bool{}
	campaignIDs := map[string]bool{}
	complete := true
	for _, entry := range locations {
		direction, coverage, inputs, err := offlineCampaignDirection(
			entry.sender, entry.captures, ca, entry.direction)
		if err != nil {
			return result, fmt.Errorf("%s: %w", entry.direction, err)
		}
		if campaignIDs[direction.CampaignID] {
			return result, errors.New("two directions must use distinct Campaign IDs")
		}
		campaignIDs[direction.CampaignID] = true
		for _, run := range direction.Runs {
			if runIDs[run.RunID] {
				return result, errors.New("signed Run ID repeated across directions")
			}
			runIDs[run.RunID] = true
		}
		if direction.Status != "AUTHENTICATED_ONE_WAY_OBSERVATIONS_NOT_RETURN_PATH_PROOF" {
			complete = false
		}
		result.Directions = append(result.Directions, direction)
		result.PassiveBatchCoverage = append(result.PassiveBatchCoverage, coverage...)
		result.PassiveInputFiles = append(result.PassiveInputFiles, inputs...)
		result.Inputs = append(result.Inputs,
			exchangeProvenance{Slot: entry.direction + "/sender", CampaignID: direction.CampaignID, Files: len(direction.Runs)},
			exchangeProvenance{Slot: entry.direction + "/receiver", CampaignID: direction.CampaignID,
				Files: countPassiveInputKind(inputs, "signed_passive_receiver_capture")})
	}
	sort.Slice(result.PassiveInputFiles, func(i, j int) bool {
		a, b := result.PassiveInputFiles[i], result.PassiveInputFiles[j]
		if a.Slot != b.Slot {
			return a.Slot < b.Slot
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.SHA256 < b.SHA256
	})
	if complete {
		result.Status = "TWO_OFFLINE_SIGNED_DIRECTIONAL_CAMPAIGNS_NOT_RETURN_PROOF"
	} else {
		result.Status = "PARTIAL_OR_EARLY_STOP_WITH_UNTESTED_COVERAGE"
	}
	if err := exchangeSaveReports(reportDir, result); err != nil {
		return result, err
	}
	return result, nil
}

func countPassiveInputKind(inputs []passiveInputFile, kind string) int {
	n := 0
	for _, input := range inputs {
		if input.Kind == kind {
			n++
		}
	}
	return n
}

func privatePassiveReportDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("report directory must be an absolute path")
	}
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("report directory must already exist and be private (0700)")
	}
	return nil
}
