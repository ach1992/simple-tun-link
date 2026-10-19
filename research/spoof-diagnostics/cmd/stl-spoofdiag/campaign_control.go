package main

// A durable, local, manually operated Campaign hold/release state. This is a
// control on future commands, not a mechanism for sending or scheduling data.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const campaignControlFormat = "sdx-campaign-control-v1"

type campaignControl struct {
	Format         string `json:"format"`
	CampaignID     string `json:"campaign_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	State          string `json:"state"`
	Revision       int    `json:"revision"`
	Reason         string `json:"reason"`
	UpdatedUTC     string `json:"updated_utc"`
}

func campaignControlFile(dir string) string {
	return filepath.Join(dir, "campaign-control.json")
}

func readCampaignControl(dir string, m campaignManifest) (campaignControl, error) {
	var zero campaignControl
	manifestBytes, err := readSmallRegular(filepath.Join(dir, "campaign.json"), 8<<20)
	if err != nil {
		return zero, err
	}
	expected := digestBytes(manifestBytes)
	path := campaignControlFile(dir)
	raw, err := readSmallRegular(path, 32768)
	if os.IsNotExist(err) {
		return campaignControl{Format: campaignControlFormat, CampaignID: m.CampaignID,
			ManifestSHA256: expected, State: "ACTIVE", Revision: 0}, nil
	}
	if err != nil {
		return zero, err
	}
	var control campaignControl
	if err = strictJSON(raw, &control); err != nil {
		return zero, err
	}
	if control.Format != campaignControlFormat || control.CampaignID != m.CampaignID ||
		control.ManifestSHA256 != expected || control.Revision < 1 ||
		(control.State != "ACTIVE" && control.State != "PAUSED" && control.State != "STOPPED_BY_OPERATOR") ||
		len(control.Reason) > 180 {
		return zero, errors.New("campaign control is invalid or references a changed manifest")
	}
	when, err := time.Parse(time.RFC3339Nano, control.UpdatedUTC)
	if err != nil || when.After(time.Now().Add(time.Minute)) {
		return zero, errors.New("campaign control time is invalid")
	}
	return control, nil
}

func requireCampaignActive(dir string, m campaignManifest) error {
	control, err := readCampaignControl(dir, m)
	if err != nil {
		return err
	}
	if control.State != "ACTIVE" {
		return fmt.Errorf("campaign is %s: no new Run or sender action permitted; local operator must review state", control.State)
	}
	return nil
}

func changeCampaignControl(dir, verb, reason string) (map[string]any, error) {
	return campaignMutate(dir, func() (map[string]any, error) {
		m, err := readCampaign(dir)
		if err != nil {
			return nil, err
		}
		current, err := readCampaignControl(dir, m)
		if err != nil {
			return nil, err
		}
		reason = strings.TrimSpace(reason)
		if len(reason) > 180 || strings.ContainsAny(reason, "\n\r") {
			return nil, errors.New("reason must be a single line of at most 180 bytes")
		}
		target := current.State
		switch verb {
		case "pause":
			if current.State == "STOPPED_BY_OPERATOR" {
				return nil, errors.New("stopped Campaign is terminal")
			}
			target = "PAUSED"
			if reason == "" {
				reason = "OPERATOR_BATCH_CHECKPOINT"
			}
		case "resume":
			if current.State == "STOPPED_BY_OPERATOR" {
				return nil, errors.New("stopped Campaign cannot resume")
			}
			if current.State != "PAUSED" {
				return nil, errors.New("resume requires a paused Campaign")
			}
			target = "ACTIVE"
			if reason == "" {
				reason = "OPERATOR_RESUMED_PENDING_BATCHES"
			}
		case "stop":
			target = "STOPPED_BY_OPERATOR"
			if reason == "" {
				return nil, errors.New("stopping a Campaign requires a specific operator reason")
			}
		default:
			return nil, errors.New("unknown campaign control action")
		}
		if target == current.State {
			return map[string]any{"campaign_id": m.CampaignID, "state": current.State,
				"revision": current.Revision, "status": "UNCHANGED_ALREADY_IN_STATE", "network_calls": "NONE"}, nil
		}
		current.State = target
		current.Revision++
		current.Reason = reason
		current.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		path := campaignControlFile(dir)
		if current.Revision == 1 {
			err = writeStagedJSON(path, current, false)
		} else {
			err = writeStagedJSON(path, current, true)
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"campaign_id": m.CampaignID, "state": current.State,
			"revision": current.Revision, "reason": current.Reason, "network_calls": "NONE",
			"note": "This changes only future campaign commands; a presently active job must be stopped separately"}, nil
	})
}

func campaignControlStatus(dir, ca string) (map[string]any, error) {
	m, err := readCampaign(dir)
	if err != nil {
		return nil, err
	}
	c, err := readCampaignControl(dir, m)
	if err != nil {
		return nil, err
	}
	states := []map[string]any{}
	completed := 0
	for _, batch := range m.Batches {
		latest, path, err := latestCampaignAttempt(dir, batch.Number)
		if err != nil {
			return nil, err
		}
		state := "NOT_TESTED"
		if latest > 0 {
			state = "PLAN_PREPARED_SENDER_STATUS_UNKNOWN"
			senderPath := filepath.Join(path, "sender.json")
			if _, e := os.Lstat(senderPath); e == nil {
				state = "SENDER_EVIDENCE_PRESENT_NOT_VERIFIED"
				if ca != "" {
					challengePath := filepath.Join(path, "challenge.json")
					env, e := readSignedFieldChallenge(challengePath)
					if e != nil {
						return nil, e
					}
					if e = validateCampaignChallenge(dir, m, batch, env, ca); e != nil {
						return nil, e
					}
					summary, e := verifySenderEvidence(senderPath, env.Challenge, ca)
					if e != nil {
						return nil, e
					}
					if summary["status"] == "COMPLETE" && summary["syscalls_succeeded"] == len(env.Challenge.Samples) {
						state = "SIGNED_LOCAL_SUBMISSION_COMPLETE_NOT_PEER_DELIVERY"
						completed++
					} else {
						state = "SIGNED_LOCAL_SUBMISSION_PARTIAL_OR_INTERRUPTED"
					}
				}
			} else if !os.IsNotExist(e) {
				return nil, e
			}
		}
		states = append(states, map[string]any{
			"batch": batch.Number, "attempts": latest, "source_count": batch.Count, "state": state,
		})
	}
	return map[string]any{
		"status":      "LOCAL_CAMPAIGN_PROGRESS_NOT_PEER_CONNECTIVITY",
		"campaign_id": m.CampaignID, "source_digest": m.SourceDigest,
		"control_state": c.State, "control_revision": c.Revision,
		"batch_count": len(m.Batches), "locally_complete_verified_batches": completed,
		"batches": states, "network_calls": "NONE", "return_path": "NOT_TESTED",
	}, nil
}
