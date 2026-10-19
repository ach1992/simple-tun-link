package main

// Offline source-order hints for a separately authorized reverse campaign.
// Only an exact candidate IP present in B's OWN approved B_TO_A inventory can
// be promoted using authenticated A_TO_B passive observation evidence.
// This is exploratory ordering, NEVER proof of reverse admission or permission.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type priorityReason struct {
	IP                    string `json:"ip"`
	OriginalPosition      int    `json:"original_position"`
	NewPosition           int    `json:"new_position"`
	ObservedAuthenticated int    `json:"observed_authenticated"`
	ObservedSourceMatched int    `json:"observed_source_matched"`
	Reason                string `json:"reason"`
}

type priorityAudit struct {
	Format                string           `json:"format"`
	CreatedUTC            string           `json:"created_utc"`
	SourceSHA256          string           `json:"source_sha256"`
	SenderChallengeSHA256 string           `json:"sender_challenge_sha256"`
	PassiveCaptureSHA256  string           `json:"passive_capture_sha256"`
	SenderReportProvided  bool             `json:"sender_report_provided"`
	Direction             string           `json:"direction"`
	Confidence            string           `json:"confidence"`
	Candidates            []priorityReason `json:"candidates"`
}

func prepareReversePriority(source, chPath, capturePath, senderPath, ca, out string) (priorityAudit, error) {
	var empty priorityAudit
	if source == "" || chPath == "" || capturePath == "" || ca == "" || out == "" {
		return empty, errors.New("reverse prioritize needs --file --hint-challenge --hint-capture --ca --out")
	}
	if filepath.Ext(out) != ".json" {
		return empty, errors.New("prioritized source output must be .json")
	}
	auditPath := strings.TrimSuffix(out, ".json") + ".ranking.json"
	if out == source || out == chPath || out == capturePath || out == senderPath ||
		auditPath == source || auditPath == chPath || auditPath == capturePath || auditPath == senderPath {
		return empty, errors.New("priority outputs must not overwrite input artifacts")
	}
	for _, target := range []string{out, auditPath} {
		if _, err := os.Lstat(target); err == nil {
			return empty, os.ErrExist
		} else if !os.IsNotExist(err) {
			return empty, err
		}
	}
	sourceBytes, err := readSmallRegular(source, 4<<20)
	if err != nil {
		return empty, err
	}
	original, err := exchangeReadSourceAnyName(source)
	if err != nil {
		return empty, err
	}
	for _, candidate := range original.Candidates {
		if candidate.Direction != "B_TO_A" || candidate.Sender != "B" || candidate.Receiver != "A" {
			return empty, errors.New("reverse prioritization requires B's own B_TO_A inventory; never copy A sources into B")
		}
	}
	ch, err := readSignedFieldChallenge(chPath)
	if err != nil {
		return empty, err
	}
	if ch.Challenge.Sender != "A" || ch.Challenge.Receiver != "B" {
		return empty, errors.New("priority hint must come from A_TO_B signed sender evidence")
	}
	hints, err := correlatePassive(chPath, capturePath, senderPath, ca)
	if err != nil {
		return empty, err
	}
	counts := map[string]*priorityReason{}
	for i, item := range original.Candidates {
		counts[item.IP] = &priorityReason{IP: item.IP, OriginalPosition: i + 1}
	}
	verified, ok := hints["observations"].([]map[string]any)
	if !ok {
		return empty, errors.New("correlator did not return verified observations")
	}
	for _, ob := range verified {
		ip, _ := ob["candidate_source_ip"].(string)
		if row := counts[ip]; row != nil {
			row.ObservedAuthenticated++
			if matched, _ := ob["source_matched"].(bool); matched {
				row.ObservedSourceMatched++
			}
		}
	}
	ordered := append([]Candidate(nil), original.Candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := counts[ordered[i].IP], counts[ordered[j].IP]
		if a.ObservedSourceMatched != b.ObservedSourceMatched {
			return a.ObservedSourceMatched > b.ObservedSourceMatched
		}
		if a.ObservedAuthenticated != b.ObservedAuthenticated {
			return a.ObservedAuthenticated > b.ObservedAuthenticated
		}
		return a.OriginalPosition < b.OriginalPosition
	})
	audit := priorityAudit{
		Format:               "sdx-reverse-priority-v1",
		CreatedUTC:           time.Now().UTC().Format(time.RFC3339Nano),
		SourceSHA256:         digestBytes(sourceBytes),
		SenderReportProvided: senderPath != "",
		Direction:            "B_TO_A",
		Confidence:           "HEURISTIC_EXACT_IP_OVERLAP_NOT_REVERSE_REACHABILITY_PREDICTION",
	}
	for _, entry := range []struct {
		path string
		to   *string
	}{{chPath, &audit.SenderChallengeSHA256}, {capturePath, &audit.PassiveCaptureSHA256}} {
		data, err := readSmallRegular(entry.path, passiveMaxFile)
		if err != nil {
			return empty, err
		}
		*entry.to = digestBytes(data)
	}
	for i, item := range ordered {
		row := *counts[item.IP]
		row.NewPosition = i + 1
		switch {
		case row.ObservedSourceMatched > 0:
			row.Reason = "A_TO_B_AUTHENTICATED_SOURCE_MATCH_EXPLORATORY_HINT_ONLY"
		case row.ObservedAuthenticated > 0:
			row.Reason = "A_TO_B_AUTHENTICATED_BUT_SOURCE_REWRITTEN_EXPLORATORY_HINT_ONLY"
		default:
			row.Reason = "NO_REVERSE_EVIDENCE_OR_EXACT_IP_OVERLAP_KEEP_STABLE_ORDER"
		}
		audit.Candidates = append(audit.Candidates, row)
	}
	result := CandidateFile{SchemaVersion: schema, Mode: "field_candidates", Candidates: ordered}
	if err := validateCandidates(result); err != nil {
		return empty, fmt.Errorf("reordered inventory invalid: %w", err)
	}
	// The rationale is written first so a produced prioritized inventory can
	// always be accompanied by the source evidence that determined its order.
	if err := saveNewJSON(auditPath, audit); err != nil {
		return empty, err
	}
	if err := saveNewJSON(out, result); err != nil {
		return empty, err
	}
	return audit, nil
}
