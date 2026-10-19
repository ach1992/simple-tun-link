package main

import "math"

// fieldSourceObservation is a per-source, per-signed-run tally. Percentages
// measure receiver observations against the *signed plan*, not network loss.
// The sender might never have transmitted every planned datagram.
type fieldSourceObservation struct {
	Candidate                        Candidate `json:"candidate"`
	PlannedSamples                   int       `json:"planned_samples"`
	AuthenticatedPeerObservations    int       `json:"authenticated_peer_observations"`
	ExactSourceObserved              int       `json:"exact_source_observed"`
	RewrittenSourceObserved          int       `json:"different_source_observed"`
	PlannedButNotObserved            int       `json:"planned_but_not_observed"`
	PeerObservationPctOfSignedPlan   float64   `json:"peer_observation_pct_of_signed_plan"`
	ExactSourcePctOfPeerObservations *float64  `json:"exact_source_pct_of_peer_observations,omitempty"`
	ObservationStatus                string    `json:"observation_status"`
	ProviderAuthorization            string    `json:"provider_authorization"`
	ReturnPath                       string    `json:"return_path"`
}

func effectiveFieldRepeats(n int) int {
	if n == 0 {
		return 1 // historical one-sample signed challenges omitted the field
	}
	return n
}

func fieldPct(numerator, denominator int) float64 {
	if denominator < 1 {
		return 0
	}
	return math.Round(1000*float64(numerator)/float64(denominator)) / 10
}

// Called only after the complete challenge/grant/receipt binding and the
// observation indices/signatures have been independently verified.
func summarizeFieldSourceObservations(samples []fieldSample, observations []fieldSeen) []fieldSourceObservation {
	ordered := make([]fieldSourceObservation, 0)
	positions := make(map[string]int)
	for _, sample := range samples {
		id := candidateIdentity(sample.Candidate)
		position, ok := positions[id]
		if !ok {
			position = len(ordered)
			positions[id] = position
			ordered = append(ordered, fieldSourceObservation{
				Candidate:             sample.Candidate,
				ProviderAuthorization: "NOT_VERIFIED_BY_DIAGNOSTICS",
				ReturnPath:            "NOT_TESTED",
			})
		}
		ordered[position].PlannedSamples++
	}
	for _, observation := range observations {
		sample := samples[observation.Index]
		position := positions[candidateIdentity(sample.Candidate)]
		entry := &ordered[position]
		entry.AuthenticatedPeerObservations++
		if observation.SourceMatched {
			entry.ExactSourceObserved++
		} else {
			entry.RewrittenSourceObserved++
		}
	}
	for i := range ordered {
		entry := &ordered[i]
		entry.PlannedButNotObserved = entry.PlannedSamples - entry.AuthenticatedPeerObservations
		entry.PeerObservationPctOfSignedPlan = fieldPct(entry.AuthenticatedPeerObservations, entry.PlannedSamples)
		if entry.AuthenticatedPeerObservations == 0 {
			entry.ObservationStatus = "NO_SIGNED_PEER_INGRESS_INCONCLUSIVE"
			continue
		}
		exactPct := fieldPct(entry.ExactSourceObserved, entry.AuthenticatedPeerObservations)
		entry.ExactSourcePctOfPeerObservations = &exactPct
		if entry.PlannedButNotObserved > 0 {
			entry.ObservationStatus = "PARTIAL_SIGNED_PEER_INGRESS"
		} else {
			entry.ObservationStatus = "ALL_PLANNED_SAMPLES_OBSERVED_AT_PEER"
		}
	}
	return ordered
}
