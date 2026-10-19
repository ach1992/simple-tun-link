package main

// Source inventories are operator input, never permissions or run triggers.
// Keep the existing field_candidates JSON as the only Campaign/Field input.
import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	sourceFormat  = "field_candidates"
	sourceMaxFile = 4 << 20 // current readCandidates budget, not a Campaign duration limit
	sourceTXTAB   = "# SDX-IP-LIST v1 direction=A_TO_B"
	sourceTXTBA   = "# SDX-IP-LIST v1 direction=B_TO_A"
)

func exchangeParseTextSource(data []byte) (CandidateFile, error) {
	var inv CandidateFile
	if !utf8.Valid(data) {
		return inv, errors.New("IP source text must be valid UTF-8")
	}
	lines := strings.Split(string(data), "\n")
	direction := ""
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if direction == "" {
			switch line {
			case sourceTXTAB:
				direction = "A_TO_B"
			case sourceTXTBA:
				direction = "B_TO_A"
			default:
				return inv, fmt.Errorf("source line %d: first nonempty line must be exactly %q or %q", i+1, sourceTXTAB, sourceTXTBA)
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "# SDX-IP-LIST") {
				return inv, fmt.Errorf("source line %d: duplicate/contradictory direction header", i+1)
			}
			continue
		}
		if strings.ContainsAny(line, " \t,;/:") {
			return inv, fmt.Errorf("source line %d: expected one exact IPv4 per line (no ranges, CIDR, ports or inline comments)", i+1)
		}
		if err := validateIP(line, sourceFormat); err != nil {
			return inv, fmt.Errorf("source line %d: %w", i+1, err)
		}
		sender, receiver := "A", "B"
		if direction == "B_TO_A" {
			sender, receiver = "B", "A"
		}
		inv.Candidates = append(inv.Candidates, Candidate{IP: line, Direction: direction, Sender: sender, Receiver: receiver})
	}
	if direction == "" {
		return inv, errors.New("missing # SDX-IP-LIST v1 direction=... header")
	}
	inv.SchemaVersion, inv.Mode = schema, sourceFormat
	if err := validateCandidates(inv); err != nil {
		return inv, err
	}
	return inv, nil
}

func exchangeParseSourceBytes(data []byte) (CandidateFile, error) {
	return parseCandidateInventoryBytes(data, "", false)
}

// One decoder for native JSON/CSV and simplified TXT operator inventories.
// Native managed source editing remains .json/.csv-only; the offline exchange
// may identify any of these formats from content regardless of filename.
func parseCandidateInventoryBytes(data []byte, kind string, allowEmpty bool) (CandidateFile, error) {
	var inv CandidateFile
	if len(data) > sourceMaxFile {
		return inv, errors.New("source input exceeds current 4 MiB reader budget; split into multiple finite Campaigns")
	}
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		data = data[3:]
	}
	body := bytes.TrimSpace(data)
	if len(body) == 0 {
		if kind == "csv" && allowEmpty {
			return CandidateFile{SchemaVersion: schema, Mode: sourceFormat}, nil
		}
		return inv, errors.New("empty source inventory")
	}
	if kind == "" {
		switch body[0] {
		case '#':
			kind = "txt"
		case '{':
			kind = "json"
		default:
			kind = "csv"
		}
	}
	switch kind {
	case "txt":
		return exchangeParseTextSource(body)
	case "json":
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&inv); err != nil {
			return inv, fmt.Errorf("invalid JSON inventory: %w", err)
		}
		var rest any
		if err := dec.Decode(&rest); err != io.EOF {
			return inv, errors.New("trailing source JSON data")
		}
	case "csv":
		reader := csv.NewReader(bytes.NewReader(body))
		reader.FieldsPerRecord = 4
		rows, err := reader.ReadAll()
		if err != nil {
			return inv, fmt.Errorf("invalid 4-column CSV source: %w", err)
		}
		if len(rows) > 0 && strings.EqualFold(strings.TrimSpace(rows[0][0]), "ip") {
			rows = rows[1:]
		}
		inv.SchemaVersion, inv.Mode = schema, sourceFormat
		for _, row := range rows {
			inv.Candidates = append(inv.Candidates, Candidate{IP: strings.TrimSpace(row[0]),
				Direction: strings.TrimSpace(row[1]), Sender: strings.TrimSpace(row[2]),
				Receiver: strings.TrimSpace(row[3])})
		}
	default:
		return inv, errors.New("source inventory must be TXT, JSON, or CSV")
	}
	return inv, validateCandidateInventory(inv, allowEmpty)
}
func exchangeReadSourceAnyName(path string) (CandidateFile, error) {
	var empty CandidateFile
	data, err := readSmallRegular(path, sourceMaxFile)
	if err != nil {
		return empty, err
	}
	return exchangeParseSourceBytes(data)
}

func exchangeNormalizeInventory(inv CandidateFile) ([]byte, error) {
	if err := validateCandidates(inv); err != nil {
		return nil, err
	}
	canonical := CandidateFile{SchemaVersion: schema, Mode: sourceFormat,
		Candidates: append([]Candidate{}, inv.Candidates...)}
	sort.Slice(canonical.Candidates, func(i, j int) bool {
		a, b := canonical.Candidates[i], canonical.Candidates[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return candidateIdentity(a) < candidateIdentity(b)
	})
	out, err := jsonBytes(canonical)
	if err != nil {
		return nil, err
	}
	if len(out) > sourceMaxFile {
		return nil, errors.New("converted JSON exceeds current 4 MiB Campaign input reader; split inventory into multiple Campaigns")
	}
	return out, nil
}

func exchangeSourceStage(base, input string) (string, int, bool, error) {
	inv, err := exchangeReadSourceAnyName(input)
	if err != nil {
		return "", 0, false, err
	}
	normalized, err := exchangeNormalizeInventory(inv)
	if err != nil {
		return "", 0, false, err
	}
	folder := filepath.Join(base, "sources")
	st, err := os.Lstat(folder)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return "", 0, false, errors.New("run exchange init first (sources must be private 0700 directory)")
	}
	target := filepath.Join(folder, "SDX-SOURCES-v1-"+exchangeSHA(normalized)+".json")
	verifyExisting := func() error {
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("existing source destination is not a private regular file")
		}
		prior, err := readSmallRegular(target, sourceMaxFile)
		if err != nil || !bytes.Equal(prior, normalized) {
			return errors.New("existing source identifier has conflicting or modified content")
		}
		return nil
	}
	if _, err := os.Lstat(target); err == nil {
		if err := verifyExisting(); err != nil {
			return "", 0, false, err
		}
		return target, len(inv.Candidates), true, nil
	} else if !os.IsNotExist(err) {
		return "", 0, false, err
	}
	if err := exchangeWriteNew(target, normalized); err != nil {
		if os.IsExist(err) && verifyExisting() == nil {
			return target, len(inv.Candidates), true, nil
		}
		return "", 0, false, err
	}
	return target, len(inv.Candidates), false, nil
}

type sourcePlanEstimate struct {
	Direction            string `json:"direction"`
	SourceCount          int    `json:"source_count"`
	BatchCount           int    `json:"batch_count"`
	PlannedSamples       int    `json:"planned_samples"`
	MinimumSenderSeconds int    `json:"minimum_sender_seconds"`
}

func exchangeEstimateSourcePlan(inv CandidateFile, batchSize, samplesPerSource int) ([]sourcePlanEstimate, error) {
	if batchSize < 1 || batchSize > fieldMaxSelectedSources || samplesPerSource < 1 || samplesPerSource > fieldMaxPacketsPerSource {
		return nil, errors.New("batch-size or samples-per-source outside existing bounded Field policy")
	}
	if err := validateCandidates(inv); err != nil {
		return nil, err
	}
	counts := map[string]int{"A_TO_B": 0, "B_TO_A": 0}
	for _, c := range inv.Candidates {
		counts[c.Direction]++
	}
	result := []sourcePlanEstimate{}
	for _, dir := range []string{"A_TO_B", "B_TO_A"} {
		n := counts[dir]
		if n == 0 {
			continue
		}
		samples := n * samplesPerSource
		// Sender intentionally paces calls at 200ms each; this excludes
		// all transfer/setup/listener/consent/manual time and is NOT an ETA.
		result = append(result, sourcePlanEstimate{Direction: dir, SourceCount: n,
			BatchCount: (n + batchSize - 1) / batchSize, PlannedSamples: samples,
			MinimumSenderSeconds: (samples + 4) / 5})
	}
	return result, nil
}

func exchangeSourcesCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: exchange sources inspect|stage")
	}
	op := args[0]
	f := flag.NewFlagSet("exchange sources "+op, flag.ContinueOnError)
	base := f.String("base", exchangeDefaultBase, "private operator exchange root")
	source := f.String("file", "", "input (default base/inbox/ip.txt)")
	batchSize := f.Int("batch-size", fieldMaxSelectedSources, "existing 1..32 candidate addresses per independent run")
	repeats := f.Int("samples-per-source", 5, "existing 1..10 bounded samples per source")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if *source == "" {
		*source = filepath.Join(*base, "inbox", "ip.txt")
	}
	if *batchSize < 1 || *batchSize > fieldMaxSelectedSources || *repeats < 1 || *repeats > fieldMaxPacketsPerSource {
		return errors.New("batch-size or samples-per-source outside existing finite Field settings")
	}
	switch op {
	case "inspect":
		inv, err := exchangeReadSourceAnyName(*source)
		if err != nil {
			return err
		}
		normalized, err := exchangeNormalizeInventory(inv)
		if err != nil {
			return err
		}
		plan, err := exchangeEstimateSourcePlan(inv, *batchSize, *repeats)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "SOURCE_VALIDATED_OFFLINE_NO_NETWORK",
			"input": *source, "canonical_sha256": exchangeSHA(normalized),
			"source_count": len(inv.Candidates), "directional_plan": plan,
			"time":    "MINIMUM_SENDER_PACING_ONLY_NOT_WALL_CLOCK_ETA",
			"run_ttl": "60_TO_900_SECONDS_PER_RUN_NOT_WHOLE_CAMPAIGN"})
	case "stage":
		target, count, identical, err := exchangeSourceStage(*base, *source)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "CANONICAL_SOURCE_STAGED_NO_NETWORK",
			"file": target, "count": count, "already_staged_identical": identical,
			"next": "Use the staged canonical JSON with existing campaign create; no packet or authorization is triggered."})
	default:
		return errors.New("usage: exchange sources inspect|stage")
	}
}
