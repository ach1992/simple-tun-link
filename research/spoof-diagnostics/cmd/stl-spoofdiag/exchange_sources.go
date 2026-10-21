package main

// Source inventories are locally selected operator data, not signed grants.
// Importing a source file NEVER authorizes or starts any diagnostic trial.
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
)

const sourceFormat = "field_candidates"

func exchangeParseSourceBytes(data []byte) (CandidateFile, error) {
	var inventory CandidateFile
	if len(data) == 0 || len(data) > 4<<20 {
		return inventory, errors.New("source exceeds 4 MiB content policy")
	}
	body := bytes.TrimSpace(data)
	if len(body) == 0 {
		return inventory, errors.New("empty source file")
	}
	switch body[0] {
	case '{':
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&inventory); err != nil {
			return inventory, fmt.Errorf("invalid JSON source: %w", err)
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return inventory, errors.New("source JSON contains trailing data")
		}
	default:
		// A CSV must have the canonical four columns, in this order;
		// extension/filename does not determine how the file is interpreted.
		inv := CandidateFile{SchemaVersion: schema, Mode: sourceFormat}
		csvReader := csv.NewReader(bytes.NewReader(body))
		csvReader.FieldsPerRecord = 4
		rows, err := csvReader.ReadAll()
		if err != nil {
			return inventory, err
		}
		if len(rows) == 0 {
			return inventory, errors.New("empty CSV inventory")
		}
		if rows[0][0] == "ip" && rows[0][1] == "direction" &&
			rows[0][2] == "sender" && rows[0][3] == "receiver" {
			rows = rows[1:]
		}
		for _, row := range rows {
			inv.Candidates = append(inv.Candidates, Candidate{IP: strings.TrimSpace(row[0]),
				Direction: strings.TrimSpace(row[1]), Sender: strings.TrimSpace(row[2]),
				Receiver: strings.TrimSpace(row[3])})
		}
		inventory = inv
	}
	if err := validateCandidates(inventory); err != nil {
		return inventory, err
	}
	return inventory, nil
}

func exchangeReadSourceAnyName(path string) (CandidateFile, error) {
	var empty CandidateFile
	data, err := readSmallRegular(path, 4<<20)
	if err != nil {
		return empty, err
	}
	return exchangeParseSourceBytes(data)
}

func exchangeNormalizeInventory(inv CandidateFile) ([]byte, error) {
	if err := validateCandidates(inv); err != nil {
		return nil, err
	}
	copyInv := CandidateFile{SchemaVersion: schema, Mode: sourceFormat,
		Candidates: append([]Candidate{}, inv.Candidates...)}
	sort.Slice(copyInv.Candidates, func(i, j int) bool {
		a, b := copyInv.Candidates[i], copyInv.Candidates[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return candidateIdentity(a) < candidateIdentity(b)
	})
	return jsonBytes(copyInv)
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
	stat, err := os.Lstat(folder)
	if err != nil || !stat.IsDir() || stat.Mode().Perm()&0077 != 0 {
		return "", 0, false, errors.New("run exchange init first: sources/ must be a private 0700 directory")
	}
	digest := exchangeSHA(normalized)
	target := filepath.Join(folder, "SDX-SOURCES-v1-"+digest+".json")
	if old, err := os.Lstat(target); err == nil {
		if !old.Mode().IsRegular() || old.Mode().Perm()&0077 != 0 {
			return "", 0, false, errors.New("existing staged source is not a private regular file")
		}
		data, err := readSmallRegular(target, 4<<20)
		if err != nil || !bytes.Equal(data, normalized) {
			return "", 0, false, errors.New("source SHA identifier points to conflicting bytes")
		}
		return target, len(inv.Candidates), true, nil
	} else if !os.IsNotExist(err) {
		return "", 0, false, err
	}
	if err := exchangeWriteNew(target, normalized); err != nil {
		return "", 0, false, err
	}
	// Normalize the saved bytes too so equivalent CSV/JSON and row order
	// yield the same deterministic staged representation and future hash.
	stored, err := readSmallRegular(target, 4<<20)
	if err != nil {
		return "", 0, false, err
	}
	if !bytes.Equal(stored, normalized) {
		// The caller never relies on a potentially ambiguous digest.
		return "", 0, false, errors.New("source saved without canonical encoding")
	}
	return target, len(inv.Candidates), false, nil
}

func exchangeSourceApprove(input, out, node, ack string) (map[string]any, error) {
	if node != "A" && node != "B" {
		return nil, errors.New("local approving node must be A or B")
	}
	if ack != "APPROVE_SOURCES" {
		return nil, errors.New("source approval requires explicit APPROVE_SOURCES acknowledgement")
	}
	inv, err := readCandidates(input)
	if err != nil {
		return nil, err
	}
	selected := CandidateFile{SchemaVersion: schema, Mode: sourceFormat, Candidates: []Candidate{}}
	for _, c := range inv.Candidates {
		if c.Receiver == node {
			selected.Candidates = append(selected.Candidates, c)
		}
	}
	if len(selected.Candidates) == 0 {
		return nil, errors.New("no source candidates address this receiver node")
	}
	if err := saveNewJSON(out, selected); err != nil {
		return nil, err
	}
	return map[string]any{"status": "LOCAL_RECEIVER_ALLOWLIST_SAVED_NO_NETWORK",
		"node": node, "count": len(selected.Candidates), "file": out,
		"caution": "This is the receiver's independent local source selection, NOT permission from any network provider."}, nil
}

func exchangeSourcesCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: exchange sources template|inspect|stage|approve")
	}
	op := args[0]
	f := flag.NewFlagSet("exchange sources "+op, flag.ContinueOnError)
	base := f.String("base", exchangeDefaultBase, "private exchange root")
	path := f.String("file", "", "candidate source file (any name for stage/inspect)")
	out := f.String("out", "", "explicit new local JSON output")
	node := f.String("node", "", "A or B for independent receiver approval")
	ack := f.String("ack", "", "type APPROVE_SOURCES only after local review")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	switch op {
	case "template":
		if *out == "" {
			return errors.New("template needs new --out .json")
		}
		if err := saveNewJSON(*out, CandidateFile{SchemaVersion: schema, Mode: sourceFormat, Candidates: []Candidate{}}); err != nil {
			return err
		}
		return pretty(map[string]any{"status": "EMPTY_TEMPLATE_CREATED_EDIT_BEFORE_USE", "out": *out, "schema_version": schema})
	case "inspect":
		if *path == "" {
			return errors.New("inspect needs --file")
		}
		inv, err := exchangeReadSourceAnyName(*path)
		if err != nil {
			return err
		}
		normalized, err := exchangeNormalizeInventory(inv)
		if err != nil {
			return err
		}
		counts := map[string]int{"A_TO_B": 0, "B_TO_A": 0}
		for _, c := range inv.Candidates {
			counts[c.Direction]++
		}
		return pretty(map[string]any{"status": "SOURCE_SHAPE_VALIDATED_UNTRUSTED_NOT_APPROVED",
			"candidate_count": len(inv.Candidates), "by_direction": counts,
			"canonical_sha256": exchangeSHA(normalized), "network_calls": "NONE"})
	case "stage":
		if *path == "" {
			return errors.New("stage needs --file (arbitrary extension allowed)")
		}
		target, n, duplicate, err := exchangeSourceStage(*base, *path)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"status": "STAGED_UNAPPROVED_SOURCE_INVENTORY", "file": target,
			"candidate_count": n, "already_staged": duplicate, "network_calls": "NONE"})
	case "approve":
		if *path == "" || *out == "" || *node == "" {
			return errors.New("approve needs --file --out --node and --ack APPROVE_SOURCES")
		}
		result, err := exchangeSourceApprove(*path, *out, *node, *ack)
		if err != nil {
			return err
		}
		return pretty(result)
	default:
		return errors.New("usage: exchange sources template|inspect|stage|approve")
	}
}
