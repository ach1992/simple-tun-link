package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func candidateIdentity(c Candidate) string {
	return strings.Join([]string{c.IP, c.Direction, c.Sender, c.Receiver}, "|")
}

// Keep operator inventory changes atomic. The directory and destination must
// already be explicitly operator-owned; never follow a symlink target.
func writeCandidateInventory(path string, cfg CandidateFile) error {
	if path == "" || filepath.Ext(path) != ".json" {
		return errors.New("source inventory must be an explicit .json path")
	}
	if err := validateCandidateInventory(cfg, true); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return errors.New("refusing symlink or non-regular source inventory")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("inventory parent must be an existing non-symlink directory")
	}
	if cfg.Candidates == nil {
		cfg.Candidates = []Candidate{}
	}
	tmp, err := os.CreateTemp(dir, ".spoofdiag-inventory-*.tmp")
	if err != nil {
		return err
	}
	pending := tmp.Name()
	defer os.Remove(pending)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(pending, path)
}

func importCandidates(path, input string) (int, error) {
	if path == "" || input == "" {
		return 0, errors.New("--file and --from required")
	}
	if filepath.Clean(path) == filepath.Clean(input) {
		return 0, errors.New("source and destination inventories must differ")
	}
	addition, err := readCandidates(input)
	if err != nil {
		return 0, err
	}
	result := CandidateFile{SchemaVersion: schema, Mode: addition.Mode, Candidates: make([]Candidate, 0, len(addition.Candidates))}
	if _, err := os.Lstat(path); err == nil {
		existing, err := readCandidateInventory(path, true)
		if err != nil {
			return 0, err
		}
		if existing.Mode != addition.Mode {
			return 0, errors.New("inventory mode mismatch")
		}
		result = existing
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	result.Candidates = append(result.Candidates, addition.Candidates...)
	if err := validateCandidates(result); err != nil {
		return 0, err
	}
	if err := writeCandidateInventory(path, result); err != nil {
		return 0, err
	}
	return len(addition.Candidates), nil
}

func removeCandidate(path string, old Candidate) error {
	if path == "" {
		return errors.New("--file required")
	}
	cfg, err := readCandidateInventory(path, true)
	if err != nil {
		return err
	}
	index := -1
	for i, c := range cfg.Candidates {
		if candidateIdentity(c) == candidateIdentity(old) {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("exact source/direction/sender/receiver candidate not found")
	}
	next := make([]Candidate, 0, len(cfg.Candidates)-1)
	next = append(next, cfg.Candidates[:index]...)
	next = append(next, cfg.Candidates[index+1:]...)
	cfg.Candidates = next
	return writeCandidateInventory(path, cfg)
}

func replaceCandidate(path string, old, updated Candidate) error {
	if path == "" {
		return errors.New("--file required")
	}
	cfg, err := readCandidateInventory(path, true)
	if err != nil {
		return err
	}
	index := -1
	for i, c := range cfg.Candidates {
		if candidateIdentity(c) == candidateIdentity(old) {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("exact candidate identity not found")
	}
	cfg.Candidates[index] = updated
	if err := validateCandidates(cfg); err != nil {
		return err
	}
	return writeCandidateInventory(path, cfg)
}

func sourceCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sources add|list|import|remove|replace")
	}
	if args[0] == "add" {
		return sourceAdd(args)
	}
	cmd := args[0]
	flags := flag.NewFlagSet("sources "+cmd, flag.ContinueOnError)
	path := flags.String("file", "", "existing operator-owned JSON source inventory")
	switch cmd {
	case "list":
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *path == "" {
			return errors.New("--file required")
		}
		cfg, err := readCandidateInventory(*path, true)
		if err != nil {
			return err
		}
		status := "READY_TO_PLAN"
		if len(cfg.Candidates) == 0 {
			status = "NO_CANDIDATES_NOT_RUN"
		}
		return pretty(map[string]any{"schema_version": schema, "mode": cfg.Mode, "candidates": cfg.Candidates, "count": len(cfg.Candidates), "status": status, "network": "NOT_RUN"})
	case "import":
		from := flags.String("from", "", "exact existing CSV/JSON source file to merge")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		added, err := importCandidates(*path, *from)
		if err != nil {
			return err
		}
		return pretty(map[string]any{"imported": added, "status": "SAVED", "network": "NOT_RUN"})
	case "remove", "replace":
		oldIP := flags.String("old-ip", "", "existing candidate exact IPv4")
		oldDirection := flags.String("old-direction", "", "existing direction")
		oldSender := flags.String("old-sender", "", "existing sender")
		oldReceiver := flags.String("old-receiver", "", "existing receiver")
		var ip, direction, sender, receiver *string
		if cmd == "replace" {
			ip = flags.String("ip", "", "new exact candidate IP")
			direction = flags.String("direction", "", "new direction")
			sender = flags.String("sender", "", "new sender")
			receiver = flags.String("receiver", "", "new receiver")
		}
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		old := Candidate{IP: *oldIP, Direction: *oldDirection, Sender: *oldSender, Receiver: *oldReceiver}
		if *path == "" || old.IP == "" || old.Direction == "" || old.Sender == "" || old.Receiver == "" {
			return errors.New("--file, --old-ip, --old-direction, --old-sender, --old-receiver required")
		}
		if cmd == "remove" {
			if err := removeCandidate(*path, old); err != nil {
				return err
			}
			return pretty(map[string]any{"removed": old, "status": "SAVED", "network": "NOT_RUN"})
		}
		if *ip == "" || *direction == "" || *sender == "" || *receiver == "" {
			return errors.New("--ip --direction --sender --receiver required for replace")
		}
		next := Candidate{IP: *ip, Direction: *direction, Sender: *sender, Receiver: *receiver}
		if err := replaceCandidate(*path, old, next); err != nil {
			return err
		}
		return pretty(map[string]any{"replaced": old, "with": next, "status": "SAVED", "network": "NOT_RUN"})
	default:
		return fmt.Errorf("unknown sources subcommand %q", cmd)
	}
}
