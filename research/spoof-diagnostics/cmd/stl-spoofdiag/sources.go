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

// addSource saves one explicit, direction-scoped candidate. There is no CIDR
// expansion or network access. The file is written atomically and mode 0600.
func addSource(path, mode string, item Candidate) error {
	if filepath.Ext(path) != ".json" {
		return errors.New("add requires a JSON source file")
	}
	if path == "" {
		return errors.New("source file path required")
	}
	if item.Direction == "" || item.Sender == "" || item.Receiver == "" {
		return errors.New("source identity incomplete")
	}
	cfg := CandidateFile{SchemaVersion: 1, Mode: mode}
	fi, err := os.Lstat(path)
	if err == nil {
		if !fi.Mode().IsRegular() {
			return errors.New("refusing non-regular or symbolic link source file")
		}
		prev, err := readCandidateInventory(path, true)
		if err != nil {
			return err
		}
		if mode != "" && mode != prev.Mode {
			return errors.New("source file mode mismatch")
		}
		cfg = prev
	} else if !os.IsNotExist(err) {
		return err
	} else if mode == "" {
		return errors.New("new source file requires --mode private_lab or approved_field_plan")
	}
	cfg.Candidates = append(cfg.Candidates, item)
	if err := validateCandidates(cfg); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".spoofdiag-sources-*.tmp")
	if err != nil {
		return err
	}
	pending := temp.Name()
	defer os.Remove(pending)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(&cfg); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(pending, path)
}
func sourceAdd(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("usage: sources add --file PATH --mode private_lab --ip A.B.C.D --direction A_TO_B --sender A --receiver B")
	}
	f := flag.NewFlagSet("sources add", flag.ContinueOnError)
	path := f.String("file", "", "local JSON candidate file")
	mode := f.String("mode", "", "private_lab or approved_field_plan (required for new file)")
	ip := f.String("ip", "", "one exact IPv4 address")
	dir := f.String("direction", "", "A_TO_B or B_TO_A")
	sender := f.String("sender", "", "sender node ID")
	receiver := f.String("receiver", "", "receiver node ID")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || *ip == "" || *dir == "" || *sender == "" || *receiver == "" {
		return errors.New("--file, --ip, --direction, --sender and --receiver required")
	}
	item := Candidate{IP: strings.TrimSpace(*ip), Direction: strings.TrimSpace(*dir), Sender: strings.TrimSpace(*sender), Receiver: strings.TrimSpace(*receiver)}
	if err := addSource(*path, *mode, item); err != nil {
		return err
	}
	fmt.Printf("Added %s for %s to %s (no traffic)\n", item.IP, item.Direction, *path)
	return nil
}
