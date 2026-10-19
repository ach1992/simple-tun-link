package main

import (
	"bufio"
	"errors"
	"strconv"
)

// Guided flows reuse the exact CLI engines. No interactive input runs inside
// the detached service and B never asks for A's source list or signed plan.
func menuPassiveObserve(reader *bufio.Reader) error {
	role, err := menuAsk(reader, "Local observer role A or B (blank=B)")
	if err != nil {
		return err
	}
	if role == "" {
		role = "B"
	}
	bind, err := menuAskNonempty(reader, "Locally assigned receiver IPv4")
	if err != nil {
		return err
	}
	port, err := menuAsk(reader, "UDP port (blank=24572)")
	if err != nil {
		return err
	}
	if port == "" {
		port = "24572"
	}
	duration, err := menuAskNonempty(reader, "Finite observation duration seconds (1..14400)")
	if err != nil {
		return err
	}
	limit, err := menuAsk(reader, "Maximum diagnostic packets captured (blank=1024)")
	if err != nil {
		return err
	}
	if limit == "" {
		limit = "1024"
	}
	out, err := menuAskNonempty(reader, "New private signed passive capture .json output")
	if err != nil {
		return err
	}
	cert, err := menuAskNonempty(reader, "Local receiver signing certificate .crt")
	if err != nil {
		return err
	}
	key, err := menuAskNonempty(reader, "Local receiver signing private key path")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(reader, "Trusted public CA .crt")
	if err != nil {
		return err
	}
	yes, err := menuAsk(reader, "Type OBSERVE to start one finite detached receiver window")
	if err != nil {
		return err
	}
	if yes != "OBSERVE" {
		return errors.New("receiver observation not selected")
	}
	seconds, e := strconv.Atoi(duration)
	if e != nil || seconds < 1 || seconds > passiveMaxWindowSeconds {
		return errors.New("invalid receiver duration")
	}
	args := []string{"start", "--", "field", "observe",
		"--receiver", role, "--bind-ip", bind, "--data-port", port,
		"--window-seconds", duration, "--max-packets", limit,
		"--out", out, "--cert", cert, "--key", key, "--ca", ca}
	return jobCLI(args)
}

func menuPassiveCorrelate(reader *bufio.Reader) error {
	challenge, err := menuAskNonempty(reader, "A or B signed sender challenge .json manually transferred after run")
	if err != nil {
		return err
	}
	capture, err := menuAskNonempty(reader, "Opposite node signed passive observation .json manually transferred after run")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(reader, "Trusted public CA .crt")
	if err != nil {
		return err
	}
	sender, err := menuAsk(reader, "Optional sender signed syscall evidence .json (blank=not available)")
	if err != nil {
		return err
	}
	args := []string{"correlate", "--challenge", challenge, "--capture", capture, "--ca", ca}
	if sender != "" {
		args = append(args, "--sender-report", sender)
	}
	return fieldCLI(args)
}

func menuJobAction(reader *bufio.Reader, verb string) error {
	unit, err := menuAskNonempty(reader, "Exact sdx-16hex.service job ID")
	if err != nil {
		return err
	}
	if verb == "stop" {
		ack, err := menuAsk(reader, "Type STOP to request graceful stop and preserve signed partial evidence")
		if err != nil {
			return err
		}
		if ack != "STOP" {
			return errors.New("job stop not selected")
		}
	}
	return jobCLI([]string{verb, "--unit", unit})
}

func menuReversePrioritize(reader *bufio.Reader) error {
	source, err := menuAskNonempty(reader, "Your OWN B_TO_A source list (TXT/CSV/JSON)")
	if err != nil {
		return err
	}
	ch, err := menuAskNonempty(reader, "Stage-1 A signed Challenge path (manually transferred)")
	if err != nil {
		return err
	}
	capture, err := menuAskNonempty(reader, "Stage-1 B local signed passive observation file")
	if err != nil {
		return err
	}
	sender, err := menuAsk(reader, "Optional A signed sender syscall evidence (blank if unavailable)")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(reader, "Trusted public CA .crt")
	if err != nil {
		return err
	}
	out, err := menuAskNonempty(reader, "NEW B ordered source inventory .json output")
	if err != nil {
		return err
	}
	args := []string{"prioritize", "--file", source, "--hint-challenge", ch,
		"--hint-capture", capture, "--ca", ca, "--out", out}
	if sender != "" {
		args = append(args, "--hint-sender", sender)
	}
	return campaignCLI(args)
}

func menuPassiveFinalCase(reader *bufio.Reader) error {
	id, err := menuAskNonempty(reader, "Shared 32-hex Case ID (operator label)")
	if err != nil {
		return err
	}
	ca, err := menuAskNonempty(reader, "Trusted public CA certificate")
	if err != nil {
		return err
	}
	reports, err := menuAskNonempty(reader, "Existing private 0700 absolute report directory")
	if err != nil {
		return err
	}
	keys := []struct{ flag, label string }{
		{"--ab-plan", "A_TO_B A signed challenge/plan"},
		{"--ab-sender", "A_TO_B A signed sender evidence"},
		{"--ab-capture", "A_TO_B B signed passive capture"},
		{"--ba-plan", "B_TO_A B signed challenge/plan"},
		{"--ba-sender", "B_TO_A B signed sender evidence"},
		{"--ba-capture", "B_TO_A A signed passive capture"},
	}
	args := []string{"analyze-passive", "--case-id", id, "--ca", ca, "--reports", reports}
	for _, entry := range keys {
		value, err := menuAskNonempty(reader, entry.label)
		if err != nil {
			return err
		}
		args = append(args, entry.flag, value)
	}
	return exchangeCLI(args)
}
