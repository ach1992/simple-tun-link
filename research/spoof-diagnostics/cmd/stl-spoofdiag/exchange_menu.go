package main

import (
	"bufio"
	"fmt"
)

func menuExchange(reader *bufio.Reader, option string) error {
	switch option {
	case "20":
		return exchangeCLI([]string{"new-case"})
	case "21":
		base, err := menuAsk(reader, "Private exchange base (blank=/root/stl-spoofdiag/exchange)")
		if err != nil {
			return err
		}
		args := []string{"init"}
		if base != "" {
			args = append(args, "--base", base)
		}
		return exchangeCLI(args)
	case "22":
		caseID, err := menuAskNonempty(reader, "Shared 32-hex Case ID")
		if err != nil {
			return err
		}
		dir, err := menuAskNonempty(reader, "Existing local campaign directory")
		if err != nil {
			return err
		}
		role, err := menuAskNonempty(reader, "My evidence role: sender or receiver")
		if err != nil {
			return err
		}
		cert, err := menuAskNonempty(reader, "MY signing certificate path")
		if err != nil {
			return err
		}
		key, err := menuAskNonempty(reader, "MY private signing key path (never exported)")
		if err != nil {
			return err
		}
		ca, err := menuAskNonempty(reader, "Public CA trust certificate path")
		if err != nil {
			return err
		}
		base, err := menuAsk(reader, "Private exchange base (blank=default)")
		if err != nil {
			return err
		}
		args := []string{"export", "--case-id", caseID, "--campaign-dir", dir,
			"--role", role, "--cert", cert, "--key", key, "--ca", ca}
		if base != "" {
			args = append(args, "--base", base)
		}
		return exchangeCLI(args)
	case "23":
		caseID, err := menuAskNonempty(reader, "Shared Case ID to analyze")
		if err != nil {
			return err
		}
		ca, err := menuAskNonempty(reader, "Trusted public CA certificate")
		if err != nil {
			return err
		}
		base, err := menuAsk(reader, "Exchange base containing inbox and reports (blank=default)")
		if err != nil {
			return err
		}
		args := []string{"analyze", "--case-id", caseID, "--ca", ca}
		if base != "" {
			args = append(args, "--base", base)
		}
		return exchangeCLI(args)
	case "25":
		ca, err := menuAskNonempty(reader, "Trusted public CA certificate")
		if err != nil {
			return err
		}
		base, err := menuAsk(reader, "Exchange base containing inbox/archive/rejected (blank=default)")
		if err != nil {
			return err
		}
		args := []string{"import", "--ca", ca}
		if base != "" {
			args = append(args, "--base", base)
		}
		return exchangeCLI(args)
	case "24":
		file, err := menuAskNonempty(reader, "Any signed bundle path, regardless of its filename")
		if err != nil {
			return err
		}
		ca, err := menuAskNonempty(reader, "Trusted public CA certificate")
		if err != nil {
			return err
		}
		return exchangeCLI([]string{"inspect", "--file", file, "--ca", ca})
	}
	return fmt.Errorf("unknown offline exchange menu choice %s", option)
}
