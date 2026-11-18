package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMasqueHelperRejectsMissingAndInvalidArgs(t *testing.T) {
	var out, stderr bytes.Buffer
	if exit := masqueHelperCommand(nil, &out, &stderr); exit != 2 ||
		!strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("unexpected missing input: exit=%d stderr=%s", exit, stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if exit := masqueHelperCommand([]string{"dial", "--config", "/nonexistent-credential-material"}, &out, &stderr); exit == 0 ||
		strings.Contains(stderr.String(), "nonexistent-credential-material") {
		t.Fatalf("unsafe helper failure message: exit=%d stderr=%s", exit, stderr.String())
	}
}
