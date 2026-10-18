package main

import (
	"bufio"
	"strings"
	"testing"
)

// Future no-network menu parser checks; not executed in this request.
func TestMenuBoundedInput(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", 20000) + "\n0\n"))
	if _, err := menuRead(reader); err == nil {
		t.Fatal("oversized menu input accepted")
	}
	next, err := menuRead(reader)
	if err != nil || next != "0" {
		t.Fatalf("menu lost subsequent input: %q %v", next, err)
	}
}
