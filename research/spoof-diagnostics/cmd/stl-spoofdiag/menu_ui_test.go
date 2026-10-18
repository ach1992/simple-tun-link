package main

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMenuHelperProcess(t *testing.T) {
	if os.Getenv("SPOOFDIAG_TEST_MENU") != "1" {
		return
	}
	if err := run([]string{"menu"}); err != nil {
		t.Fatal(err)
	}
}

func testMenuSession(t *testing.T, input string) (string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMenuHelperProcess$")
	cmd.Env = append(os.Environ(), "SPOOFDIAG_TEST_MENU=1", "NO_COLOR=1", "COLUMNS=54")
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("menu terminated on valid or invalid input: %v\nSTDOUT:\n%s\nSTDERR:\n%s", err, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String()
}

func TestMenuInvalidInputRecoverAndEOF(t *testing.T) {
	out, errs := testMenuSession(t, "wrong\n3\n?\n4\n/nonexistent/evidence.json\n1\n2\n8\n0\n")
	if strings.Count(out, "STL SPOOF DIAGNOSTICS") != 7 {
		t.Fatalf("menu did not return to top-level after errors (%d): %s", strings.Count(out, "STL SPOOF DIAGNOSTICS"), out)
	}
	for _, want := range []string{"Mode: loopback", "Field traffic: DISABLED", "Evidence levels:", "Go", "Goodbye"} {
		if !strings.Contains(out, want) && !(want == "Go" && strings.Contains(out, "go")) {
			t.Fatalf("menu missing %q: %s", want, out)
		}
	}
	if !strings.Contains(errs, "Unknown choice") || !strings.Contains(errs, "Operation not completed") {
		t.Fatalf("malformed inputs did not produce actionable recoverable errors: %s", errs)
	}
	out, errs = testMenuSession(t, "")
	if !strings.Contains(out, "Session ended.") || errs != "" {
		t.Fatalf("EOF should end normally, got %s / %s", out, errs)
	}
}

func TestMenuInventoryFullLifecycle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sources.json")
	sequence := strings.Join([]string{
		"3", "2", path, "private_lab", "10.91.1.77", "A_TO_B", "A", "B",
		"3", "1", path,
		"3", "5", path, "10.91.1.77", "A_TO_B", "A", "B", "10.91.1.78", "B_TO_A", "B", "A",
		"3", "1", path,
		"3", "4", path, "10.91.1.78", "B_TO_A", "B", "A",
		"3", "1", path,
		"3", "2", path, "", "8.8.8.8", "A_TO_B", "A", "B",
		"0",
	}, "\n") + "\n"
	out, errs := testMenuSession(t, sequence)
	if !strings.Contains(out, "NO_CANDIDATES_NOT_RUN") || !strings.Contains(out, "10.91.1.78") {
		t.Fatalf("menu inventory didn't maintain direction or fail closed on empty list: %s", out)
	}
	if !strings.Contains(errs, "Operation not completed") || !strings.Contains(errs, "private_lab requires RFC1918") {
		t.Fatalf("invalid public source not rejected with meaningful error: %s", errs)
	}
	inv, err := readCandidateInventory(path, true)
	if err != nil || len(inv.Candidates) != 0 {
		t.Fatalf("expected empty safely stored inventory: %+v %v", inv, err)
	}
	if _, err := readCandidates(path); err == nil {
		t.Fatal("empty candidates unexpectedly runnable")
	}
}

func TestMenuOversizedLineDoesNotSkipNextChoice(t *testing.T) {
	out, errs := testMenuSession(t, strings.Repeat("x", 20000)+"\n8\n0\n")
	if !strings.Contains(errs, "input too long") || !strings.Contains(out, "Requirements: Linux") {
		t.Fatalf("oversized input shifted prompt or escaped: %s / %s", out, errs)
	}
}

// Ensure new interactive actions run through the same validation path, report
// failures without killing the session, and never open sockets for a plan.
func TestMenuPlanAndMissingReceiverRecover(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sources.json")
	if err := addSource(path, "private_lab", Candidate{IP: "10.91.1.77", Direction: "A_TO_B", Sender: "A", Receiver: "B"}); err != nil {
		t.Fatal(err)
	}
	sequence := "14\n" + path + "\n9\n/nonexistent/inventory.json\n/no/cert\n/no/key\n/no/ca\nA\nB\n\n\n8\n0\n"
	out, errs := testMenuSession(t, sequence)
	if !strings.Contains(out, "\"network\": \"NOT_RUN\"") || !strings.Contains(out, "10.91.1.77") {
		t.Fatalf("menu plan did not use offline JSON plan: %s", out)
	}
	if !strings.Contains(errs, "Operation not completed") || !strings.Contains(out, "Goodbye") {
		t.Fatalf("menu must recover after missing receiver inputs: %s / %s", out, errs)
	}
}

func TestMenuPublicInventoryOfflineOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidates.json")
	seq := strings.Join([]string{
		"3", "2", path, "approved_field_plan", "8.8.8.8", "A_TO_B", "A", "B",
		"14", path, "0",
	}, "\n") + "\n"
	out, errs := testMenuSession(t, seq)
	if errs != "" {
		t.Fatalf("public address should be accepted as offline plan only: %s", errs)
	}
	if !strings.Contains(out, "\"network\": \"NOT_RUN\"") || !strings.Contains(out, "approved_field_plan") {
		t.Fatalf("did not preserve offline-only field plan: %s", out)
	}
}

// Guarded private-netns submenu must refuse invalid input before any network
// action and resume the top-level operator menu.
func TestMenuIsolatedRawInvalidChallengeRecovery(t *testing.T) {
	input := strings.Join([]string{
		"15", "2", "/no/signed-challenge.json",
		"/no/sender.crt", "/no/sender.key", "/no/ca.crt",
		"A", "B", "sdga0", "", "10.91.2.2", "8", "0",
	}, "\n") + "\n"
	out, errs := testMenuSession(t, input)
	if !strings.Contains(out, "Advanced: isolated private netns") ||
		!strings.Contains(out, "Requirements: Linux") ||
		!strings.Contains(out, "Goodbye") ||
		!strings.Contains(errs, "Operation not completed") {
		t.Fatalf("isolated raw error escaped guarded menu: %s / %s", out, errs)
	}
}

// Exercise the actual menu-driven receiver and sender as two independent
// processes, proving menu choices reach the authenticated loopback transport.
func TestMenuTwoProcessLoopbackReceipt(t *testing.T) {
	identity, ca := testLabCredentials(t)
	file := testSourcesFile(t, "10.90.3.100")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dataPort := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	server := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMenuHelperProcess$")
	server.Env = append(os.Environ(), "SPOOFDIAG_TEST_MENU=1", "NO_COLOR=1")
	server.Stdin = strings.NewReader(strings.Join([]string{
		"9", file, filepath.Join(identity, "B.crt"), filepath.Join(identity, "B.key"),
		ca, "A", "B", strconv.Itoa(controlPort), strconv.Itoa(dataPort), "0",
	}, "\n") + "\n")
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var serverStderr bytes.Buffer
	server.Stderr = &serverStderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if server.ProcessState == nil {
			server.Process.Kill()
			server.Wait()
		}
	}()
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	var serverStdout bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			serverStdout.WriteString(line + "\n")
			if strings.Contains(line, "\"type\": \"ready\"") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
		done <- scanner.Err()
	}()
	select {
	case <-ready:
	case <-time.After(6 * time.Second):
		cancel()
		server.Wait()
		<-done
		t.Fatalf("receiver menu never became ready: stdout=%s stderr=%s", serverStdout.String(), serverStderr.String())
	}
	receipt := filepath.Join(t.TempDir(), "menu-receipt.json")
	client := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMenuHelperProcess$")
	client.Env = append(os.Environ(), "SPOOFDIAG_TEST_MENU=1", "NO_COLOR=1")
	client.Stdin = strings.NewReader(strings.Join([]string{
		"10", file, filepath.Join(identity, "A.crt"), filepath.Join(identity, "A.key"),
		ca, "A", "B", strconv.Itoa(controlPort), receipt, "0",
	}, "\n") + "\n")
	clientOut, err := client.CombinedOutput()
	if err != nil {
		t.Fatalf("menu sender failed: %v %s", err, clientOut)
	}
	if err := server.Wait(); err != nil {
		<-done
		t.Fatalf("menu receiver failed: %v stdout=%s stderr=%s", err, serverStdout.String(), serverStderr.String())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(clientOut), "VERIFIED") || !strings.Contains(string(clientOut), "AUTHENTICATED_LOOPBACK_PEER_OBSERVED") ||
		!strings.Contains(serverStdout.String(), "Goodbye") {
		t.Fatalf("menu session did not complete authenticated exchange: client=%s receiver=%s stderr=%s", clientOut, serverStdout.String(), serverStderr.String())
	}
	if _, err := os.Stat(receipt); err != nil {
		t.Fatalf("menu receiver proof wasn't exported: %v", err)
	}
}
