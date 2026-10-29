#!/usr/bin/env python3
"""Opt-in, disposable failure-path regression for the QUIC/WG L3 harness.

No process-name scans, broad kill commands, system package changes or host
network mutation. The only SIGKILL targets the exact child that this driver
spawned, using a pidfd. Namespace checks are read-only.
"""
import os
import pathlib
import re
import selectors
import signal
import subprocess
import sys
import time

CASES = (
    "preflight-fail",
    "setup-fail",
    "after-helper-fail",
    "child-term",
    "child-kill",
    "supervisor-preflight-hold",
    "supervisor-materials-hold",
    "supervisor-hold",
)
ROOT = re.compile(r"^QUIC_L3_FAILURE_LAB=(/tmp/stl-quic-wg-l3\.[A-Za-z0-9_-]{8})$")
NAMESPACES = re.compile(
    r"^QUIC_L3_FAULT_READY PIDNS=pid:\[(\d+)\] NETNS=net:\[(\d+)\] SIBLINGNS=net:\[(\d+)\]$"
)


def visible_namespaces(kind):
    result = subprocess.run(
        ["lsns", "-n", "-t", kind, "-o", "NS"], check=True,
        capture_output=True, text=True, timeout=5,
    )
    return set(re.findall(r"\b\d+\b", result.stdout))


def check_released(root, namespaces):
    until = time.monotonic() + 10
    while time.monotonic() < until:
        retained = []
        if root.exists() or root.is_symlink():
            retained.append("private credentials fixture")
        if namespaces:
            pid, net, sibling = namespaces
            if pid in visible_namespaces("pid"):
                retained.append("test PID namespace")
            present_nets = visible_namespaces("net")
            if net in present_nets or sibling in present_nets:
                retained.append("test network namespace")
        if not retained:
            return
        time.sleep(0.1)
    raise AssertionError("disposable failure case retained: " + ", ".join(retained))


def run_case(mode, script, helper, wg):
    env = os.environ.copy()
    env["STL_QUIC_WG_L3_E2E"] = "approved"
    env["STL_QUIC_WG_L3_FAULT"] = mode
    child = subprocess.Popen(
        ["bash", script, helper, wg], env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True,
    )
    root = None
    namespaces = None
    sent_kill = False
    pidfd = None
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    pending = bytearray()
    logs = []
    try:
        deadline = time.monotonic() + 85
        while time.monotonic() < deadline:
            selected = selector.select(timeout=0.25)
            if selected:
                content = os.read(child.stdout.fileno(), 8192)
                if not content:
                    break
                pending.extend(content)
                if len(pending) > 1 << 16:
                    raise AssertionError("unexpected oversized test runner output")
                while b"\n" in pending:
                    raw, _, pending = pending.partition(b"\n")
                    line = raw.decode("utf-8", errors="replace").strip()
                    logs.append(line)
                    match = ROOT.fullmatch(line)
                    if match:
                        root = pathlib.Path(match.group(1))
                    match = NAMESPACES.fullmatch(line)
                    if match:
                        namespaces = match.groups()
                    if (
                        (mode == "supervisor-hold" and match)
                        or (mode == "supervisor-preflight-hold"
                            and line == "QUIC_L3_SUPERVISOR_PREFLIGHT_READY")
                        or (mode == "supervisor-materials-hold"
                            and line == "QUIC_L3_SUPERVISOR_MATERIALS_READY")
                    ):
                        if not sent_kill:
                            # Exact task-owned launcher PID; pidfd excludes
                            # numeric PID reuse and prevents foreign kills.
                            pidfd = os.pidfd_open(child.pid, 0)
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                            sent_kill = True
            elif child.poll() is not None:
                # Wait for pipe EOF; if descendants are leaking the descriptor,
                # the deadline will expose a real containment failure.
                continue
        else:
            raise AssertionError("disposable failure scenario did not terminate in time")

        rc = child.wait(timeout=8)
        if rc == 0:
            raise AssertionError("injected failure unexpectedly succeeded")
        if root is None:
            raise AssertionError("supervisor did not announce its exact owned fixture")
        if mode not in (
            "preflight-fail", "setup-fail",
            "supervisor-preflight-hold", "supervisor-materials-hold",
        ) and namespaces is None:
            raise AssertionError("fault did not reach verified live QUIC workers")
        if mode in (
            "supervisor-hold", "supervisor-preflight-hold",
            "supervisor-materials-hold",
        ) and not sent_kill:
            raise AssertionError("owned supervisor SIGKILL was not delivered")
        check_released(root, namespaces)
        print(f"QUIC_L3_TERMINATION_{mode.upper().replace('-', '_')}=PASS", flush=True)
    except Exception:
        # Do not use process-name matching or kill an arbitrary PID. We
        # still own this un-reaped subprocess; its supervisor/janitor must
        # perform all task-scoped descendant and credential cleanup.
        if child.poll() is None:
            if pidfd is None:
                pidfd = os.pidfd_open(child.pid, 0)
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            except ProcessLookupError:
                pass
        raise
    finally:
        selector.close()
        child.stdout.close()
        if pidfd is not None:
            os.close(pidfd)
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            raise AssertionError("owned launcher failed to terminate after SIGKILL")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: failure-tests.py /abs/script /abs/pinned-hysteria /abs/wg")
    if os.environ.get("STL_QUIC_WG_L3_E2E") != "approved":
        raise SystemExit("REFUSED: explicitly opt in to disposable namespace tests")
    script, helper, wg = sys.argv[1:]
    if not all(pathlib.Path(x).is_absolute() and pathlib.Path(x).is_file()
               for x in (script, helper, wg)):
        raise SystemExit("REFUSED: exact absolute regular local fixtures required")
    for mode in CASES:
        run_case(mode, script, helper, wg)
    print("QUIC_L3_ALL_ABNORMAL_TERMINATION_PATHS=PASS")


if __name__ == "__main__":
    main()
