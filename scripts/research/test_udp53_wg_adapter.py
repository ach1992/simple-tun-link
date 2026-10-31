#!/usr/bin/env python3
"""Unprivileged real-loopback checks; synthetic WG shapes are not authentication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import threading
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.8)
    return sock


def vacant_endpoint():
    with udp_socket() as sock:
        return sock.getsockname()


def address(endpoint):
    return "%s:%d" % endpoint


def frame(kind, size=None):
    size = size or {1: 148, 2: 92, 3: 64, 4: 32}[kind]
    return bytes([kind, 0, 0, 0]) + bytes([0x40 + kind]) * (size - 4)


def expect_packet(sock, data, source, timeout=0.8):
    sock.settimeout(timeout)
    actual, peer = sock.recvfrom(2048)
    require(actual == data, "forwarded bytes differ")
    require(peer == source, "source tuple changed: %r != %r" % (peer, source))


def expect_silence(sock, duration=0.12):
    sock.settimeout(duration)
    try:
        data, source = sock.recvfrom(2048)
    except socket.timeout:
        return
    raise AssertionError("unexpected packet (%d bytes) from %r" % (len(data), source))


def timestamped_packet(sock):
    # Linux SO_TIMESTAMPNS_OLD is 35; this proof host uses 64-bit native longs.
    timestamp_option = getattr(socket, "SO_TIMESTAMPNS", 35)
    require(struct.calcsize("ll") == 16, "64-bit Linux timestamp layout required")
    data, ancillary, flags, source = sock.recvmsg(2048, socket.CMSG_SPACE(16))
    require(not flags, "unexpected datagram/control truncation")
    stamps = [struct.unpack("ll", value[:16]) for level, kind, value in ancillary
              if level == socket.SOL_SOCKET and kind == timestamp_option]
    require(len(stamps) == 1, "kernel receive timestamp missing")
    sec, nano = stamps[0]
    return data, source, sec * 1_000_000_000 + nano


class Adapter:
    def __init__(self, source, role, extra=(), duration=2.2):
        self.outer_peer = udp_socket()
        self.inner_peer = udp_socket()
        self.outer_bind = vacant_endpoint()
        self.inner_bind = vacant_endpoint()
        while self.inner_bind == self.outer_bind:
            self.inner_bind = vacant_endpoint()
        self.events = []
        self.event_queue = queue.Queue()
        self.started = time.monotonic()
        args = [sys.executable, str(source), "--role", role,
                "--outer-bind", address(self.outer_bind),
                "--outer-peer", address(self.outer_peer.getsockname()),
                "--inner-bind", address(self.inner_bind),
                "--inner-peer", address(self.inner_peer.getsockname()),
                "--loopback-control", "--run-id", "loopback-" + role,
                "--duration", str(duration), "--max-datagram", "256", *extra]
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.reader = threading.Thread(target=self.read_events, daemon=True)
        self.reader.start()
        self.ready = self.wait_event("READY")
        require(self.ready["authentication"] == "not_observed_by_adapter",
                "adapter must not claim authentication")
        self.inode = self.ready["outer_socket_inode"]
        self.check_inode()

    def read_events(self):
        for line in self.process.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {"event": "NON_JSON", "line": line[:200]}
            self.events.append(event)
            self.event_queue.put(event)

    def wait_event(self, name, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            event = self.event_queue.get(timeout=max(0.01, deadline - time.monotonic()))
            if event.get("event") == name:
                return event
            require(event.get("event") not in ("ERROR", "NON_JSON", "STOPPED"),
                    "adapter stopped before %s: %r" % (name, event))
        raise AssertionError("missing event " + name)

    def check_inode(self):
        target = "socket:[%d]" % self.inode
        directory = "/proc/%d/fd" % self.process.pid
        require(target in [os.readlink(directory + "/" + fd) for fd in os.listdir(directory)],
                "original outer socket inode is absent")

    def finish(self):
        code = self.process.wait(timeout=4)
        self.reader.join(timeout=1)
        stderr = self.process.stderr.read()
        require(code == 0, "adapter exit %d: %s" % (code, stderr))
        require(not stderr, "unexpected adapter stderr: " + stderr[:200])
        stops = [e for e in self.events if e.get("event") == "STOPPED"]
        require(len(stops) == 1 and stops[0]["reason"] == "deadline",
                "finite deadline exit missing")
        require(not any(e.get("event") in ("ERROR", "NON_JSON") for e in self.events),
                "unexpected error event")
        require(time.monotonic() - self.started < 5, "deadline did not bound runtime")
        return stops[0]

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.reader.join(timeout=1)
        self.outer_peer.close()
        self.inner_peer.close()
        self.process.stdout.close()
        self.process.stderr.close()


def listener_controls(source):
    a = Adapter(source, "listen", duration=2.4)
    try:
        a.inner_peer.sendto(frame(1), a.inner_bind)
        expect_silence(a.outer_peer)
        with udp_socket() as foreign:
            foreign.sendto(frame(1), a.outer_bind)
            foreign.sendto(frame(1), a.inner_bind)
            expect_silence(a.inner_peer)
            expect_silence(a.outer_peer)
        dns = b"\x12\x34\x81\x80" + b"\0" * 28
        malformed = frame(1)[:-1]
        oversize = frame(4, 400)
        for data in (dns, malformed, oversize):
            a.outer_peer.sendto(data, a.outer_bind)
        expect_silence(a.inner_peer)
        for data in (dns, malformed, oversize):
            a.inner_peer.sendto(data, a.inner_bind)
        expect_silence(a.outer_peer)
        for kind in (1, 2, 3, 4):
            a.outer_peer.sendto(frame(kind), a.outer_bind)
            expect_packet(a.inner_peer, frame(kind), a.inner_bind)
            a.inner_peer.sendto(frame(kind), a.inner_bind)
            expect_packet(a.outer_peer, frame(kind), a.outer_bind)
        a.check_inode()
        end = a.finish()
        c = end["counts"]
        require(c["listener_early_inner"] == 1, "early listener traffic not discarded")
        require(c["invalid_outer"] == c["invalid_inner"] == 2, "invalid packets not classified")
        require(c["truncated_outer"] == c["truncated_inner"] == 1, "truncated packets not classified")
        require(c["introductions"] == 0 and c["inner_tx"] == c["outer_tx"] == 4,
                "unexpected forwarding or introduction")
        require(end["types"]["outer_rx"] == end["types"]["outer_tx"] ==
                {str(k): 1 for k in (1, 2, 3, 4)}, "WG structural type coverage differs")
        return end
    finally:
        a.close()


def dial_without_introduction(source):
    a = Adapter(source, "dial", duration=1)
    try:
        expect_silence(a.outer_peer)
        a.inner_peer.sendto(frame(4, 64), a.inner_bind)
        expect_packet(a.outer_peer, frame(4, 64), a.outer_bind)
        a.outer_peer.sendto(frame(4), a.outer_bind)
        expect_packet(a.inner_peer, frame(4), a.inner_bind)
        a.check_inode()
        end = a.finish()
        require(end["counts"]["introductions"] == 0, "default dial introduced unexpectedly")
        require(end["counts"]["outer_tx"] == end["counts"]["inner_tx"] == 1,
                "default dial forwarding failed")
        return end
    finally:
        a.close()


def introduction_continuity(source):
    a = Adapter(source, "dial", ("--introduction", "--introduction-settle", "0.25"), duration=1.6)
    try:
        a.outer_peer.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_TIMESTAMPNS", 35), 1)
        expect_silence(a.outer_peer)
        a.inner_peer.sendto(frame(1), a.inner_bind)
        a.outer_peer.settimeout(0.8)
        intro, peer, received_intro = timestamped_packet(a.outer_peer)
        require(peer == a.outer_bind and intro[:4] != frame(1)[:4], "introduction source/content wrong")
        require(intro[-4:] == b"\x00\x10\x00\x01", "introduction is not TXT/IN")
        event = a.wait_event("INTRODUCTION_SENT")
        require(event["outer_socket_inode"] == a.inode, "introduction used another inode")
        first_wg, peer, received_wg = timestamped_packet(a.outer_peer)
        require(first_wg == frame(1) and peer == a.outer_bind, "queued frame or tuple changed")
        require(received_wg - received_intro >= 250_000_000, "settle interval bypassed")
        a.inner_peer.sendto(frame(4), a.inner_bind)
        expect_packet(a.outer_peer, frame(4), a.outer_bind)
        a.check_inode()
        expect_silence(a.outer_peer)
        end = a.finish()
        require(end["counts"]["introductions"] == 1, "introduction count differs")
        require(end["counts"]["outer_tx"] == 3, "duplicate introduction or missing WG frame")
        require(len([e for e in a.events if e.get("event") == "INTRODUCTION_SENT"]) == 1,
                "introduction event repeated")
        return end
    finally:
        a.close()


def loopback_fault_is_bounded(source):
    a = Adapter(source, 'dial', ('--lab-drop-outer-after', '0.7'), duration=2.0)
    try:
        a.inner_peer.sendto(frame(1), a.inner_bind)
        expect_packet(a.outer_peer, frame(1), a.outer_bind)
        time.sleep(0.75)
        a.inner_peer.sendto(frame(4), a.inner_bind)
        expect_silence(a.outer_peer)
        end = a.finish()
        require(end['counts']['lab_dropped_outer'] >= 1 and
                end['counts']['send_errors'] == 0,
                'lab fault did not discard packets without false send errors')
        require(len([e for e in a.events if e.get('event') == 'LAB_OUTER_BLACKHOLE']) == 1,
                'lab fault event must occur exactly once')
        require(end['counts']['outer_tx'] == 1,
                'fault must not count discarded datagrams as delivered')
        return end
    finally:
        a.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", type=Path, default=Path(__file__).with_name("udp53_wg_adapter.py"))
    parser.add_argument("--result", type=Path, default=Path(__file__).with_suffix(".result.json"))
    args = parser.parse_args()
    result = {"kind": "real_unprivileged_loopback", "cryptographic_authentication_tested": False,
              "adapter_sha256": hashlib.sha256(args.adapter.read_bytes()).hexdigest(), "cases": []}
    for test in (listener_controls, dial_without_introduction, introduction_continuity,
                 loopback_fault_is_bounded):
        try:
            receipt = test(args.adapter)
            result["cases"].append({"name": test.__name__, "status": "PASS", "receipt": receipt})
        except Exception as exc:
            result["cases"].append({"name": test.__name__, "status": "FAIL",
                                    "error": type(exc).__name__, "detail": str(exc)})
            break
    result["status"] = "PASS" if len(result["cases"]) == 4 and all(
        c["status"] == "PASS" for c in result["cases"]) else "FAIL"
    args.result.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
