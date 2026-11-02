#!/usr/bin/env python3
"""Bounded receiver-hash witness for disposable L2TPv3 private TCP E2E.

Only invoked on explicitly approved, isolated network namespaces. This is a
data-integrity check, not a WAN reachability or performance benchmark.
"""
import hashlib
import json
import socket
import sys
import time

if len(sys.argv) != 7:
    raise SystemExit("usage: l2tpv3-tcp.py <server|client> <source-ip> <dest-ip> <port> <MiB> <run-tag>")

action, source, dest, port, size_mib, tag = sys.argv[1:]
port = int(port)
size_mib = int(size_mib)
if not (1 <= size_mib <= 128 and 1024 <= port <= 65535):
    raise SystemExit("invalid bounded E2E size or port")
expected_length = size_mib * 1024 * 1024

if action == "server":
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((source, port))
    listener.listen(1)
    listener.settimeout(25)
    print(f"RECEIVER_READY {source}:{port} tag={tag}", flush=True)
    conn, peer = listener.accept()
    conn.settimeout(35)
    digest = hashlib.sha256()
    received = 0
    while received < expected_length:
        chunk = conn.recv(min(131072, expected_length - received))
        if not chunk:
            raise SystemExit("receiver: premature EOF")
        digest.update(chunk)
        received += len(chunk)
    conn.sendall((digest.hexdigest() + "\n").encode("ascii"))
    conn.close()
    print(json.dumps({
        "event": "RECEIVER_SHA256",
        "tag": tag,
        "bytes": received,
        "peer": peer[0],
        "sha256": digest.hexdigest(),
    }), flush=True)
elif action == "client":
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.bind((source, 0))
    conn.settimeout(35)
    conn.connect((dest, port))
    start = time.monotonic()
    digest = hashlib.sha256()
    for i in range(expected_length // 32768):
        chunk = hashlib.shake_256(f"stl-l2tpv3-e2e:{tag}:{i}".encode()).digest(32768)
        digest.update(chunk)
        conn.sendall(chunk)
    witness = bytearray()
    while not witness.endswith(b"\n"):
        chunk = conn.recv(100)
        if not chunk or len(witness) + len(chunk) > 80:
            raise SystemExit("sender: invalid receiver receipt")
        witness.extend(chunk)
    if witness.decode("ascii").strip() != digest.hexdigest():
        raise SystemExit("sender: receiver SHA256 does not match transmitted data")
    conn.close()
    print(json.dumps({
        "event": "SENDER_PEER_SHA256_VERIFIED",
        "tag": tag,
        "bytes": expected_length,
        "sha256": digest.hexdigest(),
        "seconds": round(time.monotonic()-start, 3),
    }), flush=True)
else:
    raise SystemExit("invalid test role")
