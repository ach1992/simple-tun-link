#!/usr/bin/env python3
"""STL research-only, opt-in two-node source-address admission diagnostic.

No STL runtime integration. Default mode is local_loopback (never spoofs).
The separately gated permitted_field adapter uses bounded raw IPv4 datagrams
only to an explicitly configured, mutually authenticated, cooperating peer.
Peer receipt is NOT evidence of a return route or private L3 connectivity.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

MAGIC = b"STD1"
WIRE_HEADER = struct.Struct("!4s16sH4s12s")
MIN_PAYLOAD = WIRE_HEADER.size + 32
MAX_CONTROL = 16384
MAX_SAMPLES = 128
SCHEMA = 1


class DiagnosticError(ValueError):
    pass


def exact_ipv4(value):
    if not isinstance(value, str):
        raise DiagnosticError("IPv4 must be a string")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise DiagnosticError("invalid IPv4") from exc
    if str(address) != value:
        raise DiagnosticError("IPv4 must use canonical notation")
    return address


def bounded_int(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise DiagnosticError(f"{label} must be integer {low}..{high}")
    return value


def load_json(path):
    path = Path(path)
    if path.stat().st_size > 32768:
        raise DiagnosticError("configuration exceeds 32 KiB")
    return json.loads(path.read_text(encoding="utf-8"))


def load_config(path):
    value = load_json(path)
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != SCHEMA:
        raise DiagnosticError("unsupported schema_version")
    mode = value.get("mode")
    if mode not in ("local_loopback", "permitted_field"):
        raise DiagnosticError("unknown mode")
    peer = exact_ipv4(value.get("peer_ipv4"))
    candidates = value.get("approved_sources")
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 32:
        raise DiagnosticError("approved_sources requires 1..32 exact IPv4 addresses")
    parsed = [exact_ipv4(x) for x in candidates]
    if len(set(parsed)) != len(parsed):
        raise DiagnosticError("duplicate source address")
    sizes = value.get("payload_sizes")
    if not isinstance(sizes, list) or not 1 <= len(sizes) <= 2:
        raise DiagnosticError("payload_sizes requires 1..2 sizes")
    sizes = [bounded_int(x, 96, 512, "payload size") for x in sizes]
    if len(set(sizes)) != len(sizes):
        raise DiagnosticError("duplicate payload size")
    repetitions = bounded_int(value.get("repetitions"), 1, 2, "repetitions")
    interval_ms = bounded_int(value.get("interval_ms"), 200, 1000, "interval_ms")
    control_port = bounded_int(value.get("control_port"), 1024, 65535, "control_port")
    data_port = bounded_int(value.get("data_port"), 1024, 65535, "data_port")
    if control_port == data_port:
        raise DiagnosticError("control_port and data_port must differ")
    iface = value.get("egress_interface")
    if not isinstance(iface, str) or not 1 <= len(iface) <= 15 or not all(c.isalnum() or c in "_.-" for c in iface):
        raise DiagnosticError("egress_interface must be an explicit Linux interface name")
    if len(parsed) * len(sizes) * repetitions > MAX_SAMPLES:
        raise DiagnosticError("sample count over hard safety bound")
    if mode == "local_loopback":
        if peer != ipaddress.IPv4Address("127.0.0.1") or any(x != peer for x in parsed) or iface != "lo":
            raise DiagnosticError("local_loopback is restricted to 127.0.0.1/lo")
    else:
        if not peer.is_global or any(not x.is_global for x in parsed):
            raise DiagnosticError("field mode requires routable unicast public IPv4 peer and sources")
        if peer in parsed:
            raise DiagnosticError("source cannot equal peer")
    # Canonical equality prevents the two endpoints from silently accepting
    # divergent test definitions and keeps field permission exact-address scoped.
    fingerprint = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    entries = [(i, str(src), size) for i, (src, size, _) in enumerate(
        (src, size, repetition) for src in parsed for size in sizes for repetition in range(repetitions)
    )]
    if (len(entries) - 1) * interval_ms / 1000 + 5 > 120:
        raise DiagnosticError("test would exceed 120-second window")
    return {"mode": mode, "peer": str(peer), "sources": [str(x) for x in parsed],
            "sizes": sizes, "entries": entries, "interval_ms": interval_ms,
            "control_port": control_port, "data_port": data_port,
            "interface": iface, "fingerprint": fingerprint,
            "receive_seconds": (len(entries) - 1) * interval_ms / 1000 + 4}


def require_field_permission(config, args):
    if config["mode"] != "permitted_field":
        return
    if not args.enable_authorized_field or not args.permit:
        raise DiagnosticError("permitted_field requires --enable-authorized-field and --permit")
    permit = load_json(args.permit)
    if not isinstance(permit, dict) or permit.get("schema_version") != 1:
        raise DiagnosticError("invalid permit metadata")
    if permit.get("peer_ipv4") != config["peer"] or permit.get("exact_sources") != config["sources"]:
        raise DiagnosticError("permit peer/sources do not match the manifest")
    for field in ("provider_approval_reference", "source_address_authority_reference", "peer_consent_reference"):
        text = permit.get(field)
        if not isinstance(text, str) or len(text.strip()) < 12 or "placeholder" in text.lower():
            raise DiagnosticError("missing non-placeholder permit reference: " + field)
    try:
        expiry = dt.datetime.fromisoformat(permit["valid_until_utc"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError) as exc:
        raise DiagnosticError("valid_until_utc missing or invalid") from exc
    if expiry.tzinfo is None or expiry <= dt.datetime.now(dt.timezone.utc):
        raise DiagnosticError("permit expired or lacks timezone")
    # Metadata is a human declaration, NOT independent verification of provider
    # permission. The operator MUST actually secure/verify all permissions.


def make_packet(key, run_id, index, src, length, nonce=None):
    if len(key) != 32 or len(run_id) != 16 or length < MIN_PAYLOAD or length > 512:
        raise DiagnosticError("invalid packet parameters")
    nonce = secrets.token_bytes(12) if nonce is None else nonce
    if len(nonce) != 12:
        raise DiagnosticError("invalid nonce")
    body = WIRE_HEADER.pack(MAGIC, run_id, index, exact_ipv4(src).packed, nonce)
    body += b"\x00" * (length - len(body) - 32)
    return body + hmac.new(key, body, hashlib.sha256).digest()


def verify_packet(data, key, run_id, expected, actual_source, used):
    if not MIN_PAYLOAD <= len(data) <= 512 or len(key) != 32:
        return None
    body, tag = data[:-32], data[-32:]
    if not hmac.compare_digest(tag, hmac.new(key, body, hashlib.sha256).digest()):
        return None
    try:
        magic, got_run, index, encoded_source, _ = WIRE_HEADER.unpack(body[:WIRE_HEADER.size])
    except struct.error:
        return None
    if magic != MAGIC or got_run != run_id or index not in expected or index in used:
        return None
    src, size = expected[index]
    if len(data) != size or encoded_source != exact_ipv4(src).packed or actual_source != src:
        return None
    used.add(index)
    return index


def raw_ipv4_packet(src, dst, destination_port, udp_payload, identification):
    # IPv4 UDP checksum=0 is permitted by RFC 768; Linux raw IP_HDRINCL
    # fills/checks the IP header length/checksum. No fragmentation requested.
    if not MIN_PAYLOAD <= len(udp_payload) <= 512:
        raise DiagnosticError("invalid UDP payload")
    src_bytes = exact_ipv4(src).packed
    dst_bytes = exact_ipv4(dst).packed
    udp = struct.pack("!HHHH", 24101, destination_port, 8 + len(udp_payload), 0) + udp_payload
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), identification,
                            0x4000, 64, socket.IPPROTO_UDP, 0, src_bytes, dst_bytes)
    return ip_header + udp


def send_test_packet(config, src, data):
    if config["mode"] == "local_loopback":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            return udp.sendto(data, (config["peer"], config["data_port"]))
    packet = raw_ipv4_packet(src, config["peer"], config["data_port"], data, secrets.randbelow(65536))
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, config["interface"].encode() + b"\x00")
        return raw.sendto(packet, (config["peer"], 0))


def send_msg(conn, msg):
    data = json.dumps(msg, separators=(",", ":"), sort_keys=True).encode()
    if len(data) > MAX_CONTROL - 1:
        raise DiagnosticError("control message too large")
    conn.sendall(data + b"\n")


def recv_msg(conn):
    # Read at most one bounded control-line, never an unlimited file.readline().
    output = bytearray()
    while len(output) < MAX_CONTROL:
        chunk = conn.recv(1)
        if not chunk:
            raise DiagnosticError("control connection closed")
        if chunk == b"\n":
            break
        output.extend(chunk)
    else:
        raise DiagnosticError("control message exceeds limit")
    try:
        obj = json.loads(output)
    except (ValueError, UnicodeDecodeError) as exc:
        raise DiagnosticError("invalid control JSON") from exc
    if not isinstance(obj, dict):
        raise DiagnosticError("control message must be an object")
    return obj


def tls_context(args, server):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=args.ca)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    context.verify_mode = ssl.CERT_REQUIRED
    if not server:
        context.check_hostname = True
    return context


def serve(config, args):
    context = tls_context(args, server=True)
    expected = {i: (src, size) for i, src, size in config["entries"]}
    bind_ipv4 = args.bind_ipv4 or config["peer"]
    bind_address = exact_ipv4(bind_ipv4)
    if bind_address.is_unspecified or bind_address.is_multicast or (config["mode"] == "local_loopback" and bind_ipv4 != "127.0.0.1"):
        raise DiagnosticError("bind_ipv4 must be an explicit owned local interface address")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        udp.bind((bind_ipv4, config["data_port"]))
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_ipv4, config["control_port"]))
        listener.listen(1)
        listener.settimeout(40)
        # No public output or reflected UDP ACK to any claimed source address.
        print(json.dumps({"event": "peer_ready", "mode": config["mode"],
                          "data_port": config["data_port"], "control_port": config["control_port"]}), flush=True)
        sock, _ = listener.accept()
        with sock:
            sock.settimeout(12)
            with context.wrap_socket(sock, server_side=True) as conn:
                hello = recv_msg(conn)
                if hello.get("type") != "begin" or hello.get("fingerprint") != config["fingerprint"]:
                    raise DiagnosticError("peer manifest mismatch")
                try:
                    key = bytes.fromhex(hello["key"])
                    run_id = bytes.fromhex(hello["run_id"])
                except (ValueError, KeyError, TypeError) as exc:
                    raise DiagnosticError("invalid control credentials") from exc
                if len(key) != 32 or len(run_id) != 16:
                    raise DiagnosticError("invalid session key/ID length")
                used = set()
                send_msg(conn, {"type": "ready", "run_id": run_id.hex()})
                deadline = time.monotonic() + config["receive_seconds"]
                while len(used) < len(expected):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    udp.settimeout(remaining)
                    try:
                        payload, address = udp.recvfrom(2048)
                    except socket.timeout:
                        break
                    verify_packet(payload, key, run_id, expected, address[0], used)
                # TLS-authenticated independent peer observations; no claim
                # of sender NIC capture, return-path ACK or VPN feasibility.
                send_msg(conn, {"type": "observations", "run_id": run_id.hex(),
                                "accepted_indices": sorted(used), "return_path": "NOT_TESTED",
                                "sender_egress_capture": "NOT_TESTED", "private_L3": "NOT_TESTED"})
                print(json.dumps({"event": "peer_finished", "valid_observations": len(used),
                                  "total_planned": len(expected)}), flush=True)


def probe(config, args):
    key, run_id = secrets.token_bytes(32), secrets.token_bytes(16)
    submitted = {}
    context = tls_context(args, server=False)
    with socket.create_connection((config["peer"], config["control_port"]), timeout=10) as sock:
        sock.settimeout(config["receive_seconds"] + 15)
        with context.wrap_socket(sock, server_hostname=config["peer"]) as conn:
            send_msg(conn, {"type": "begin", "fingerprint": config["fingerprint"],
                            "run_id": run_id.hex(), "key": key.hex()})
            ready = recv_msg(conn)
            if ready.get("type") != "ready" or ready.get("run_id") != run_id.hex():
                raise DiagnosticError("peer did not authenticate/accept probe plan")
            for index, src, size in config["entries"]:
                packet = make_packet(key, run_id, index, src, size)
                try:
                    submitted[index] = send_test_packet(config, src, packet) >= len(packet)
                except OSError:
                    submitted[index] = False
                # Sleep after every sample except the last; receiver's deadline
                # starts from ready, and has an additional 4-second margin.
                if index < len(config["entries"]) - 1:
                    time.sleep(config["interval_ms"] / 1000)
            result = recv_msg(conn)
    if (result.get("type") != "observations" or result.get("run_id") != run_id.hex()
            or result.get("return_path") != "NOT_TESTED"
            or result.get("sender_egress_capture") != "NOT_TESTED"):
        raise DiagnosticError("invalid peer report")
    observed = result.get("accepted_indices")
    if (not isinstance(observed, list) or any(type(i) is not int or i not in submitted for i in observed)
            or sorted(set(observed)) != observed):
        raise DiagnosticError("invalid/duplicate peer observations")
    observed = set(observed)
    rows = []
    selected = []
    for src in config["sources"]:
        for size in config["sizes"]:
            sample_ids = [i for i, candidate, sample_size in config["entries"] if candidate == src and sample_size == size]
            sends = sum(submitted[i] for i in sample_ids)
            peers = sum(i in observed for i in sample_ids)
            rows.append({"source": src, "payload_size": size, "attempted": len(sample_ids),
                         "kernel_submitted": sends, "authenticated_peer_observed": peers,
                         "status": "PEER_OBSERVED" if peers == sends == len(sample_ids) else "INCOMPLETE_OR_REJECTED"})
        if all(row["status"] == "PEER_OBSERVED" for row in rows if row["source"] == src):
            selected.append(src)
    return {"schema_version": 1, "mode": config["mode"], "run_id": run_id.hex(),
            "scope_fingerprint": config["fingerprint"], "peer": config["peer"],
            "peer_observed_sources": selected, "by_source_and_size": rows,
            "sender_egress_capture": "NOT_TESTED", "return_path": "NOT_TESTED",
            "private_L3": "NOT_TESTED", "provider_field_acceptance": (
                "NOT_RUN" if config["mode"] == "local_loopback" else "MEASURED_THIS_RUN_ONLY"),
            "notice": "Peer observation is not two-way source-IP viability or a tunnel."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "serve", "probe"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--bind-ipv4", help="serve-only: explicit owned local bind IP (for NATed peer hosts)")
    parser.add_argument("--ca", help="mTLS CA PEM for serve/probe")
    parser.add_argument("--cert", help="local mTLS certificate PEM for serve/probe")
    parser.add_argument("--key", help="local mTLS private key PEM for serve/probe")
    parser.add_argument("--permit", help="field-mode, separately obtained approval metadata JSON")
    parser.add_argument("--enable-authorized-field", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        # check has no networking and can safely validate a hypothetical field plan.
        if args.command == "check":
            print(json.dumps({"valid_manifest": True, "mode": config["mode"],
                              "peer": config["peer"], "candidate_count": len(config["sources"]),
                              "planned_packets": len(config["entries"]),
                              "peer_auth": "mTLS-required-for-execution",
                              "spoof_public_field": "NOT_RUN",
                              "return_path": "NOT_TESTED", "private_L3": "NOT_TESTED"}, sort_keys=True))
            return 0
        require_field_permission(config, args)
        if args.bind_ipv4 is not None and args.command != "serve":
            raise DiagnosticError("--bind-ipv4 is only valid with serve")
        if not all((args.ca, args.cert, args.key)):
            raise DiagnosticError("--ca, --cert and --key required for mTLS")
        if args.command == "serve":
            serve(config, args)
        else:
            print(json.dumps(probe(config, args), indent=2, sort_keys=True))
        return 0
    except (DiagnosticError, OSError, ssl.SSLError, json.JSONDecodeError, UnicodeError) as exc:
        print("DIAGNOSTIC_ABORTED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
