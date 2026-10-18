#!/usr/bin/env python3
"""Unprivileged local tests: no spoofed or public packets are transmitted."""
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import ssl

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("stl_spoof_diag", HERE / "stl_spoof_diag.py")
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_manifest():
    c, d = free_port(), free_port()
    while d == c:
        d = free_port()
    return {"schema_version": 1, "mode": "local_loopback", "peer_ipv4": "127.0.0.1",
            "control_port": c, "data_port": d, "approved_sources": ["127.0.0.1"],
            "payload_sizes": [96, 384], "repetitions": 2, "interval_ms": 200,
            "egress_interface": "lo"}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name) / "manifest.json"
        self.manifest = make_manifest()

    def load(self, value=None):
        self.path.write_text(json.dumps(self.manifest if value is None else value))
        return diag.load_config(self.path)

    def test_lab_config_has_bounded_plan(self):
        plan = self.load()
        self.assertEqual(len(plan["entries"]), 4)
        self.assertEqual(plan["sources"], ["127.0.0.1"])
        self.assertLess(plan["receive_seconds"], 10)

    def test_refuses_nonloopback_lab(self):
        self.manifest["approved_sources"] = ["10.0.0.3"]
        with self.assertRaisesRegex(diag.DiagnosticError, "local_loopback"):
            self.load()

    def test_refuses_duplicate_source(self):
        self.manifest["approved_sources"] *= 2
        with self.assertRaisesRegex(diag.DiagnosticError, "duplicate"):
            self.load()

    def test_refuses_duplicate_sizes(self):
        self.manifest["payload_sizes"] = [96, 96]
        with self.assertRaisesRegex(diag.DiagnosticError, "duplicate"):
            self.load()

    def test_refuses_oversize_payload(self):
        self.manifest["payload_sizes"] = [600]
        with self.assertRaisesRegex(diag.DiagnosticError, "payload size"):
            self.load()

    def test_refuses_unbounded_frequency(self):
        self.manifest["interval_ms"] = 1
        with self.assertRaisesRegex(diag.DiagnosticError, "interval_ms"):
            self.load()

    def test_refuses_unknown_mode_and_bool_integer(self):
        self.manifest["mode"] = "internet_scan"
        with self.assertRaises(diag.DiagnosticError):
            self.load()
        self.manifest["mode"] = "local_loopback"
        self.manifest["repetitions"] = True
        with self.assertRaises(diag.DiagnosticError):
            self.load()

    def test_permitted_field_cannot_execute_without_approval(self):
        self.manifest.update(mode="permitted_field", peer_ipv4="8.8.8.8",
                             approved_sources=["1.1.1.1"], egress_interface="eth0")
        plan = self.load()
        self.assertEqual(plan["mode"], "permitted_field")
        class Args:
            enable_authorized_field = False
            permit = None
        with self.assertRaisesRegex(diag.DiagnosticError, "requires"):
            diag.require_field_permission(plan, Args())
        self.assertEqual(diag.main(["check", "--config", str(self.path)]), 0)

    def test_permit_must_match_sources_and_peer(self):
        self.manifest.update(mode="permitted_field", peer_ipv4="8.8.8.8",
                             approved_sources=["1.1.1.1"], egress_interface="eth0")
        plan = self.load()
        permit = pathlib.Path(self.temp.name) / "permit.json"
        permit.write_text(json.dumps({"schema_version": 1, "peer_ipv4": "8.8.8.8",
                                     "exact_sources": ["9.9.9.9"]}))
        class Args:
            enable_authorized_field = True
        args = Args()
        args.permit = str(permit)
        with self.assertRaisesRegex(diag.DiagnosticError, "do not match"):
            diag.require_field_permission(plan, args)

    def test_rejects_reserved_field_source(self):
        self.manifest.update(mode="permitted_field", peer_ipv4="8.8.8.8",
                             approved_sources=["198.51.100.20"], egress_interface="eth0")
        with self.assertRaisesRegex(diag.DiagnosticError, "routable"):
            self.load()

    def test_approved_field_manifest_and_permit_are_static_only(self):
        self.manifest.update(mode="permitted_field", peer_ipv4="8.8.8.8",
                             approved_sources=["1.1.1.1"], egress_interface="eth0")
        plan = self.load()
        permit = pathlib.Path(self.temp.name) / "permit.json"
        permit.write_text(json.dumps({
            "schema_version": 1, "peer_ipv4": "8.8.8.8", "exact_sources": ["1.1.1.1"],
            "provider_approval_reference": "test-authorization-reference-001",
            "source_address_authority_reference": "source-address-permission-002",
            "peer_consent_reference": "peer-consent-ticket-003",
            "valid_until_utc": "2099-01-01T00:00:00Z"
        }))
        class Args:
            enable_authorized_field = True
        args = Args()
        args.permit = str(permit)
        # Pure configuration checking; no socket should be created.
        diag.require_field_permission(plan, args)
        with mock.patch.object(diag.socket, "socket", side_effect=AssertionError("network access")):
            self.assertEqual(diag.main(["check", "--config", str(self.path)]), 0)
        permit.write_text(permit.read_text().replace("2099", "2001"))
        with self.assertRaisesRegex(diag.DiagnosticError, "expired"):
            diag.require_field_permission(plan, args)

    def test_field_port_requires_explicit_iface(self):
        self.manifest.update(mode="permitted_field", peer_ipv4="8.8.8.8",
                             approved_sources=["1.1.1.1"], egress_interface="")
        with self.assertRaisesRegex(diag.DiagnosticError, "interface"):
            self.load()


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.key, self.run_id = os.urandom(32), os.urandom(16)
        self.packet = diag.make_packet(self.key, self.run_id, 7, "10.1.1.7", 128)
        self.expected = {7: ("10.1.1.7", 128)}

    def test_authentic_packet_and_replay_rejected(self):
        used = set()
        self.assertEqual(diag.verify_packet(self.packet, self.key, self.run_id,
                                           self.expected, "10.1.1.7", used), 7)
        self.assertIsNone(diag.verify_packet(self.packet, self.key, self.run_id,
                                             self.expected, "10.1.1.7", used))

    def test_mismatched_real_source_rejected(self):
        self.assertIsNone(diag.verify_packet(self.packet, self.key, self.run_id,
                                             self.expected, "10.1.1.8", set()))

    def test_wrong_session_or_authentication_rejected(self):
        self.assertIsNone(diag.verify_packet(self.packet, self.key, os.urandom(16),
                                             self.expected, "10.1.1.7", set()))
        corrupted = bytearray(self.packet)
        corrupted[-1] ^= 1
        self.assertIsNone(diag.verify_packet(corrupted, self.key, self.run_id,
                                             self.expected, "10.1.1.7", set()))
        self.assertIsNone(diag.verify_packet(self.packet, os.urandom(32), self.run_id,
                                             self.expected, "10.1.1.7", set()))

    def test_source_and_length_are_authenticated(self):
        corrupt = bytearray(self.packet)
        corrupt[diag.WIRE_HEADER.size - 15] ^= 1
        self.assertIsNone(diag.verify_packet(corrupt, self.key, self.run_id,
                                             self.expected, "10.1.1.7", set()))
        self.assertIsNone(diag.verify_packet(self.packet[:-1], self.key, self.run_id,
                                             self.expected, "10.1.1.7", set()))

    def test_raw_wire_header_contains_claimed_source_and_exact_target(self):
        raw = diag.raw_ipv4_packet("10.1.1.7", "10.2.2.2", 24444, self.packet, 99)
        self.assertEqual(raw[0], 0x45)
        self.assertEqual(raw[9], 17)
        self.assertEqual(socket.inet_ntoa(raw[12:16]), "10.1.1.7")
        self.assertEqual(socket.inet_ntoa(raw[16:20]), "10.2.2.2")
        self.assertEqual(int.from_bytes(raw[2:4], "big"), len(raw))
        self.assertEqual(int.from_bytes(raw[22:24], "big"), 24444)
        self.assertEqual(raw[28:], self.packet)

    def test_field_send_binds_exact_interface_without_real_network(self):
        class FakeRaw:
            def __init__(self):
                self.opts = []
                self.sent = None
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def setsockopt(self, *args): self.opts.append(args)
            def sendto(self, payload, address):
                self.sent = (payload, address)
                return len(payload)
        fake = FakeRaw()
        plan = {"mode": "permitted_field", "peer": "8.8.8.8", "data_port": 29991, "interface": "eth0"}
        with mock.patch.object(diag.socket, "socket", return_value=fake):
            sent = diag.send_test_packet(plan, "1.1.1.1", self.packet)
        self.assertEqual(sent, len(fake.sent[0]))
        self.assertEqual(fake.sent[1], ("8.8.8.8", 0))
        self.assertIn((socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0\x00"), fake.opts)
        self.assertEqual(socket.inet_ntoa(fake.sent[0][12:16]), "1.1.1.1")

    def test_control_size_and_malformed_json_fail_closed(self):
        a, b = socket.socketpair()
        with a, b:
            a.sendall(b"[]\n")
            with self.assertRaisesRegex(diag.DiagnosticError, "object"):
                diag.recv_msg(b)


class LocalTLSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subprocess.run(["which", "openssl"], capture_output=True).returncode == 0:
            raise unittest.SkipTest("openssl unavailable")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = pathlib.Path(cls.tmp.name)
        # Ephemeral CA, server and client identities; no services or public network.
        def openssl(*cmd):
            subprocess.run(["openssl", *map(str, cmd)], check=True,
                           capture_output=True, cwd=cls.directory)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=STL Test CA", "-keyout", "ca.key", "-out", "ca.crt")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", "server.key", "-out", "server.csr")
        (cls.directory / "san.ext").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-days", "1", "-in", "server.csr", "-CA", "ca.crt",
                "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.crt",
                "-extfile", "san.ext")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=STL Test Client",
                "-keyout", "client.key", "-out", "client.csr")
        (cls.directory / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
        openssl("x509", "-req", "-days", "1", "-in", "client.csr", "-CA", "ca.crt",
                "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.crt",
                "-extfile", "client.ext")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_authenticated_peer_reports_no_packets_as_empty(self):
        manifest = self.directory / "negative-loopback.json"
        data = make_manifest()
        data["payload_sizes"] = [96]
        data["repetitions"] = 1
        manifest.write_text(json.dumps(data))
        common = ["--config", str(manifest), "--ca", str(self.directory / "ca.crt")]
        server = subprocess.Popen(
            [sys.executable, str(HERE / "stl_spoof_diag.py"), "serve", *common,
             "--cert", str(self.directory / "server.crt"), "--key", str(self.directory / "server.key")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready = server.stdout.readline()
            self.assertEqual(json.loads(ready)["event"], "peer_ready")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_verify_locations(cafile=str(self.directory / "ca.crt"))
            ctx.load_cert_chain(certfile=str(self.directory / "client.crt"),
                                keyfile=str(self.directory / "client.key"))
            plan = diag.load_config(manifest)
            with socket.create_connection(("127.0.0.1", plan["control_port"]), timeout=10) as plain:
                plain.settimeout(10)
                with ctx.wrap_socket(plain, server_hostname="127.0.0.1") as secure:
                    key, run_id = os.urandom(32), os.urandom(16)
                    diag.send_msg(secure, {"type": "begin", "fingerprint": plan["fingerprint"],
                                           "run_id": run_id.hex(), "key": key.hex()})
                    self.assertEqual(diag.recv_msg(secure)["type"], "ready")
                    # Zero packets: do not infer reachability from TLS alone.
                    report = diag.recv_msg(secure)
                    self.assertEqual(report["accepted_indices"], [])
                    self.assertEqual(report["return_path"], "NOT_TESTED")
            server.wait(timeout=6)
            self.assertEqual(server.returncode, 0, server.stderr.read())
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
            server.stdout.close()
            server.stderr.close()

    def test_tls_client_without_certificate_is_rejected(self):
        manifest = self.directory / "bad-client-loopback.json"
        manifest.write_text(json.dumps(make_manifest()))
        common = ["--config", str(manifest), "--ca", str(self.directory / "ca.crt")]
        server = subprocess.Popen(
            [sys.executable, str(HERE / "stl_spoof_diag.py"), "serve", *common,
             "--cert", str(self.directory / "server.crt"), "--key", str(self.directory / "server.key")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(json.loads(server.stdout.readline())["event"], "peer_ready")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_verify_locations(cafile=str(self.directory / "ca.crt"))
            with socket.create_connection(("127.0.0.1", diag.load_config(manifest)["control_port"]), timeout=10) as plain:
                plain.settimeout(10)
                try:
                    with ctx.wrap_socket(plain, server_hostname="127.0.0.1") as tls:
                        tls.sendall(b"\n")
                        try:
                            tls.recv(1)
                        except (ssl.SSLError, ConnectionError, OSError):
                            pass
                except (ssl.SSLError, ConnectionError, OSError):
                    pass
            server.wait(timeout=6)
            self.assertNotEqual(server.returncode, 0, "unauthenticated TLS client must fail")
            self.assertIn("PEER_DID_NOT_RETURN_A_CERTIFICATE", server.stderr.read().upper().replace(" ", "_"))
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
            server.stdout.close()
            server.stderr.close()

    def test_mutual_tls_two_process_loopback_admission(self):
        manifest = self.directory / "loopback.json"
        manifest.write_text(json.dumps(make_manifest()))
        common = ["--config", str(manifest), "--ca", str(self.directory / "ca.crt")]
        server = subprocess.Popen(
            [sys.executable, str(HERE / "stl_spoof_diag.py"), "serve", *common,
             "--cert", str(self.directory / "server.crt"), "--key", str(self.directory / "server.key")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # readiness output occurs after both listeners bound.
            ready = server.stdout.readline()
            self.assertEqual(json.loads(ready)["event"], "peer_ready")
            client = subprocess.run(
                [sys.executable, str(HERE / "stl_spoof_diag.py"), "probe", *common,
                 "--cert", str(self.directory / "client.crt"), "--key", str(self.directory / "client.key")],
                capture_output=True, text=True, timeout=18)
            self.assertEqual(client.returncode, 0, client.stderr)
            result = json.loads(client.stdout)
            self.assertEqual(result["peer_observed_sources"], ["127.0.0.1"])
            self.assertTrue(all(row["authenticated_peer_observed"] == 2 for row in result["by_source_and_size"]))
            self.assertEqual(result["return_path"], "NOT_TESTED")
            self.assertEqual(result["private_L3"], "NOT_TESTED")
            self.assertEqual(result["provider_field_acceptance"], "NOT_RUN")
            server.wait(timeout=10)
            self.assertEqual(server.returncode, 0, server.stderr.read())
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
            server.stdout.close()
            server.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
