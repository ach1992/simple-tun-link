#!/usr/bin/env python3
"""Local-only native-WireGuard recovery experiment; never an STL Carrier.

Creates two disposable namespaces on ONE development host, preserves their
WireGuard identity, injects a loopback-only outbound blackhole, and restarts
both exact-tuple adapters once after genuine private application failures.
No remote SSH, WAN sockets, host routes, firewall, DNS or STL State changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid


HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "udp53_fixture.py"
ADAPTER = HERE / "udp53_wg_adapter.py"
APPS = HERE / "udp53_apps.py"
EVIDENCE_PARENT = Path("/srv/ai-workspace/stl-research-evidence/2026-10-31-udp53-local")


def execute(argv, *, timeout=20, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command_failed:{argv[:4]!r}:exit={result.returncode}:{result.stderr[-180:]}")
    return result


def receipt(result):
    for line in reversed(result.stdout.splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            pass
    raise RuntimeError("missing_json_receipt")


def events(path):
    if not path.exists():
        return []
    values = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            values.append(json.loads(line))
        except ValueError:
            pass
    return values


def wait_event(path, expected, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for e in events(path):
            if e.get("event") == expected:
                return e
            if e.get("event") in ("ERROR", "FIXTURE_ERROR"):
                raise RuntimeError(f"child_failed:{path}:{e.get('error')}")
        time.sleep(0.05)
    raise RuntimeError(f"event_missing:{expected}:{path}")


def unused_pair():
    sockets = []
    try:
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0))
            sockets.append(s)
        ports = [s.getsockname()[1] for s in sockets]
        if len(set(ports)) != 2:
            raise RuntimeError("local_udp_port_collision")
        return ports
    finally:
        for s in sockets:
            s.close()


def start(name, argv, log, processes):
    f = log.open("x")
    try:
        p = subprocess.Popen(argv, stdout=f, stderr=subprocess.STDOUT,
                             start_new_session=True, close_fds=True)
    finally:
        f.close()
    processes.append((name, p))
    return p


def terminate(name, proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)
            raise RuntimeError(f"forced_kill:{name}")
    return proc.returncode


def ip_probe(local, peer, *, count=3, expect_good=True):
    result = execute(["ip", "netns", "exec", local["name"], "ping", "-n",
                      "-I", local["addr"], "-c", str(count), "-W", "1",
                      peer["addr"]], timeout=count * 3 + 5, check=False)
    good = result.returncode == 0 and f"{count} received" in result.stdout
    if good != expect_good:
        raise RuntimeError(f"unexpected_private_ping:{local['name']}:good={good}:{result.stdout[-140:]}")
    return {"from": local["name"], "to": peer["name"], "ok": good,
            "exit_code": result.returncode}


def app_client(local, peer, kind, phase, run_id, *, expect_good=True):
    argv = ["ip", "netns", "exec", local["name"], sys.executable, str(APPS), kind,
            "--run", run_id, "--side", local["side"], "--bind", local["addr"],
            "--peer", peer["addr"], "--phase", phase, "--port", "42053"]
    if kind == "tcp":
        argv += ["--bytes", "65536", "--tcp-seconds", "5" if not expect_good else "12"]
        timeout = 18
    else:
        argv += ["--count", "8", "--size", "512"]
        timeout = 17
    result = execute(argv, timeout=timeout, check=False)
    record = receipt(result)
    success = record.get("ok") is True and result.returncode == 0
    if success != expect_good:
        raise RuntimeError(f"unexpected_{kind}_result:{local['side']}:{phase}:{record}")
    return record


def assert_server_receipt(log, kind, phase, expected_count):
    event = "TCP_RECEIPT" if kind == "tcp" else "UDP_RECEIPT"
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        for e in events(log):
            if e.get("event") == event and e.get("phase") == phase:
                if kind == "tcp":
                    if (e.get("received") == expected_count and
                            e.get("ok") is True and len(e.get("sha256", "")) == 64):
                        return {"event": event, "phase": phase, "bytes": e["received"],
                                "sha256": e["sha256"]}
                elif e.get("received") == expected_count and e.get("expected") == expected_count:
                    return {"event": event, "phase": phase,
                            "received": e["received"], "expected": e["expected"]}
                raise RuntimeError(f"invalid_receiver_receipt:{phase}:{e}")
        time.sleep(0.05)
    raise RuntimeError(f"receiver_receipt_absent:{phase}")


def compare_identities(sides, original):
    for s in sides:
        actual = receipt(execute([sys.executable, str(FIXTURE), "inspect", "--root", s["root"]]))
        if actual["namespace"] != original[s["side"]]["namespace"]:
            raise RuntimeError("wireguard_namespace_changed")
        key = execute(["ip", "netns", "exec", s["name"], "wg", "show", "wgproof",
                       "public-key"]).stdout.strip()
        if key != original[s["side"]]["public_key"]:
            raise RuntimeError("wireguard_public_identity_changed")
        if int(execute(["ip", "netns", "exec", s["name"], "wg", "show",
                        "wgproof", "listen-port"]).stdout.strip()) != 42511:
            raise RuntimeError("wireguard_listen_port_changed")


def authenticate_native(sides, original, phase, summary):
    verified = {}
    for s in sides:
        expected_peer = original['b' if s['side'] == 'a' else 'a']['public_key']
        output = execute(['ip', 'netns', 'exec', s['name'], 'wg', 'show',
                          'wgproof', 'latest-handshakes']).stdout.strip().splitlines()
        fields = output[0].split() if len(output) == 1 else []
        if len(fields) != 2 or fields[0] != expected_peer or int(fields[1]) <= 0:
            raise RuntimeError('native_wireguard_peer_authentication_not_observed')
        verified[s['side']] = int(fields[1])
    summary['phases'].append({'phase': phase, 'probe': 'native_peer_authentication',
                              'handshake_epochs': verified})


def preserve_fixture_root(s, original, workspace):
    root = Path(s['root'])
    stat = root.stat(follow_symlinks=False)
    identity = original[s['side']]['root_identity']
    if (not root.is_dir() or root.is_symlink() or
            stat.st_dev != identity['dev'] or stat.st_ino != identity['inode'] or
            stat.st_mode & 0o777 != 0o700):
        raise RuntimeError('fixture_root_identity_changed_before_retention')
    expected = {'receipt.json', 'cleanup.json'}
    if {p.name for p in root.iterdir()} != expected:
        raise RuntimeError('unexpected_fixture_root_entries')
    evidence = workspace / ('fixture-' + s['side'])
    evidence.mkdir(mode=0o700)
    for filename in sorted(expected):
        src = root / filename
        if src.is_symlink() or not src.is_file():
            raise RuntimeError('unexpected_fixture_root_file')
        content = src.read_bytes()
        dst = evidence / filename
        with dst.open('xb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if hashlib.sha256(dst.read_bytes()).digest() != hashlib.sha256(content).digest():
            raise RuntimeError('fixture_receipt_copy_not_verified')
    for filename in sorted(expected):
        (root / filename).unlink()
    root.rmdir()
    return {'fixture_receipts_preserved': s['side'], 'source_root_removed': True}


def host_fingerprint():
    commands = [
        ["ip", "-j", "route", "show", "table", "all"],
        ["ip", "-j", "rule", "show"],
        ["ip", "-j", "address", "show"],
        ["nft", "list", "ruleset"],
    ]
    return {" ".join(c): hashlib.sha256(execute(c, timeout=10).stdout.encode()).hexdigest()
            for c in commands if shutil.which(c[0])}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wg-tool", required=True, type=Path)
    a = ap.parse_args()
    if os.geteuid() != 0:
        ap.error("root_required_for_disposable_native_network_namespaces")
    if not a.wg_tool.is_absolute() or not a.wg_tool.is_file() or not os.access(a.wg_tool, os.X_OK):
        ap.error("explicit_extracted_wg_tool_required")
    os.environ["PATH"] = str(a.wg_tool.parent) + ":" + os.environ["PATH"]
    for command in ("ip", "wg", "ping", "nft"):
        if not shutil.which(command):
            ap.error(f"missing_local_test_prerequisite:{command}")
    run_id = uuid.uuid4().hex[:8]
    EVIDENCE_PARENT.mkdir(mode=0o700, parents=False, exist_ok=True)
    workspace = EVIDENCE_PARENT / ("native-" + run_id)
    workspace.mkdir(mode=0o700)
    key_parent = Path("/etc/wireguard")
    created_key_parent = False
    processes = []
    setups = []
    summary = {"run_id": run_id, "kind": "local_native_wg_coordinated_recovery",
               "status": "INCOMPLETE", "wan_tested": False,
               "adapter_sha256": hashlib.sha256(ADAPTER.read_bytes()).hexdigest(),
               "phases": [], "cleanup": []}
    failed = None
    original = {}
    start_baseline = None
    try:
        if not key_parent.exists():
            key_parent.mkdir(mode=0o700)
            created_key_parent = True
        if key_parent.is_symlink() or not key_parent.is_dir() or key_parent.stat().st_uid != 0 or (
                key_parent.stat().st_mode & 0o022):
            raise RuntimeError("unsafe_dev_wireguard_parent")
        start_baseline = host_fingerprint()
        sides = []
        for side, addr, peer in (("a", "10.253.53.1", "10.253.53.2"),
                                 ("b", "10.253.53.2", "10.253.53.1")):
            name = f"u53-lab-{side}-{run_id}"
            root = f"/tmp/stl-u53-lab-{side}-{run_id}"
            key = f"/etc/wireguard/stl-u53-lab-{side}-{run_id}"
            if any(Path(p).exists() for p in (root, key, f"/run/netns/{name}")):
                raise RuntimeError("collision_with_existing_resource")
            s = {"side": side, "name": name, "addr": addr, "peer_addr": peer,
                 "root": root, "key_dir": key}
            setup = receipt(execute([sys.executable, str(FIXTURE), "setup", "--root", root,
                                     "--key-dir", key, "--name", name, "--addr", addr,
                                     "--peer", peer, "--wg-port", "42511",
                                     "--local-port", "42512"]))
            if setup.get("event") != "NAMESPACE_READY":
                raise RuntimeError("fixture_setup_not_ready")
            sides.append(s)
            setups.append(s)
            original[side] = {"namespace": setup["namespace"], "public_key": setup["public_key"],
                              "root_identity": setup["root_identity"]}
        for s in sides:
            other = sides[1 if s["side"] == "a" else 0]
            receipt(execute([sys.executable, str(FIXTURE), "configure", "--root",
                             s["root"], "--pubkey", original[other["side"]]["public_key"]]))
        compare_identities(sides, original)
        for s in sides:
            log = workspace / (s["side"] + "-app.jsonl")
            s["app_log"] = log
            start("app-" + s["side"],
                  ["ip", "netns", "exec", s["name"], sys.executable, str(APPS),
                   "serve", "--run", run_id, "--side", s["side"], "--bind", s["addr"],
                   "--peer", s["peer_addr"], "--port", "42053", "--seconds", "230",
                   "--tcp-seconds", "12"], log, processes)
            wait_event(log, "READY")
        for public_dial in ("a", "b"):
            by_side = {s["side"]: s for s in sides}
            dial, listen = by_side[public_dial], by_side["b" if public_dial == "a" else "a"]
            for gen in (1, 2):
                port_listen, port_dial = unused_pair()
                bindings = {listen["side"]: port_listen, dial["side"]: port_dial}
                adapters = []
                for s, role in ((listen, "listen"), (dial, "dial")):
                    log = workspace / f"{public_dial}-gen{gen}-{s['side']}.jsonl"
                    argv = [sys.executable, str(ADAPTER), "--role", role,
                            "--outer-bind", f"127.0.0.1:{bindings[s['side']]}",
                            "--outer-peer", f"127.0.0.1:{bindings[(dial if role == 'listen' else listen)['side']]}",
                            "--inner-bind", "127.0.0.1:42512",
                            "--inner-peer", "127.0.0.1:42511",
                            "--netns-path", f"/run/netns/{s['name']}",
                            "--run-id", f"lab-{run_id}-{public_dial}-{gen}",
                            "--max-datagram", "1200", "--duration", "220",
                            "--introduction-settle", "0.25"]
                    if role == "dial":
                        argv += ["--introduction"]
                        if gen == 1:
                            argv += ["--lab-drop-outer-after", "13"]
                    p = start(f"{public_dial}-gen{gen}-{s['side']}", argv, log, processes)
                    ready = wait_event(log, "READY")
                    if (ready["outer_local"] != ["127.0.0.1", bindings[s["side"]]] or
                            ready["role"] != role or
                            ready["current_netns"] != {
                                "device": original[s["side"]]["namespace"]["dev"],
                                "inode": original[s["side"]]["namespace"]["inode"]}):
                        raise RuntimeError("adapter_preflight_mismatch")
                    adapters.append((s, role, p, log))
                compare_identities(sides, original)
                label = f"{public_dial}-gen{gen}"
                for s, other in ((dial, listen), (listen, dial)):
                    summary["phases"].append({"phase": label, "probe": "ping",
                                              "result": ip_probe(s, other)})
                for s, other in ((dial, listen), (listen, dial)):
                    for kind in ("tcp", "udp"):
                        phase = f"{public_dial}{gen}{s['side']}{kind}"
                        record = app_client(s, other, kind, phase, run_id)
                        received = assert_server_receipt(other["app_log"], kind, phase,
                                                         65536 if kind == "tcp" else 8)
                        if kind == "tcp" and record["peer_receipt"]["sha256"] != received["sha256"]:
                            raise RuntimeError("sender_receiver_digest_conflict")
                        summary["phases"].append({"phase": phase, "probe": kind,
                                                  "client_ok": True, "receiver": received})
                authenticate_native(sides, original, label, summary)
                if gen == 1:
                    # No new private application packets until the bounded blackhole engages.
                    deadline = time.monotonic() + 18
                    while time.monotonic() < deadline:
                        if events(adapters[1][3])[-1].get("elapsed_s", 0) >= 14:
                            break
                        time.sleep(0.3)
                    else:
                        raise RuntimeError("lab_fault_arming_deadline_expired")
                    # A failed private probe is the trigger, not the WireGuard handshake age.
                    failed_a = ip_probe(dial, listen, count=2, expect_good=False)
                    failed_b = ip_probe(listen, dial, count=2, expect_good=False)
                    blackhole_event = events(adapters[1][3])
                    if not any(e.get("event") == "LAB_OUTER_BLACKHOLE" for e in blackhole_event):
                        raise RuntimeError("expected_lab_blackhole_not_observed")
                    bad_udp = app_client(dial, listen, "udp", f"{public_dial}1fault", run_id,
                                         expect_good=False)
                    if bad_udp.get("acknowledged") != 0:
                        raise RuntimeError("fault_proof_udp_unexpected_ack")
                    summary["phases"].append({"phase": label, "probe": "fault",
                                              "ping_dial_failed": not failed_a["ok"],
                                              "ping_listen_failed": not failed_b["ok"],
                                              "udp_ack": bad_udp["acknowledged"],
                                              "fault_confirmed": True})
                if gen == 2:
                    time.sleep(8)
                    for s, other in ((dial, listen), (listen, dial)):
                        summary["phases"].append({"phase": label, "probe": "post_idle_ping",
                                                  "result": ip_probe(s, other)})
                        for kind in ('tcp', 'udp'):
                            phase = f'{public_dial}{gen}{s["side"]}idle{kind}'
                            record = app_client(s, other, kind, phase, run_id)
                            received = assert_server_receipt(other['app_log'], kind, phase,
                                                             65536 if kind == 'tcp' else 8)
                            if kind == 'tcp' and record['peer_receipt']['sha256'] != received['sha256']:
                                raise RuntimeError('post_idle_sender_receiver_digest_conflict')
                            summary['phases'].append({'phase': phase, 'probe': 'post_idle_' + kind,
                                                      'client_ok': True, 'receiver': received})
                    authenticate_native(sides, original, label + '-post-idle', summary)
                for s, role, p, log in reversed(adapters):
                    code = terminate(f"{public_dial}-{gen}-{s['side']}", p)
                    if code not in (0,):
                        raise RuntimeError(f"adapter_exit_not_clean:{code}")
                compare_identities(sides, original)
                summary["phases"].append({"phase": label, "probe": "identity_still_intact"})
        summary["status"] = "LOCAL_PASS"
    except Exception as exc:
        failed = f"{type(exc).__name__}:{exc}"
        summary["failure"] = failed[:450]
        summary["status"] = "LOCAL_FAIL"
    finally:
        for name, proc in reversed(processes):
            try:
                code = terminate(name, proc)
                summary["cleanup"].append({"process": name, "exit_code": code})
            except Exception as exc:
                summary["cleanup"].append({"process": name, "error": str(exc)[:120]})
        for s in reversed(setups):
            try:
                clean = receipt(execute([sys.executable, str(FIXTURE), "cleanup",
                                         "--root", s["root"]]))
                summary["cleanup"].append({"fixture": s["name"],
                                           "namespace_absent": clean["namespace_absent"],
                                           "key_absent": clean["key_absent"]})
                summary['cleanup'].append(preserve_fixture_root(s, original, workspace))
            except Exception as exc:
                summary["cleanup"].append({"fixture": s["name"], "error": str(exc)[:160]})
        if created_key_parent:
            try:
                key_parent.rmdir()
                summary["cleanup"].append({"dev_wireguard_parent_removed": True})
            except Exception as exc:
                summary["cleanup"].append({"dev_wireguard_parent_removed": False,
                                           "error": str(exc)[:120]})
        if start_baseline is not None:
            try:
                after = host_fingerprint()
                summary["host_baseline_restored"] = start_baseline == after
            except Exception as exc:
                summary["host_baseline_restored"] = False
                summary["baseline_error"] = str(exc)[:150]
        summary["cleanup_ok"] = (summary.get("host_baseline_restored") is True and
                                  all("error" not in item for item in summary["cleanup"]))
        if summary["status"] == "LOCAL_PASS" and not summary["cleanup_ok"]:
            summary["status"] = "LOCAL_FAIL_CLEANUP"
        (workspace / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"evidence_dir": str(workspace), "run_id": run_id,
                          "status": summary["status"], "failure": summary.get("failure"),
                          "cleanup_ok": summary["cleanup_ok"],
                          "host_baseline_restored": summary.get("host_baseline_restored"),
                          "phases": summary["phases"]}, sort_keys=True))
    return 0 if summary["status"] == "LOCAL_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
