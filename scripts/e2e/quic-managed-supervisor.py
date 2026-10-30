#!/usr/bin/env python3
"""Exact-process lifetime boundary for the opt-in, disposable managed QUIC CLI/kernel lab.

This is not a general launcher or an STL runtime service. The original
janitor creates and owns the private fixture before any
sensitive staging; an anonymous socket witnesses controller death. A pidfd binds cleanup to the
exact unshare child, never to a recycled numeric PID. The child itself is
PID 1 in a disposable PID namespace, so killing it destroys all descendants.
Root launch is admitted only for the same-repository GitHub-hosted PR fixture.
"""
import array
import ctypes
import hashlib
import json
import os
import pathlib
import re
import select
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

PR_SET_PDEATHSIG = 1
MAX_SETUP_SECONDS = 300
MAX_LAB_SECONDS = 420
MAX_TERMINATION_MS = 8000
RECOVERY_WAIT_SECONDS = 60


def reject(message):
    raise RuntimeError(message)


def active_helper_identity(observed):
    if (not isinstance(observed, dict) or observed.get("active") is not True or type(observed.get("pid")) is not int
            or type(observed.get("start_time")) is not int or observed["pid"] <= 0 or observed["start_time"] <= 0):
        return None
    return observed["pid"], observed["start_time"]


def wait_for_recovery(probe, deadline):
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        if probe(deadline) and time.monotonic() <= deadline:
            return True, attempts
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.2, remaining))
    return False, attempts


def github_hosted_root_gate(check_event=False, repo=None):
    required = {
        "STL_RUN_PRIVILEGED_E2E": "1",
        "STL_QUIC_MANAGED_ROOT_LAUNCH": "github-hosted-pr",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": "ach1992/simple-tun-link",
        "GITHUB_EVENT_NAME": "pull_request",
    }
    if any(os.environ.get(key) != expected for key, expected in required.items()) or any(
            not re.fullmatch(r"[1-9][0-9]*", os.environ.get(key, ""))
            for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")):
        reject("root launch requires the actual opted-in GitHub-hosted repository PR job")
    if not check_event:
        return
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not os.path.isabs(workspace) or os.path.realpath(workspace) != os.path.realpath(repo) or not os.path.isabs(event_path):
        reject("root fixture source or GitHub event provenance differs")
    descriptor = os.open(event_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 8 << 20:
            reject("bounded GitHub PR event is unavailable")
        event = json.loads(source.read((8 << 20) + 1))
    if not isinstance(event, dict):
        reject("actual GitHub PR event is unavailable")
    pull = event.get("pull_request", {})
    expected = required["GITHUB_REPOSITORY"]
    try:
        repositories = (event["repository"]["full_name"], pull["head"]["repo"]["full_name"], pull["base"]["repo"]["full_name"])
    except (KeyError, TypeError):
        reject("same-repository PR provenance unavailable")
    if any(repository != expected for repository in repositories):
        reject("root fixture requires a same-repository PR")


def fixture_witness(name, maximum=512):
    descriptor = os.open("/lab/" + name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        entry = os.fstat(source.fileno())
        if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != 0 or stat.S_IMODE(entry.st_mode) != 0o600
                or entry.st_nlink != 1 or not 0 < entry.st_size <= maximum):
            reject("private namespace witness metadata differs")
        raw = source.read(maximum + 1)
    if len(raw) != entry.st_size:
        reject("private namespace witness changed")
    return raw.decode("ascii")


def safe_cli_failure(raw):
    """Project fixed public/fixture enums only, never private command output."""
    reasons = {
        "none", "other_redacted", "deadline", "cancelled", "permission", "missing",
        "nft_inventory_unavailable", "nft_inventory_ambiguous", "nft_inventory_shape",
        "nft_inventory_metadata", "nft_inventory_members", "nft_inventory_handle",
        "nft_table_unavailable", "nft_table_shape", "nft_table_identity",
        "helper_parent_trust", "helper_open", "helper_metadata", "helper_digest",
        "helper_readback", "manager_rpc", "underlay_source", "guard_scope", "guard_journal",
        "material_receipt_missing", "material_receipt_rejected",
        "nft_stderr", "legacy_stderr", "iptables_version_stderr", "iptables_backend",
        "nft_foreign_early_hook", "nft_ruleset_schema", "nft_chain_policy",
        "guard_observation_changed", "legacy_readback_failed", "legacy_policy_unverified",
    }
    public_fields = {
        "code": {"invalid", "unsupported", "conflict", "inspect_failed", "plan_failed", "validation_failed",
                 "apply_failed", "verify_failed", "state_failed", "rollback_failed", "internal"},
        "reason_code": {"rejected_before_host_apply", "credential_provision_outcome_unverified", "kernel_module_not_loaded",
                        "state_publication_uncertain", "post_commit_cleanup_incomplete", "rollback_incomplete",
                        "rollback_completed_unverified", "operation_deadline_exceeded_before_apply",
                        "operation_cancelled_before_apply", "apply_outcome_unverified", "state_unverified"},
        "stage": {"preflight", "inspect", "plan", "validate", "apply", "verify", "persistence", "commit",
                  "persistence_cleanup", "credential_provision", "credential_retirement"},
        "host_mutation": {"not_attempted", "attempted"},
        "desired_state": {"no_commit_attempted", "prior_preserved", "visible_unconfirmed", "committed"},
        "rollback": {"not_required", "not_attempted", "completed_unverified", "incomplete"},
        "credential_provision": {"not_attempted", "attempted"},
    }
    fixture_fields = {
        "stage": {"not_reached", "inspect", "plan", "begin", "handoff", "validate", "apply", "verify"},
        "result": {"not_reached", "ok", "failed"},
        "reason": reasons, "check_reason": reasons, "helper_identity": reasons,
        "state_load": reasons, "key_readback": reasons, "material_verified": reasons,
        "check": {"guard_readback", "helper_readback", "guard_preflight"},
        "material_directory": {"absent", "unreadable", "regular", "directory", "other"},
        "material_config": {"absent", "unreadable", "regular", "directory", "other"},
        "material_receipt": {"absent", "unreadable", "regular", "directory", "other"},
        "handoff": {"absent", "unreadable", "regular", "directory", "other"},
    }
    public, fixture = {}, {}

    def project(value, fields):
        return {key: item if type(item) is str and item in fields[key] else "unrecognized"
                for key, item in value.items() if key in fields}

    # A failing command does not justify forwarding its raw stdout/stderr.
    for line in raw[:1 << 20].splitlines()[:256]:
        if len(line) > 8192:
            continue
        marker = b"QUIC_MANAGED_FIXTURE_DIAGNOSTIC="
        try:
            if line.startswith(marker):
                value = json.loads(line[len(marker):])
                if isinstance(value, dict):
                    fixture = project(value, fixture_fields)
                    fixture.update({key: value[key] for key in ("boot_readable", "committed", "journal_present", "key_matches")
                                    if type(value.get(key)) is bool})
            elif line.startswith(b"{"):
                value = json.loads(line)
                if not isinstance(value, dict) or not isinstance(value.get("error"), dict):
                    continue
                error = value["error"]
                public = project(error, public_fields)
                evidence = error.get("evidence")
                if isinstance(evidence, dict):
                    public.update(project(evidence, public_fields))
        except (ValueError, TypeError):
            continue
    return {"public": public, "fixture": fixture}


def death_with_parent(parent_pid):
    # This runs only in a forked, single-threaded subprocess before exec.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(127)
    # The parent might have died before PR_SET_PDEATHSIG was installed.
    if os.getppid() != parent_pid:
        os._exit(127)


def exact_fixture(path, original_stat):
    root = pathlib.Path(path)
    if root.parent != pathlib.Path("/tmp") or not re.fullmatch(
        r"stl-quic-managed\.[A-Za-z0-9_-]{8}", root.name
    ):
        return False
    try:
        now = os.lstat(root)
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(now.st_mode)
        and now.st_uid == os.geteuid()
        and stat.S_IMODE(now.st_mode) == 0o700
        and (now.st_dev, now.st_ino) == (original_stat.st_dev, original_stat.st_ino)
    )


def janitor(watch_socket):
    # Create the fixture in the independent janitor itself: even if the
    # launcher is SIGKILLed before its first preparation command, there is
    # never an unowned private directory left behind by the parent.
    os.setsid()
    root = tempfile.mkdtemp(prefix="stl-quic-managed.", dir="/tmp")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    original_stat = os.lstat(root)
    if not exact_fixture(root, original_stat):
        os.close(root_fd)
        os.rmdir(root)  # Our newly created, still-empty directory only.
        reject("new private test fixture identity invalid")
    try:
        watch_socket.sendall(b"R" + os.fsencode(root) + b"\n")
    except BrokenPipeError:
        # Parent already died; immediately retire the new empty fixture.
        pass
    pidfd = None
    try:
        # Receive an *open pidfd*, not an unchecked host PID.
        raw, controls, _, _ = watch_socket.recvmsg(1, socket.CMSG_SPACE(4))
        if raw:
            if raw != b"P":
                reject("invalid supervisor process identity message")
            for level, kind, value in controls:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received = array.array("i")
                    received.frombytes(value[: len(value) - len(value) % received.itemsize])
                    if len(received) != 1:
                        reject("ambiguous supervisor pidfd identity")
                    pidfd = received[0]
            if pidfd is None:
                reject("missing pinned child-process identity")
        # EOF: the supervising parent finished or was killed (including
        # SIGKILL). The child cannot retain this close-on-exec socket.
        while watch_socket.recv(4096):
            pass
        if pidfd is not None:
            poll = select.poll()
            poll.register(pidfd, select.POLLIN)
            if not poll.poll(250):
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                if not poll.poll(MAX_TERMINATION_MS):
                    reject("exact disposable namespace supervisor did not terminate")
        pinned = os.fstat(root_fd)
        if not exact_fixture(root, original_stat) or (pinned.st_dev, pinned.st_ino) != (original_stat.st_dev, original_stat.st_ino):
            reject("private fixture identity changed before retirement")
        # The janitor has never entered the child's mount namespace. Its view
        # contains only this pinned directory, not the guest's read-only host
        # bind mounts. The fd-based rmtree refuses substituted symlink trees.
        if not shutil.rmtree.avoids_symlink_attacks:
            reject("descriptor-safe private fixture retirement unavailable")
        shutil.rmtree(root)
        if os.path.lexists(root):
            reject("private fixture still present after retirement")
        return 0
    except Exception:
        # No raw credentials, paths, helper logs or foreign process details.
        print("FAIL: disposable QUIC lab cleanup could not be verified", file=sys.stderr)
        return 1
    finally:
        if pidfd is not None:
            os.close(pidfd)
        os.close(root_fd)
        watch_socket.close()


def copy_verified_wg(source, destination):
    """Snapshot one selected lab tool, without executing or changing its source."""
    if not os.path.isabs(source) or os.path.normpath(source) != source or len(source) > 4096 or any(c in source for c in "\x00\r\n"):
        reject("WireGuard fixture path must be absolute and canonical")
    maximum = 32 << 20
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        original = os.fstat(descriptor)
        if (not stat.S_ISREG(original.st_mode) or original.st_uid not in (0, os.geteuid())
                or original.st_mode & 0o6022 or not original.st_mode & 0o111
                or original.st_nlink != 1 or not 0 < original.st_size <= maximum):
            reject("WireGuard fixture owner, mode, type or size is unverified")

        def identity(entry):
            return (entry.st_dev, entry.st_ino, entry.st_mode, entry.st_uid, entry.st_gid,
                    entry.st_nlink, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns)

        digest = hashlib.sha256()
        copied = 0
        output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700)
        with os.fdopen(output_fd, "wb") as output:
            while True:
                block = os.read(descriptor, 1 << 20)
                if not block:
                    break
                copied += len(block)
                if copied > original.st_size or copied > maximum:
                    reject("WireGuard fixture changed size during snapshot")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if copied != original.st_size or identity(os.fstat(descriptor)) != identity(original) or identity(os.stat(source, follow_symlinks=False)) != identity(original):
            reject("selected WireGuard fixture changed during snapshot")
        actual = hashlib.sha256()
        with open(destination, "rb") as checked:
            for block in iter(lambda: checked.read(1 << 20), b""):
                actual.update(block)
        if actual.digest() != digest.digest() or os.stat(destination, follow_symlinks=False).st_size != copied:
            reject("WireGuard private snapshot differs from selected original")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def stage_verified_launcher(repo, source, destination):
    """Retain the exact checkout script while making a private executable copy."""
    if source != str(pathlib.Path(repo, "scripts/e2e/quic-managed-wireguard.sh")):
        reject("launcher does not name the exact checkout fixture")
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as original:
        before = os.fstat(original.fileno())
        owner = os.stat(repo, follow_symlinks=False).st_uid
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid(), owner)
                or before.st_mode & 0o6022 or before.st_nlink != 1 or not 0 < before.st_size <= 128 << 10):
            reject("checkout launcher metadata is unverified")
        contents = original.read((128 << 10) + 1)
        if len(contents) != before.st_size:
            reject("checkout launcher changed during snapshot")
        output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700)
        with os.fdopen(output_fd, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())

        def identity(entry):
            return (entry.st_dev, entry.st_ino, entry.st_mode, entry.st_uid, entry.st_gid,
                    entry.st_nlink, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns)

        if (identity(os.fstat(original.fileno())) != identity(before)
                or identity(os.stat(source, follow_symlinks=False)) != identity(before)
                or pathlib.Path(destination).read_bytes() != contents):
            reject("private launcher differs from the retained checkout source")
        return hashlib.sha256(contents).hexdigest()


def outer(repo, helper, wg_binary, launcher):
    if os.environ.get("STL_RUN_PRIVILEGED_E2E") != "1" or not all(pathlib.Path(p).is_absolute() for p in (repo, helper, wg_binary, launcher)):
        reject("explicit opt-in and owned absolute source/helper paths required")
    origin_uid = os.geteuid()
    namespace_mode = "rootless"
    if origin_uid == 0:
        github_hosted_root_gate(check_event=True, repo=repo)
        namespace_mode = "github-hosted-root"
    elif os.environ.get("STL_QUIC_MANAGED_ROOT_LAUNCH"):
        reject("root fixture authorization cannot change an unprivileged mapping")
    if not shutil.rmtree.avoids_symlink_attacks:
        reject("descriptor-safe disposable cleanup is required")
    parent_sock, watch_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    watcher = os.fork()
    if watcher == 0:
        parent_sock.close()
        os._exit(janitor(watch_sock))
    watch_sock.close()
    pidfd = None
    child = None
    try:
        ready = b""
        while not ready.endswith(b"\n") and len(ready) < 256:
            part = parent_sock.recv(256 - len(ready))
            if not part:
                reject("private fixture janitor unavailable")
            ready += part
        if not ready.startswith(b"R") or not ready.endswith(b"\n"):
            reject("invalid private fixture identity")
        root = os.fsdecode(ready[1:-1])
        initial = os.lstat(root)
        if not exact_fixture(root, initial):
            reject("private fixture provenance changed")
        data = pathlib.Path(root, "data")
        data.mkdir(mode=0o700)
        nonce = secrets.token_hex(16)
        (data / "namespace-guard").write_text(nonce + "\n", encoding="ascii")
        (data / "parent-namespaces").write_text("".join(os.readlink("/proc/self/ns/" + name) + "\n" for name in ("user", "net", "pid", "mnt")), encoding="ascii")
        (data / "origin-uid").write_text(str(origin_uid) + "\n", encoding="ascii")
        (data / "namespace-mode").write_text(namespace_mode + "\n", encoding="ascii")
        for name in ("namespace-guard", "parent-namespaces", "origin-uid", "namespace-mode"):
            os.chmod(data / name, 0o600)
        shutil.copyfile(helper, data / "hysteria")
        os.chmod(data / "hysteria", 0o700)
        wg_digest = copy_verified_wg(wg_binary, data / "wg")
        (data / "wg.sha256").write_text(wg_digest + "\n", encoding="ascii")
        os.chmod(data / "wg.sha256", 0o600)
        shutil.copyfile(pathlib.Path(repo, "scripts/e2e/quic-managed-supervisor.py"), data / "driver.py")
        os.chmod(data / "driver.py", 0o700)
        staged_launcher = data / "launcher.sh"
        launcher_digest = stage_verified_launcher(repo, launcher, staged_launcher)
        (data / "launcher.sha256").write_text(launcher_digest + "\n", encoding="ascii")
        os.chmod(data / "launcher.sha256", 0o600)
        env = os.environ.copy()
        env.update({"STL_QUIC_MANAGED_ROOT": root, "STL_QUIC_MANAGED_LAB": nonce,
                    "GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly -modcacherw -buildvcs=false", "GOWORK": "off", "GOENV": "off"})
        # All build output/caches belong to the same private fixture. Compile
        # the immutable checkout without rewriting go.mod/go.sum or shared caches.
        for key, directory in (("GOCACHE", "build-cache"), ("GOMODCACHE", "module-cache"), ("GOTMPDIR", "build-tmp"), ("GOPATH", "build-gopath")):
            path = pathlib.Path(root, directory)
            path.mkdir(mode=0o700)
            env[key] = str(path)
        owner = os.getpid()
        with open(pathlib.Path(root, "build.log"), "wb") as log:
            build = subprocess.run(["go", "test", "-c", "-tags", "stl_e2e_lab", "-o", str(data / "stl-lab"), "./cmd/stl"],
                                   cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   timeout=MAX_SETUP_SECONDS, preexec_fn=lambda: death_with_parent(owner))
        if build.returncode:
            # Build diagnostics contain source/API names, never staged secrets.
            print(pathlib.Path(root, "build.log").read_text(errors="replace")[-16000:], file=sys.stderr)
            reject("managed CLI test executable did not compile")
        argv = ["unshare", "--user", "--map-root-user", "--net", "--mount", "--pid", "--fork", "--kill-child", "--mount-proc",
                "bash", str(staged_launcher), "--isolated"]
        # The mapped root cannot traverse runner-private checkout ancestors.
        # Only compilation uses that checkout; namespace entry uses our exact
        # verified launcher and cwd below the already-owned private root.
        child = subprocess.Popen(argv, cwd=root, env=env, close_fds=True, preexec_fn=lambda: death_with_parent(owner))
        pidfd = os.pidfd_open(child.pid, 0)
        parent_sock.sendmsg([b"P"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [pidfd]))])
        try:
            code = child.wait(timeout=MAX_LAB_SECONDS)
        except subprocess.TimeoutExpired:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            child.wait(timeout=8)
            reject("managed namespace acceptance exceeded its bounded lifetime")
        if code:
            reject("managed namespace acceptance failed")
    finally:
        if child is not None and child.poll() is None:
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            else:
                child.kill()  # Unreaped direct child created by this process.
            child.wait(timeout=8)
        if pidfd is not None:
            os.close(pidfd)
        parent_sock.close()
        _, status = os.waitpid(watcher, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            reject("private managed fixture cleanup failed")
    print("QUIC_MANAGED_NAMESPACE_CLEANUP=PASS", flush=True)


def namespace_gate():
    token = fixture_witness("namespace-guard", 33).strip()
    if not re.fullmatch(r"[a-f0-9]{32}", token) or os.environ.get("STL_QUIC_MANAGED_LAB") != token or os.geteuid() != 0:
        reject("disposable test witness unavailable")
    parents = fixture_witness("parent-namespaces").splitlines()
    if len(parents) != 4 or any(os.readlink("/proc/self/ns/" + name) == parent for name, parent in zip(("user", "net", "pid", "mnt"), parents)):
        reject("test process shares a parent namespace")
    origin = fixture_witness("origin-uid", 11).strip()
    namespace_mode = fixture_witness("namespace-mode", 32).strip()
    if not re.fullmatch(r"0|[1-9][0-9]{0,9}", origin):
        reject("original mapping witness invalid")
    uid_map = pathlib.Path("/proc/self/uid_map").read_text().split()
    if uid_map != ["0", origin, "1"]:
        reject("independent one-user mapping required")
    if origin == "0":
        if namespace_mode != "github-hosted-root":
            reject("root fixture mapping has no hosted-runner witness")
        github_hosted_root_gate()
    elif namespace_mode != "rootless":
        reject("unprivileged fixture mapping mode differs")
    return namespace_mode


def process_start(pid):
    raw = pathlib.Path("/proc", str(pid), "stat").read_bytes()
    return int(raw[raw.rfind(b")") + 2:].split()[19])


def manager(peer):
    namespace_gate()
    if peer not in ("alpha", "beta"):
        reject("invalid test manager peer")
    endpoint = "/lab/" + peer + "-manager.sock"
    if os.path.lexists(endpoint):
        reject("test manager socket already occupied")
    binary = "/usr/local/libexec/stl/hysteria"
    executable = os.stat(binary, follow_symlinks=False)
    entries = {}

    def inspect(entry):
        if entry["process"].poll() is not None:
            return False
        pid = entry["process"].pid
        if process_start(pid) != entry["start"]:
            reject("owned test helper start identity changed")
        actual = os.stat("/proc/" + str(pid) + "/exe")
        if (actual.st_dev, actual.st_ino) != (executable.st_dev, executable.st_ino):
            reject("owned test helper executable changed")
        if pathlib.Path("/proc", str(pid), "cmdline").read_bytes() != b"\0".join(os.fsencode(a) for a in entry["argv"]) + b"\0":
            reject("owned test helper command changed")
        return True

    def terminate(entry, abrupt=False):
        if not inspect(entry):
            return
        signal.pidfd_send_signal(entry["pidfd"], signal.SIGKILL if abrupt else signal.SIGTERM, None, 0)
        try:
            entry["process"].wait(timeout=4)
        except subprocess.TimeoutExpired:
            signal.pidfd_send_signal(entry["pidfd"], signal.SIGKILL, None, 0)
            entry["process"].wait(timeout=2)
        if inspect(entry):
            reject("owned test helper termination unverified")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(endpoint)
        os.chmod(endpoint, 0o600)
        listener.listen(4)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(8)
                reply = {"ok": False, "active": False, "pid": 0, "start_time": 0}
                try:
                    raw = b""
                    while not raw.endswith(b"\n") and len(raw) <= 4096:
                        chunk = connection.recv(4097 - len(raw))
                        if not chunk:
                            break
                        raw += chunk
                    request = json.loads(raw)
                    if set(request) != {"Action", "LinkID", "Nonce", "Role"}:
                        reject("invalid task supervisor request")
                    action, link, nonce, role = (request[k] for k in ("Action", "LinkID", "Nonce", "Role"))
                    if action not in ("observe", "start", "stop", "kill") or not re.fullmatch(r"lnk_[0-9a-f]{32}", link) or not re.fullmatch(r"[0-9a-f]{32}", nonce) or role not in ("dial", "listen"):
                        reject("invalid task supervisor identity")
                    entry = entries.get(link)
                    if entry is not None and (entry["nonce"], entry["role"]) != (nonce, role):
                        reject("foreign test helper identity")
                    active = entry is not None and inspect(entry)
                    if action == "start" and not active:
                        config = "/lab/" + peer + "-state/credentials/quic/" + link + "/helper.json"
                        argv = [binary, "--disable-update-check", "--log-level", "info", "--log-format", "json", "-c", config, "client" if role == "dial" else "server"]
                        # Private logs are never displayed or uploaded by this lab.
                        with open("/lab/" + peer + "-" + link + "-helper.log", "ab", buffering=0) as log:
                            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                                     env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/", "QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING": "true"}, close_fds=True)
                        fd = os.pidfd_open(child.pid, 0)
                        if entry is not None:
                            os.close(entry["pidfd"])
                        entry = {"process": child, "pidfd": fd, "nonce": nonce, "role": role, "argv": argv, "start": process_start(child.pid)}
                        entries[link] = entry
                        time.sleep(0.12)
                        active = inspect(entry)
                        if not active:
                            reject("official test helper exited during start")
                    elif action in ("stop", "kill") and active:
                        terminate(entry, action == "kill")
                        active = False
                    reply = {"ok": True, "active": active, "pid": entry["process"].pid if active else 0, "start_time": entry["start"] if active else 0}
                except (RuntimeError, OSError, ValueError, KeyError, TypeError):
                    pass
                connection.sendall(json.dumps(reply).encode("ascii") + b"\n")


def test_rpc(peer, record, action):
    link = record["desired"]
    request = {"Action": action, "LinkID": link["id"], "Nonce": record["quic_generation"]["origin_nonce"], "Role": link["quic"]["role"]}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect("/lab/" + peer + "-manager.sock")
        connection.sendall(json.dumps(request).encode() + b"\n")
        raw = b""
        while not raw.endswith(b"\n") and len(raw) < 4096:
            raw += connection.recv(4096 - len(raw))
        reply = json.loads(raw)
        if not reply.get("ok"):
            reject("exact task helper failure injection refused")
        return reply


def echo_server(address, port, ready):
    namespace_gate()
    port = int(port)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((address, port)); tcp.listen(3)
    udp.bind((address, port))
    pathlib.Path(ready).write_text("ready\n", encoding="ascii")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        for current in select.select([tcp, udp], [], [], 1)[0]:
            if current is udp:
                data, remote = udp.recvfrom(2048)
                udp.sendto(data, remote)
            else:
                connection, _ = tcp.accept()
                with connection:
                    connection.settimeout(5)
                    while True:
                        data = connection.recv(65536)
                        if not data:
                            break
                        connection.sendall(data)


def echo_client(source, remote, port):
    namespace_gate()
    port = int(port)
    payload = bytes(range(256)) * 256
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        tcp.settimeout(8); tcp.bind((source, 0)); tcp.connect((remote, port)); tcp.sendall(payload)
        echoed = b""
        while len(echoed) < len(payload):
            part = tcp.recv(len(payload) - len(echoed))
            if not part:
                reject("private TCP echo ended early")
            echoed += part
        if echoed != payload:
            reject("private 64KiB TCP payload changed")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3); udp.bind((source, 0)); udp.connect((remote, port))
        for counter in range(16):
            payload = counter.to_bytes(4, "big") + bytes([counter]) * 1196
            udp.send(payload)
            if udp.recv(2048) != payload:
                reject("private 1200-byte UDP payload changed")


def run_lab():
    namespace_mode = namespace_gate()
    if os.getpid() != 1:
        reject("only the disposable namespace PID 1 may control this fixture")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    print("QUIC_MANAGED_NAMESPACE_MODE=" + namespace_mode, flush=True)
    print("QUIC_MANAGED_EVIDENCE=public-CLI+Engine+real-kernel-WG+nft+official-Hysteria; systemd-and-boot-source=TEST-SHIM", flush=True)
    for peer in ("alpha", "beta"):
        pathlib.Path("/lab/" + peer + "-state").mkdir(mode=0o700)
    holder = subprocess.Popen(["unshare", "--net", "sleep", "400"])
    holder_pidfd = os.pidfd_open(holder.pid, 0)
    alpha_ns = os.readlink("/proc/self/ns/net")
    for _ in range(100):
        if holder.poll() is not None:
            reject("disposable second peer exited")
        if os.readlink("/proc/" + str(holder.pid) + "/ns/net") != alpha_ns:
            break
        time.sleep(0.02)
    else:
        reject("second peer network namespace was not created")

    def prefix(peer):
        return [] if peer == "alpha" else ["nsenter", "-t", str(holder.pid), "-n", "--"]

    def command(peer, args, check=True, timeout=20):
        result = subprocess.run(prefix(peer) + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if check and result.returncode:
            reject("disposable native operation failed: " + args[0])
        return result

    command("alpha", ["ip", "link", "set", "lo", "up"])
    command("beta", ["ip", "link", "set", "lo", "up"])
    command("alpha", ["ip", "link", "add", "stlqma", "type", "veth", "peer", "name", "stlqmb"])
    command("alpha", ["ip", "link", "set", "stlqmb", "netns", str(holder.pid)])
    for peer, interface, address in (("alpha", "stlqma", "172.31.246.1/30"), ("beta", "stlqmb", "172.31.246.2/30")):
        command(peer, ["ip", "address", "add", address, "dev", interface])
        command(peer, ["ip", "link", "set", interface, "up"])
        command(peer, ["ip", "route", "add", "default", "dev", interface])
    command("alpha", ["ping", "-n", "-c", "1", "-W", "1", "172.31.246.2"])
    managers = []
    for peer in ("alpha", "beta"):
        managers.append(subprocess.Popen(prefix(peer) + ["python3", "/lab/driver.py", "manager", peer], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for _ in range(100):
        if all(pathlib.Path("/lab/" + peer + "-manager.sock").is_socket() for peer in ("alpha", "beta")):
            break
        if any(item.poll() is not None for item in managers):
            reject("private test process supervisor exited")
        time.sleep(0.03)
    else:
        reject("private test process supervisor did not become ready")
    sequence = 0

    def cli(peer, args, contents=b"", succeeds=True, interrupted=False, timeout=70):
        nonlocal sequence
        sequence += 1
        env = os.environ.copy()
        env.update({"STL_QUIC_LAB_PEER": peer, "STL_QUIC_LAB_ARGS": json.dumps(["link"] + args)})
        env.pop("STL_QUIC_LAB_FAIL_AFTER_HANDOFF", None)
        if interrupted:
            env["STL_QUIC_LAB_FAIL_AFTER_HANDOFF"] = "1"
        if isinstance(contents, dict):
            contents = json.dumps(contents).encode()
        result = subprocess.run(prefix(peer) + ["/lab/stl-lab", "-test.run", "^TestQUICManagedLabCLI$"],
                                input=contents, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=timeout)
        logfile = pathlib.Path("/lab/" + peer + "-command-" + str(sequence) + ".log")
        logfile.write_bytes(result.stdout); os.chmod(logfile, 0o600)
        if (result.returncode == 0) != succeeds:
            # State and file-presence facts are sampled read-only after failure;
            # they are diagnostics, never authority to resume or remove anything.
            diagnostic = safe_cli_failure(result.stdout)
            print("QUIC_MANAGED_FAILURE_DIAGNOSTIC=" + json.dumps(diagnostic, sort_keys=True, separators=(",", ":")), flush=True)
            public = diagnostic["public"]
            reason = ":" + public.get("code", "unavailable") + ":" + public.get("reason_code", "unavailable")
            reject("managed CLI unexpected result: " + peer + "/" + args[0] + reason)
        for line in result.stdout.splitlines():
            if line.startswith(b"{"):
                return json.loads(line)
        return None

    def snapshot(peer):
        return json.loads(pathlib.Path("/lab/" + peer + "-state/state.json").read_bytes())

    def record(peer, link):
        matches = [r for r in snapshot(peer)["links"] if r["desired"]["id"] == link]
        if len(matches) != 1:
            reject("managed original committed owner missing")
        return matches[0]

    def request(link, subnet, local_port, peer_port, udp_port=0, forward=0, obfuscation=""):
        value = {"schema_version": 1, "link_id": link,
                 "underlay": {"local": "172.31.246.1", "peer": "172.31.246.2"},
                 "addresses": {"local": subnet + ".1/30", "peer": subnet + ".2/30"},
                 "listen_port": local_port, "peer_port": peer_port,
                 "local_keepalive": 1, "peer_keepalive": 1}
        if udp_port:
            value.update({"role": "listen", "udp_port": udp_port, "remote_forward_udp_port": forward})
            if obfuscation:
                value.update({"schema_version": 2, "obfuscation": obfuscation})
        return value

    def pair(value, native=False):
        link = value["link_id"]
        handoff = "/lab/" + link + "-receiver.json"
        cli("alpha", ["create-wireguard" if native else "create-quic", "--stdin", "--output", handoff, "--json"], value)
        raw = pathlib.Path(handoff).read_bytes()
        preview = cli("beta", ["preview" if native else "preview-quic", "--stdin", "--json"], raw)
        confirmation = preview["import_confirmation" if native else "confirmation_sha256"]
        cli("beta", ["import" if native else "import-quic", "--stdin", "--confirm", confirmation, "--json"], raw)
        if not native:
            cli("alpha", ["resume-quic", "--stdin", "--confirm", confirmation, "--json"], raw)
        return raw

    native_id = "lnk_" + "73" * 16
    first_id = "lnk_" + "71" * 16
    second_id = "lnk_" + "72" * 16
    pair(request(native_id, "10.246.3", 51931, 51932), native=True)
    first_raw = pair(request(first_id, "10.246.1", 51821, 51822, 29443, 53001, "salamander"))
    pair(request(second_id, "10.246.2", 51831, 51832, 29444, 53002))
    for peer in ("alpha", "beta"):
        for link, mode in ((first_id, "salamander"), (second_id, "")):
            if record(peer, link)["desired"]["quic"].get("obfuscation", "") != mode:
                reject("managed pairing changed the selected QUIC mode")
            materials = pathlib.Path("/lab/" + peer + "-state/credentials/quic/" + link)
            config = json.loads((materials / "helper.json").read_bytes())
            secret_path = materials / "obfs-secret"
            if mode:
                secret = secret_path.read_bytes()
                authorization = (materials / "authorization-token").read_bytes()
                if (secret_path.stat().st_mode & 0o777 != 0o600 or
                        secret == authorization or
                        config.get("obfs") != {"type": "salamander", "salamander": {"password": secret.decode().strip()}}):
                    reject("managed Salamander protected material/config binding failed")
            elif secret_path.exists() or "obfs" in config:
                reject("legacy-input Plain sibling acquired obfuscation material")
    print("QUIC_MANAGED_SALAMANDER_AND_LEGACY_PLAIN_PAIRING=PASS", flush=True)
    print("QUIC_MANAGED_SEPARATE_PROCESS_CREATE_PREVIEW_IMPORT_RESUME_TWO_LINKS=PASS", flush=True)

    def ping(peer, source, destination, required=True):
        result = command(peer, ["ping", "-n", "-I", source, "-c", "1", "-W", "1", destination], check=False, timeout=3)
        if required and result.returncode:
            reject("bilateral managed private ICMP failed")
        return result.returncode == 0

    def await_ping(peer, source, destination):
        for _ in range(25):
            if ping(peer, source, destination, False):
                return
            time.sleep(0.2)
        reject("managed private link did not become reachable")

    for subnet in ("10.246.1", "10.246.2", "10.246.3"):
        await_ping("alpha", subnet + ".1", subnet + ".2")
        await_ping("beta", subnet + ".2", subnet + ".1")
    echo_workers = []
    for subnet in ("10.246.1", "10.246.2"):
        for peer, suffix in (("alpha", ".1"), ("beta", ".2")):
            ready = "/lab/echo-" + subnet + suffix
            echo_workers.append(subprocess.Popen(prefix(peer) + ["python3", "/lab/driver.py", "echo-server", subnet + suffix, "41111", ready], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            for _ in range(100):
                if pathlib.Path(ready).is_file():
                    break
                time.sleep(0.02)
            else:
                reject("owned private application listener unavailable")

    def applications(subnet):
        command("alpha", ["python3", "/lab/driver.py", "echo-client", subnet + ".1", subnet + ".2", "41111"], timeout=15)
        command("beta", ["python3", "/lab/driver.py", "echo-client", subnet + ".2", subnet + ".1", "41111"], timeout=15)

    for subnet in ("10.246.1", "10.246.2"):
        applications(subnet)
    initial_diagnostics = {}
    for peer in ("alpha", "beta"):
        for link in (first_id, second_id):
            current = record(peer, link)
            status = cli(peer, ["status", link, "--json"])
            if not status["interface_verified"] or status["connectivity"] != "not_measured" or not status["quic_state"]["quic_helper_active"]:
                reject("managed status does not distinguish local readiness from connectivity")
            info = cli(peer, ["diagnose-quic", link, "--json"])
            if not info["wireguard_handshake_observed"] or info["rx_bytes"] <= 0 or info["tx_bytes"] <= 0:
                reject("managed WireGuard handshake/counters unavailable after real traffic")
            if link == first_id:
                initial_diagnostics[peer] = info
            quality = cli(peer, ["diagnose", link, "--json"])
            if quality["quality"]["packets_received"] != 5 or not quality["quality"]["reachable"]:
                reject("managed five-ping diagnostics did not observe peer replies")
            # Auto's conservative start is a policy, not a measured path MTU.
            interface = status["quic_state"]["interface"]
            metadata = json.loads(command(peer, ["ip", "-j", "link", "show", "dev", interface]).stdout)[0]
            if current["desired"]["mtu"]["mode"] != "auto" or metadata["mtu"] != 1280:
                reject("managed QUIC did not enforce conservative automatic MTU")
    print("QUIC_MANAGED_BILATERAL_ICMP_TCP64K_UDP16X1200_STATUS_DIAGNOSE=PASS", flush=True)

    def guard_counter(peer, link):
        table = "stlquic_" + hashlib.sha256(("quic:" + link).encode()).hexdigest()[:16]
        result = json.loads(command(peer, ["nft", "-j", "-a", "list", "table", "inet", table]).stdout)
        counters = [expr["counter"]["packets"] for item in result["nftables"] if "rule" in item for expr in item["rule"]["expr"] if "counter" in expr]
        if len(counters) != 1:
            reject("original QUIC drop-counter shape differs")
        return counters[0]

    for peer, remote, physical, port in (("alpha", "beta", "172.31.246.1", 51821), ("beta", "alpha", "172.31.246.2", 51822)):
        before = guard_counter(peer, first_id)
        code = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'disposable-guard-check',(" + repr(physical) + "," + str(port) + "))"
        command(remote, ["python3", "-c", code])
        time.sleep(0.1)
        if guard_counter(peer, first_id) <= before:
            reject("physical kernel WG port bypassed original ingress guard")
    print("QUIC_MANAGED_BOTH_PHYSICAL_WG_UDP_PORTS_DROP=PASS", flush=True)

    def identity(peer, link):
        current = record(peer, link)
        return current["desired"], current.get("quic_generation"), current.get("owned_resources")

    siblings = {(peer, link): identity(peer, link) for peer in ("alpha", "beta") for link in (second_id, native_id)}
    original = {peer: identity(peer, first_id) for peer in ("alpha", "beta")}
    original_helpers = {peer: active_helper_identity(test_rpc(peer, record(peer, first_id), "observe"))
                        for peer in ("alpha", "beta")}
    if any(value is None for value in original_helpers.values()):
        reject("original helper process identities are unavailable before failure injection")
    owned = record("alpha", first_id)
    test_rpc("alpha", owned, "kill")
    if ping("alpha", "10.246.1.1", "10.246.1.2", False):
        reject("QUIC helper absence still allowed private traffic")
    down = cli("alpha", ["status", first_id, "--json"])
    if down["quic_state"]["quic_helper_active"]:
        reject("dead helper was presented as active")
    ping("alpha", "10.246.2.1", "10.246.2.2")
    ping("alpha", "10.246.3.1", "10.246.3.2")
    for peer in ("alpha", "beta"):
        cli(peer, ["restore", "--all"])
    restore_finished = time.monotonic()
    restored_helpers = {}

    def recovery_facts(phase, wait_elapsed_ms=0, attempts=0):
        # Only exact-process comparisons and finite public diagnostic fields
        # leave this fixture. No PID, names, keys, config or helper logs do.
        report = {"phase": phase, "wait_elapsed_ms": wait_elapsed_ms, "attempts": attempts,
                  "wait_limit_ms": RECOVERY_WAIT_SECONDS * 1000}
        lifecycle_ok = True
        for peer, role in (("alpha", "listener"), ("beta", "dial")):
            facts = {"process_observed": False, "generation_unchanged": False,
                     "process_identity_expected": False, "diagnostics_observed": False}
            try:
                current = active_helper_identity(test_rpc(peer, record(peer, first_id), "observe"))
                facts["process_observed"] = current is not None
                facts["generation_unchanged"] = identity(peer, first_id) == original[peer]
                facts["process_changed_from_original"] = current is not None and current != original_helpers[peer]
                expected = current != original_helpers[peer] if peer == "alpha" else current == original_helpers[peer]
                facts["process_identity_expected"] = current is not None and expected and (
                    peer not in restored_helpers or current == restored_helpers[peer])
                if phase == "post_restore":
                    restored_helpers[peer] = current
            except (RuntimeError, OSError, ValueError, KeyError, TypeError):
                pass
            lifecycle_ok = lifecycle_ok and all(facts[key] for key in (
                "process_observed", "generation_unchanged", "process_identity_expected"))
            try:
                details = cli(peer, ["diagnose-quic", first_id, "--json"], timeout=10)
                for field in ("quic_helper_active", "wg_ingress_guard_active", "kernel_wireguard_present"):
                    facts[field] = details.get(field) is True
                for field in ("rx_bytes", "tx_bytes"):
                    value, before = details[field], initial_diagnostics[peer][field]
                    if type(value) is not int or type(before) is not int or not 0 <= before <= value < 1 << 64:
                        raise ValueError("bounded diagnostic counter unavailable")
                    facts[field + "_delta"] = value - before
                facts["handshake_advanced"] = details.get("last_handshake_unix", 0) > initial_diagnostics[peer].get("last_handshake_unix", 0)
                facts["diagnostics_observed"] = True
            except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
                pass
            report[role] = facts
        report["post_restore_elapsed_ms"] = int((time.monotonic() - restore_finished) * 1000)
        print("QUIC_MANAGED_RECOVERY_OBSERVATION=" + json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
        return lifecycle_ok

    if not recovery_facts("post_restore"):
        reject("restore did not preserve the required exact helper and saved generation identities")

    # Pinned Hysteria v2.13.0 defaults MaxIdleTimeout to 30s. Forwarding Feed
    # refreshes its UDP-session idle clock, so 1s WG keepalives do not let the
    # configured 20s forwarding timeout bound recovery. After ReceiveLoop
    # loses the QUIC session, one UDP() call clears the closed client and a
    # later call reconnects. Allow 60s for that sequence and WG delivery;
    # this is a test observation budget, not a protocol guarantee or SLO.
    # Initial startup keeps its original bound; the live dial is never reset.
    def recovery_ping(deadline):
        for peer, source, destination in (("alpha", "10.246.1.1", "10.246.1.2"),
                                           ("beta", "10.246.1.2", "10.246.1.1")):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                result = command(peer, ["ping", "-n", "-I", source, "-c", "1", "-W", "1", destination],
                                 check=False, timeout=min(3, remaining))
            except subprocess.TimeoutExpired:
                return False
            if result.returncode:
                return False
        return True

    wait_started = time.monotonic()
    recovered, attempts = wait_for_recovery(recovery_ping, wait_started + RECOVERY_WAIT_SECONDS)
    wait_elapsed_ms = int((time.monotonic() - wait_started) * 1000)
    lifecycle_ok = recovery_facts("reachable" if recovered else "timeout", wait_elapsed_ms, attempts)
    if not recovered:
        reject("managed private link recovery exceeded its bounded observation deadline")
    if not lifecycle_ok:
        reject("helper or saved generation identity changed during recovery")
    applications("10.246.1")
    for peer in ("alpha", "beta"):
        if identity(peer, first_id) != original[peer]:
            reject("helper repair replaced committed WG/material/guard generation")
        cli(peer, ["ensure", "--stdin", "--json"], {"schema_version": 5, "link": record(peer, first_id)["desired"]})
    print("QUIC_MANAGED_HELPER_FAILURE_BLOCKS_TRAFFIC_AND_CANONICAL_RESTORE_REPAIRS=PASS", flush=True)
    print("QUIC_MANAGED_REBOOT_PROOF=NOT_RUN; restore above reconciles the same kernel generation", flush=True)

    for suffix, value in (("port", request("lnk_" + "74" * 16, "10.246.4", 51831, 51842, 29445, 53004)),
                          ("subnet", request("lnk_" + "75" * 16, "10.246.2", 51851, 51852, 29446, 53005))):
        previous = pathlib.Path("/lab/alpha-state/state.json").read_bytes()
        output = "/lab/conflict-" + suffix + ".json"
        cli("alpha", ["create-quic", "--stdin", "--output", output, "--json"], value, succeeds=False)
        if pathlib.Path(output).exists() or pathlib.Path("/lab/alpha-state/state.json").read_bytes() != previous:
            reject("conflicting QUIC intent mutated State or published credentials")
    print("QUIC_MANAGED_PORT_AND_SUBNET_CONFLICTS_FAIL_BEFORE_MUTATION=PASS", flush=True)

    for peer in ("alpha", "beta"):
        cli(peer, ["remove", first_id, "--confirm", first_id, "--json"])
        if any(item["desired"]["id"] == first_id for item in snapshot(peer)["links"]):
            reject("managed Remove retained desired owner")
        cli(peer, ["retire-quic", first_id, "--confirm", first_id, "--json"])
        cli(peer, ["retire-quic", first_id, "--confirm", first_id, "--json"])
        receipt = [item for item in snapshot(peer)["removal_receipts"] if item["link_id"] == first_id]
        if len(receipt) != 1 or not receipt[0]["retired"] or receipt[0]["quic_original_termination"] != "original-ifindex-deleted-v1":
            reject("managed retirement receipt lacks original-termination proof")
        for link in (second_id, native_id):
            if identity(peer, link) != siblings[(peer, link)]:
                reject("target lifecycle changed an independent sibling")
    applications("10.246.2")
    ping("alpha", "10.246.3.1", "10.246.3.2")
    ping("beta", "10.246.3.2", "10.246.3.1")
    print("QUIC_MANAGED_REMOVE_RETIRE_AND_NATIVE_QUIC_SIBLING_ISOLATION=PASS", flush=True)

    interrupted_id = "lnk_" + "76" * 16
    interrupted_file = "/lab/interrupted-original.json"
    cli("alpha", ["create-quic", "--stdin", "--output", interrupted_file, "--json"],
        request(interrupted_id, "10.246.6", 51861, 51862, 29447, 53006, "salamander"), succeeds=False, interrupted=True)
    interrupted_raw = pathlib.Path(interrupted_file).read_bytes()
    confirmation = hashlib.sha256(interrupted_raw.removesuffix(b"\n")).hexdigest()
    journal_before = pathlib.Path("/lab/alpha-state/state.json").read_bytes()
    cli("alpha", ["resume-quic", "--stdin", "--confirm", confirmation, "--json"], interrupted_raw, succeeds=False)
    if pathlib.Path("/lab/alpha-state/state.json").read_bytes() != journal_before:
        reject("interrupted first creation was silently replayed")
    cli("alpha", ["reconcile-quic-cold-boot", interrupted_id, "--confirm", interrupted_id, "--json"], succeeds=False)
    if pathlib.Path("/lab/alpha-state/state.json").read_bytes() != journal_before:
        reject("same-boot reconciliation altered the quarantined original journal")
    pending = snapshot("alpha").get("quic_crash_operations", [])
    if len(pending) != 1 or pending[0].get("managed", {}).get("intent", {}).get("id") != interrupted_id:
        reject("interrupted managed journal not durably quarantined")
    cli("alpha", ["status", second_id, "--json"])
    print("QUIC_MANAGED_INTERRUPTED_CREATION_REMAINS_QUARANTINED=PASS", flush=True)
    print("QUIC_MANAGED_NAMESPACE_ACCEPTANCE=PASS", flush=True)
    # No numeric-PID/name cleanup. PID-1 exit destroys the entire disposable
    # hierarchy; outer retained pidfd + independent janitor verify retirement.
    os.close(holder_pidfd)


if __name__ == "__main__":
    try:
        mode = sys.argv[1] if len(sys.argv) > 1 else ""
        if mode == "outer" and len(sys.argv) == 6:
            outer(*sys.argv[2:])
        elif mode == "manager" and len(sys.argv) == 3:
            manager(sys.argv[2])
        elif mode == "run" and len(sys.argv) == 2:
            run_lab()
        elif mode == "echo-server" and len(sys.argv) == 5:
            echo_server(*sys.argv[2:])
        elif mode == "echo-client" and len(sys.argv) == 5:
            echo_client(*sys.argv[2:])
        else:
            reject("invalid bounded disposable test mode")
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("QUIC managed lab FAILED: " + str(error), file=sys.stderr, flush=True)
        sys.exit(1)
