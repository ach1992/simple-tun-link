#!/usr/bin/env python3
"""Exact-process lifetime boundary for the opt-in, disposable QUIC L3 lab.

This is not a general launcher or an STL runtime service. The original
unprivileged janitor creates and owns the private fixture before any
sensitive staging; an anonymous socket witnesses controller death. A pidfd binds cleanup to the
exact unshare child, never to a recycled numeric PID. The child itself is
PID 1 in a disposable PID namespace, so killing it destroys all descendants.
"""
import array
import ctypes
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
MAX_SETUP_SECONDS = 140
MAX_LAB_SECONDS = 190
MAX_TERMINATION_MS = 8000


def reject(message):
    raise RuntimeError(message)


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
        r"stl-quic-wg-l3\.[A-Za-z0-9_-]{8}", root.name
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
    root = tempfile.mkdtemp(prefix="stl-quic-wg-l3.", dir="/tmp")
    original_stat = os.lstat(root)
    if not exact_fixture(root, original_stat):
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
        if not exact_fixture(root, original_stat):
            reject("private fixture identity changed before retirement")
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
        watch_socket.close()


def main():
    if len(sys.argv) != 5:
        reject("expected trusted repository, official helper, wg executable and launcher")
    repo, helper, wg, launcher = sys.argv[1:]
    if any(not pathlib.Path(p).is_absolute() for p in sys.argv[1:]):
        reject("test launch requires absolute, trusted local paths")
    if not pathlib.Path(repo, "go.mod").is_file():
        reject("source repository is unavailable")
    if not pathlib.Path(launcher).is_file():
        reject("source-bound isolated launcher is unavailable")

    fault = os.environ.get("STL_QUIC_WG_L3_FAULT", "")
    if fault not in {
        "", "preflight-fail", "setup-fail", "after-helper-fail",
        "child-term", "child-kill", "supervisor-hold",
        "supervisor-preflight-hold", "supervisor-materials-hold",
    }:
        reject("unsupported isolated failure-path test mode")
    # The janitor begins before fixture creation, in its own session.
    # This closes the parent-SIGKILL cleanup gap even during preparation.
    parent_sock, watch_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    watcher = os.fork()
    if watcher == 0:
        parent_sock.close()
        code = janitor(watch_sock)
        os._exit(code)
    watch_sock.close()
    pidfd = None
    process = None
    try:
        ready = b""
        while not ready.endswith(b"\n") and len(ready) < 256:
            block = parent_sock.recv(256 - len(ready))
            if not block:
                reject("isolated cleanup janitor did not create a fixture")
            ready += block
        if not ready.startswith(b"R") or not ready.endswith(b"\n"):
            reject("isolated cleanup janitor reported invalid fixture")
        root = os.fsdecode(ready[1:-1])
        original_stat = os.lstat(root)
        if not exact_fixture(root, original_stat):
            reject("isolated cleanup janitor fixture identity invalid")
        if fault:
            # Public path/namespace identifier only; no credential bytes.
            print("QUIC_L3_FAILURE_LAB=" + root, flush=True)
        if fault == "supervisor-preflight-hold":
            # Parent SIGKILL before credential generation must still retire
            # its empty private fixture through the independent janitor.
            print("QUIC_L3_SUPERVISOR_PREFLIGHT_READY", flush=True)
            time.sleep(90)
            reject("test supervisor was not interrupted before preflight")
        environment = os.environ.copy()
        environment.update({
            "STL_QUIC_WG_L3_ROOT": root,
            "STL_QUIC_HYSTERIA_BIN": helper,
            "STL_QUIC_WG_L3_WG_BINARY": wg,
            "STL_QUIC_WG_L3_NONCE": secrets.token_hex(16),
            "STL_QUIC_PARENT_USERNS": os.readlink("/proc/self/ns/user"),
            "STL_QUIC_PARENT_NETNS": os.readlink("/proc/self/ns/net"),
            "STL_QUIC_PARENT_PIDNS": os.readlink("/proc/self/ns/pid"),
        })
        pathlib.Path(root, "parent-namespaces").write_text(
            environment["STL_QUIC_PARENT_USERNS"] + "\n"
            + environment["STL_QUIC_PARENT_NETNS"] + "\n"
            + environment["STL_QUIC_PARENT_PIDNS"] + "\n",
            encoding="ascii",
        )
        nonce_path = pathlib.Path(root, "nonce")
        nonce_path.write_text(environment["STL_QUIC_WG_L3_NONCE"] + "\n", encoding="ascii")
        os.chmod(nonce_path, 0o600)
        os.chmod(pathlib.Path(root, "parent-namespaces"), 0o600)
        if fault == "preflight-fail":
            reject("injected failure before private credential staging")

        parent_pid = os.getpid()

        def run_pinned(args, log_name, timeout, env):
            with open(pathlib.Path(root, log_name), "wb") as output:
                result = subprocess.run(
                    args, cwd=repo, env=env, stdout=output, stderr=subprocess.STDOUT,
                    timeout=timeout,
                    preexec_fn=lambda: death_with_parent(parent_pid),
                    check=False,
                )
            if result.returncode:
                reject("trusted test fixture build or stage failed")

        build_env = environment.copy()
        build_env["GOTOOLCHAIN"] = "local"
        run_pinned(
            ["go", "test", "-c", "-o", root + "/quic-test", "./internal/carrier/quic"],
            "build.log", MAX_SETUP_SECONDS, build_env,
        )
        stage_env = environment.copy()
        stage_env["STL_QUIC_WG_L3_FIXTURE"] = "approved"
        run_pinned(
            [root + "/quic-test", "-test.run", "^TestPinnedHysteriaKernelWGPairFixture$", "-test.v"],
            "fixture.log", MAX_SETUP_SECONDS, stage_env,
        )
        if fault == "supervisor-materials-hold":
            # Parent SIGKILL with real protected TLS/mTLS/bearer files on
            # disk must not leave credentials even before unshare starts.
            print("QUIC_L3_SUPERVISOR_MATERIALS_READY", flush=True)
            time.sleep(90)
            reject("test supervisor was not interrupted after staging")

        # --pid + --mount-proc make the isolated controller PID 1 and
        # put all Hysteria/Python/sibling workers under that PID namespace.
        # --kill-child ensures the controller dies if the unshare monitor
        # dies; PR_SET_PDEATHSIG ensures unshare dies if this launcher dies.
        args = [
            "unshare", "--user", "--map-root-user", "--net", "--mount",
            "--pid", "--fork", "--kill-child", "--mount-proc",
            "bash", launcher, "--isolated",
        ]
        process = subprocess.Popen(
            args, env=environment, cwd=repo,
            preexec_fn=lambda: death_with_parent(parent_pid),
            close_fds=True,
        )
        pidfd = os.pidfd_open(process.pid, 0)
        descriptors = array.array("i", [pidfd])
        parent_sock.sendmsg(
            [b"P"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)]
        )
        try:
            result = process.wait(timeout=MAX_LAB_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=MAX_TERMINATION_MS / 1000)
            reject("disposable QUIC lab exceeded its test-only time budget")
        if result != 0:
            reject("isolated QUIC L3 test did not complete successfully")
        return 0
    finally:
        # The independent janitor gets EOF even after an ordinary error.
        # After an uncatchable SIGKILL it gets EOF from the kernel directly.
        if process is not None and process.poll() is None:
            process.kill()  # Only the exact Popen child, never names or groups.
            process.wait(timeout=MAX_TERMINATION_MS / 1000)
        if pidfd is not None:
            os.close(pidfd)
        parent_sock.close()
        _, status = os.waitpid(watcher, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            reject("disposable lab private fixture cleanup failed")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
        # Errors are sanitized to keep private fixture/helper data out of
        # operator-facing diagnostics; the janitor reports its own outcome.
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    print("QUIC_KERNEL_WIREGUARD_PRIVATE_L3_ISOLATED=PASS")
