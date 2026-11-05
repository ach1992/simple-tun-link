#!/usr/bin/env python3
"""Real installed-root menu -> pinned HTTPS Mirror Update in a disposable guest.

All test updates require fresh PTY consent. A failed/aborted menu operation
must preserve the installed binary and install-record; successful Update
delegates to the same installed CLI and canonical transaction as direct CLI.
Never run against a real host or without the disposable guest marker.
"""
import fcntl
import hashlib
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time

EXE = "/usr/local/bin/stl"
RECORD = "/usr/local/lib/simple-tun-link/install-record"


def require_disposable() -> None:
    if (os.geteuid() != 0 or not os.path.isfile("/.dockerenv")
            or os.environ.get("STL_E2E_DISPOSABLE_GUEST") != "approved"):
        raise RuntimeError("root PTY update requires approved disposable guest")


def sha_file(path: str) -> str:
    with open(path, "rb") as stream:
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
        return h.hexdigest()


def installed_identity() -> tuple[str, str]:
    return sha_file(EXE), sha_file(RECORD)


def installed_version() -> bytes:
    return subprocess.check_output([EXE, "version", "--json"], timeout=10)


def assert_not_modified(previous: tuple[str, str]) -> None:
    if installed_identity() != previous:
        raise AssertionError("refused/cancelled menu changed installed identity")
    if os.path.lexists("/var/lib/simple-tun-link"):
        raise AssertionError("refused/cancelled menu changed private Link State")
    for prefix in (".stl-mirror-preflight.", ".stl-preflight."):
        if any(entry.startswith(prefix) for entry in os.listdir("/root")):
            raise AssertionError("refused/cancelled menu left private download stage")


def exercise(
    url: str,
    digest: str,
    action: str,
    expect: str,
    transcript_file: str | None = None,
    choice: str = "3",
) -> bytes:
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 38, 0, 0))

    def set_controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    env = {**os.environ, "NO_COLOR": "1", "TERM": "dumb", "STL_NO_CLEAR": "0"}
    child = subprocess.Popen(
        [EXE, "menu"], stdin=slave, stdout=slave, stderr=slave,
        env=env, preexec_fn=set_controlling_terminal,
    )
    os.close(slave)
    pending = b""
    transcript = bytearray()

    def wait_for(marker: bytes, seconds: float = 25) -> None:
        nonlocal pending
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            pos = pending.find(marker)
            if pos != -1:
                pending = pending[pos + len(marker):]
                return
            readable, _, _ = select.select([master], [], [], min(0.2, max(0, end - time.monotonic())))
            if readable:
                try:
                    data = os.read(master, 8192)
                except OSError:
                    data = b""
                if not data:
                    raise AssertionError(f"PTY terminated before {marker!r}: {pending[-450:]!r}")
                transcript.extend(data)
                pending += data
                if len(transcript) > 250000:
                    raise AssertionError("unbounded menu transcript")
        raise AssertionError(f"missing {marker!r}: {pending[-450:]!r}")

    def send(value: str) -> None:
        os.write(master, value.encode("ascii"))

    try:
        wait_for(b"Choose a task:")
        send("6\n")
        wait_for(b"Choose update source")
        send(choice + "\n")
        if choice == "2":
            wait_for(b"Full official local-installer path")
        else:
            wait_for(b"Trusted HTTPS mirror URL")
        send(url + "\n")
        wait_for(b"Independent SHA256 (64 lowercase hex")
        send(digest + "\n")
        if action == "reject":
            wait_for(b"pinned_update_input_invalid")
            wait_for(b"Press Enter to continue...")
            send("\n")
            wait_for(b"Choose a task:")
            send("8\n")
            wait_for(b"Goodbye.")
        else:
            wait_for(b"Type UPDATE")
            if action == "cancel":
                send("\n")
                wait_for(b"Update cancelled")
                wait_for(b"Press Enter to continue...")
                send("\n")
                wait_for(b"Choose a task:")
                send("8\n")
                wait_for(b"Goodbye.")
            else:
                send("UPDATE\n")
                wait_for(expect.encode("ascii"), 200)
                child.wait(timeout=15)
        if child.poll() is None:
            child.wait(timeout=10)
        if child.returncode != 0:
            raise AssertionError(f"menu exit {child.returncode}")
        if b"\x1b" in transcript:
            raise AssertionError("NO_COLOR permitted ANSI escape in narrow PTY")
        if transcript_file:
            with open(transcript_file, "wb") as out:
                out.write(transcript)
        return bytes(transcript)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        os.close(master)


def main() -> int:
    require_disposable()
    if len(sys.argv) != 4 or len(sys.argv[2]) != 64:
        raise SystemExit("usage: terminal-offline-update.py HTTPS_INSTALL_SH SHA256 OUTPUT")
    url, sha, output_path = sys.argv[1:]
    before = installed_identity()
    if b'"version":"v999.0.0"' not in installed_version():
        raise AssertionError("unexpected starting guest release")

    bad_url = url.replace("https://", "http://", 1)
    exercise(bad_url, sha, "reject", "unused")
    assert_not_modified(before)
    print("DISPOSABLE_MENU_MIRROR_INPUT_REFUSAL=PASS")

    exercise(url, sha, "cancel", "unused")
    assert_not_modified(before)
    print("DISPOSABLE_MENU_MIRROR_CONSENT_CANCEL=PASS")

    exercise(url, "0" * 64, "attempt", "Verified Update did not complete")
    assert_not_modified(before)
    print("DISPOSABLE_MENU_MIRROR_WRONG_DIGEST=PASS")

    # The same menu root/TTY/consent gate must also reach the existing
    # local-file CLI without running unauthenticated transferred shell.
    old_name = os.environ["STL_E2E_OLDER_NAME"]
    local = "/root/stl/" + old_name
    exercise(local, "0" * 64, "attempt", "Verified Update did not complete", choice="2")
    assert_not_modified(before)
    print("DISPOSABLE_MENU_LOCAL_WRONG_DIGEST=PASS")

    exercise(url, sha, "attempt", "[OK] Canonical Update reported success: v999.0.1",
             transcript_file=output_path)
    if b'"version":"v999.0.1"' not in installed_version():
        raise AssertionError("menu did not publish intended synthetic Stable")
    if installed_identity() == before:
        raise AssertionError("menu did not update binary and ownership record")
    print("DISPOSABLE_MENU_MIRROR_VERIFIED_UPDATE=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
