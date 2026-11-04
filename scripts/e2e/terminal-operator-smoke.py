#!/usr/bin/env python3
"""Real installed-STL PTY, 38-column, NO_COLOR, cancel-only operator smoke.

This is a non-root, non-mutating acceptance seam. It never confirms a Link,
installs packages, removes State, changes network configuration or uses secrets.
"""
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time


def main() -> int:
    if len(sys.argv) != 2 or not os.path.isabs(sys.argv[1]):
        raise SystemExit("usage: terminal-operator-smoke.py /absolute/installed/stl")
    exe = sys.argv[1]
    version = subprocess.check_output([exe, "version", "--json"], timeout=5)
    if b'"schema_version":1' not in version:
        raise AssertionError("installed executable did not report STL identity")

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 38, 0, 0))

    def bind_tty():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    env = os.environ.copy()
    env.update(TERM="xterm-256color", NO_COLOR="1", STL_NO_CLEAR="0")
    child = subprocess.Popen(
        [exe, "menu"], stdin=slave, stdout=slave, stderr=slave,
        env=env, preexec_fn=bind_tty,
    )
    os.close(slave)
    pending = b""
    transcript = bytearray()

    def until(marker: str, timeout=15):
        nonlocal pending
        target = marker.encode("ascii")
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            idx = pending.find(target)
            if idx >= 0:
                pending = pending[idx + len(target):]
                return
            readable, _, _ = select.select(
                [master], [], [], min(.25, max(0, end - time.monotonic()))
            )
            if readable:
                data = os.read(master, 4096)
                if not data:
                    raise AssertionError(f"PTY closed before {marker!r}")
                transcript.extend(data)
                pending += data
                if len(transcript) > 300000:
                    raise AssertionError("unbounded terminal output")
        raise AssertionError(f"timeout waiting for {marker!r}; tail={pending[-700:]!r}")

    def send(value: str):
        os.write(master, value.encode("ascii"))

    try:
        until("Choose a task:")
        if b"SIMPLE TUN LINK" not in transcript:
            raise AssertionError("no installed-version terminal header")
        send("1\n")
        until("Tunnel type [1]:")
        send("0\n")
        until("Press Enter to continue...")
        send("\n")
        until("Choose a task:")
        print("INSTALLED_38COL_CREATE_BACK_CANCEL=PASS")

        send("2\n")
        until("Choose type [1]:")
        send("0\n")
        until("Press Enter to continue...")
        send("\n")
        until("Choose a task:")
        print("INSTALLED_38COL_IMPORT_BACK_CANCEL=PASS")

        send("z\n")
        until("Choose a number from 1 to 8.")
        until("Press Enter to continue...")
        send("\n")
        until("Choose a task:")
        print("INSTALLED_38COL_INVALID_SELECTION=PASS")

        send("5\n")
        until("Press Enter to continue...")
        send("\n")
        until("Choose a task:")
        print("INSTALLED_38COL_SETTINGS_BACK=PASS")

        send("8\n")
        until("Goodbye.")
        child.wait(timeout=5)
        if child.returncode != 0:
            raise AssertionError(f"menu exited with {child.returncode}")
        if b"\x1b" in transcript:
            raise AssertionError("NO_COLOR permitted ANSI/clear screen")
        print("INSTALLED_38COL_NO_COLOR_NO_ANSI=PASS")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        os.close(master)
    return 0


if __name__ == "__main__":
    sys.exit(main())
