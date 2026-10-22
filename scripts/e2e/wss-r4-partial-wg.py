#!/usr/bin/python3
"""Disposable namespace-only partial wg set followed by a hard process crash.

This test helper is never installed or used outside the verified rootless
WSS acceptance lab. It publishes only the originally intended public
listener and private-key-derived WireGuard identity, preserving FD3 directly.
"""
import os
import pathlib
import signal
import subprocess
import sys

REAL_WG = "/lab/bin/wg-extract/usr/bin/wg"


def isolated_alpha() -> bool:
    if os.geteuid() != 0 or os.environ.get("STL_R1_SIDE_ROOT") != "/lab/alpha":
        return False
    try:
        expected = pathlib.Path("/lab/namespace-guard").read_text().strip()
        if not expected or expected != os.environ.get("STL_WSS_R1_TEST_GUARD"):
            return False
        return (
            os.readlink("/proc/self/ns/user")
            != pathlib.Path("/lab/host-user-ns-id").read_text().strip()
            and os.readlink("/proc/self/ns/net")
            != pathlib.Path("/lab/host-ns-id").read_text().strip()
        )
    except OSError:
        return False


args = sys.argv[1:]
if (
    os.environ.get("STL_WSS_R4_PARTIAL_WG_TEST") == "key-port"
    and args[:3] == ["set", "stlwg0123456789", "listen-port"]
):
    if not isolated_alpha() or "private-key" not in args or "/proc/self/fd/3" not in args:
        sys.exit("WSS R4 partial-original injection lacks attested ownership")
    # All effect arguments come from the actual Engine-provided wg set.
    # Preserve the already validated private credential FD, not its bytes.
    listen_port = args[3]
    result = subprocess.run(
        [REAL_WG, "set", "stlwg0123456789", "listen-port", listen_port,
         "private-key", "/proc/self/fd/3"],
        pass_fds=(3,),
        check=False,
    )
    if result.returncode:
        sys.exit(result.returncode)
    os.kill(os.getppid(), signal.SIGKILL)
    sys.exit(1)

os.execv(REAL_WG, [REAL_WG, *args])
