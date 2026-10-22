#!/usr/bin/python3
"""Disposable namespace-only foreign WG listener injection at Remove guard gate.

Never inject on a real host. The harness must prove isolation before staging
this executable, and this helper re-checks that proof and a one-use marker.
The sole injected effect is a foreign WG interface in the disposable beta
network namespace, AFTER the original WG interface disappears but BEFORE the
final WSS nft guard inventory. No actual host network changes are permitted.
"""
import os
import pathlib
import stat
import subprocess
import sys

REAL_WG = "/lab/bin/wg-extract/usr/bin/wg"
TEST_MARKER = pathlib.Path("/lab/beta/enable-foreign-guard-interloper")


def attested_netns():
    try:
        if os.geteuid() != 0 or os.environ.get("STL_R1_SIDE_ROOT") != "/lab/beta":
            return False
        expected = pathlib.Path("/lab/namespace-guard").read_text().strip()
        if not expected or expected != os.environ.get("STL_WSS_R1_TEST_GUARD"):
            return False
        host_user_ns = pathlib.Path("/lab/host-user-ns-id").read_text().strip()
        host_net_ns = pathlib.Path("/lab/host-ns-id").read_text().strip()
        if os.readlink("/proc/self/ns/user") == host_user_ns:
            return False
        if os.readlink("/proc/self/ns/net") == host_net_ns:
            return False
        if not TEST_MARKER.exists() or TEST_MARKER.is_symlink():
            return False
        item = TEST_MARKER.stat()
        return stat.S_ISREG(item.st_mode) and item.st_uid == 0
    except (OSError, ValueError):
        return False


args = sys.argv[1:]
if os.environ.get("STL_WSS_R4_GUARD_INTERLOPER") == "port" and args == ["show", "interfaces"]:
    if attested_netns():
        original = subprocess.run(
            ["/usr/sbin/ip", "link", "show", "stlwg0123456789"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if original.returncode != 0:
            subprocess.run(
                ["/usr/sbin/ip", "link", "add", "foreignwg0", "type", "wireguard"],
                check=True,
            )
            subprocess.run([REAL_WG, "set", "foreignwg0", "listen-port", "51822"], check=True)
            TEST_MARKER.unlink()
    elif TEST_MARKER.exists():
        sys.exit("WSS R4: foreign listener injection boundary not attested")

os.execv(REAL_WG, [REAL_WG, *args])
