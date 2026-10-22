#!/usr/bin/python3
"""Disposable namespace-only crash injection at the FIRST successful nft
transaction. Kills the child STL process AFTER real nft succeeds but BEFORE
the Engine gets a result or can commit desired State. Not a system tool.
"""
import os
import signal
import subprocess
import sys

args = sys.argv[1:]
if args == ["-f", "-"] and os.environ.get("STL_WSS_R2_CRASH_AFTER_GUARD") == "1":
    batch = sys.stdin.buffer.read(4096 + 1)
    if len(batch) > 4096 or b"create table inet stlwss_" not in batch:
        print("unexpected WSS crash-injection nft batch", file=sys.stderr)
        sys.exit(1)
    result = subprocess.run(["/usr/sbin/nft", "-f", "-"], input=batch, check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)
    # Process being killed is the actual Go test-tagged STL CLI. This does
    # not kill the supervising namespace harness or any process outside it.
    os.kill(os.getppid(), signal.SIGKILL)
    sys.exit(1)
os.execv("/usr/sbin/nft", ["/usr/sbin/nft", *args])
