#!/usr/bin/python3
"""Disposable namespace-only crash injection at the FIRST successful nft
transaction. Kills the child STL process AFTER real nft succeeds but BEFORE
the Engine gets a result or can commit desired State. Not a system tool.
"""
import os
import signal
import subprocess
import sys
import time

args = sys.argv[1:]
kind=os.environ.get("STL_WSS_R2_AMBIGUOUS_TEST","")
if args == ["-f", "-"] and (os.environ.get("STL_WSS_R2_CRASH_AFTER_GUARD") == "1" or kind in ("nft-error","nft-timeout","nft-cancel")):
    batch = sys.stdin.buffer.read(4096 + 1)
    if len(batch) > 4096 or b"create table inet stlwss_" not in batch:
        print("unexpected WSS crash-injection nft batch", file=sys.stderr)
        sys.exit(1)
    result = subprocess.run(["/usr/sbin/nft", "-f", "-"], input=batch, check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)
    # Process being killed is the actual Go test-tagged STL CLI. This does
    # not kill the supervising namespace harness or any process outside it.
    if kind=="nft-cancel":
        os.kill(os.getppid(),signal.SIGINT)
        time.sleep(12)
        sys.exit(1)
    if kind=="nft-error":
        print("injected post-effect nft error",file=sys.stderr)
        sys.exit(1)
    if kind=="nft-timeout":
        time.sleep(12)
        sys.exit(1)
    os.kill(os.getppid(), signal.SIGKILL)
    sys.exit(1)
if args == ["-f", "-"] and os.environ.get("STL_WSS_R2_REMOVE_CRASH_TEST")=="guard":
    batch=sys.stdin.buffer.read(4097)
    if len(batch)>4096:sys.exit(2)
    result=subprocess.run(["/usr/sbin/nft","-f","-"],input=batch,check=False)
    if result.returncode:sys.exit(result.returncode)
    if b"delete table inet stlwss_" in batch:
        os.kill(os.getppid(),signal.SIGKILL)
        sys.exit(1)
    sys.exit(0)
os.execv("/usr/sbin/nft", ["/usr/sbin/nft", *args])
