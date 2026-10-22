#!/usr/bin/python3
"""Bounded test-only WG host-effect crash; rootless namespace only."""
import os,sys,subprocess,signal
args=sys.argv[1:]
result=subprocess.run(["/lab/bin/wg-extract/usr/bin/wg",*args],check=False,close_fds=False)
if result.returncode:sys.exit(result.returncode)
if os.environ.get("STL_WSS_R2_AMBIGUOUS_TEST")=="kernel-crash" and args and args[0]=="set":
    os.kill(os.getppid(),signal.SIGKILL)
    sys.exit(1)
sys.exit(0)
