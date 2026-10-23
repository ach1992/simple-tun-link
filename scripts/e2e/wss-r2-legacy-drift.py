#!/usr/bin/python3
"""Fake only a foreign legacy iptables rule, inside namespace-only E2E."""
import os,sys
name=os.path.basename(sys.argv[0])
if name not in ("iptables-legacy-save","ip6tables-legacy-save") or len(sys.argv)!=1:
    sys.exit(2)
if os.environ.get("STL_WSS_R2_LEGACY_DRIFT")=="1" and name=="iptables-legacy-save":
    print("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p udp --dport 51821 -j ACCEPT\nCOMMIT")
    sys.exit(0)
os.execv("/lab/bin/iptables-extract/usr/sbin/"+name,["/lab/bin/iptables-extract/usr/sbin/"+name])
