#!/usr/bin/env python3
"""Bounded research datagram adapter, not an STL Carrier or authenticated proxy.

The outer socket is created before entering an already-owned network namespace.
WireGuard is born in that namespace and is the sole cryptographic verifier.
Exact peer tuples are immutable; no discovery, roaming, retries or fallback.
"""
import argparse
import base64
import ctypes
import datetime
import hashlib
import ipaddress
import json
import os
import re
import resource
import selectors
import signal
import socket
import stat
import struct
import time


def endpoint(text):
    host, port = text.rsplit(':', 1)
    ip = ipaddress.IPv4Address(host)
    value = int(port)
    if not 1 <= value <= 65535 or ip.is_unspecified or ip.is_multicast:
        raise ValueError('explicit_unicast_ipv4_and_port_required')
    return str(ip), value


def wg_type(data):
    if len(data) < 4 or data[1:4] != b'\0\0\0':
        return None
    kind = data[0]
    if kind in (1, 2, 3):
        return kind if len(data) == {1:148, 2:92, 3:64}[kind] else None
    return 4 if kind == 4 and len(data) >= 32 and len(data) % 16 == 0 else None


def introduction(run_id, local_port):
    token = base64.b32encode(hashlib.shake_256(run_id.encode()).digest(80)).decode().lower()
    labels = ['p'+str(local_port)] + [token[i:i+45] for i in range(0,len(token),45)] + ['research','invalid']
    name = b''.join(bytes([len(s)])+s.encode('ascii') for s in labels)+b'\0'
    txid = int.from_bytes(hashlib.sha256(run_id.encode()).digest()[:2],'big')
    return struct.pack('!HHHHHH',txid,0x0100,1,0,0,0)+name+struct.pack('!HH',16,1)


def enter_netns(path):
    if not re.fullmatch(r'/run/netns/u53-[a-z0-9-]{1,30}',path):
        raise ValueError('explicit_u53_namespace_required')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
    try:
        current = os.stat('/proc/self/ns/net')
        desired = os.fstat(fd)
        if (current.st_dev,current.st_ino) == (desired.st_dev,desired.st_ino):
            raise ValueError('already_in_destination_namespace')
        libc = ctypes.CDLL(None,use_errno=True)
        if libc.setns(fd, 0x40000000):
            raise OSError(ctypes.get_errno(),'setns_failed')
        after = os.stat('/proc/self/ns/net')
        if (after.st_dev,after.st_ino)!=(desired.st_dev,desired.st_ino):
            raise RuntimeError('namespace_switch_unconfirmed')
        return dict(device=after.st_dev,inode=after.st_ino)
    finally:
        os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role',choices=['dial','listen'],required=True)
    p.add_argument('--outer-bind',type=endpoint,required=True)
    p.add_argument('--outer-peer',type=endpoint,required=True)
    p.add_argument('--inner-bind',type=endpoint,default=('127.0.0.1',42512))
    p.add_argument('--inner-peer',type=endpoint,default=('127.0.0.1',42511))
    p.add_argument('--netns-path')
    p.add_argument('--loopback-control',action='store_true')
    p.add_argument('--run-id',required=True)
    p.add_argument('--duration',type=float,default=900)
    p.add_argument('--introduction',action='store_true')
    p.add_argument('--introduction-settle',type=float,default=1.5)
    p.add_argument('--max-datagram',type=int,default=1200)
    a=p.parse_args()
    if (not 1<=a.duration<=1800 or not 148<=a.max_datagram<=1500 or
            not 0<=a.introduction_settle<=3 or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',a.run_id)):
        p.error('invalid_research_bounds')
    if a.inner_bind[0]!='127.0.0.1' or a.inner_peer[0]!='127.0.0.1' or a.inner_bind==a.inner_peer:
        p.error('distinct_exact_loopback_inner_endpoints_required')
    if a.introduction and a.role!='dial':p.error('only_explicit_dialer_may_introduce')
    if bool(a.netns_path)==a.loopback_control:p.error('choose_netns_or_loopback_control')
    if a.loopback_control and not all(ipaddress.ip_address(x[0]).is_loopback for x in [a.outer_bind,a.outer_peer]):
        p.error('control_mode_requires_loopback_outer')
    counts={k:0 for k in ['outer_rx','outer_tx','inner_rx','inner_tx','outer_bytes_rx','outer_bytes_tx','invalid_outer','invalid_inner','truncated_outer','truncated_inner','listener_early_inner','queue_dropped','send_errors','introductions']}
    types={'outer_rx':{},'outer_tx':{}}
    stop=[False];outer=None;inner=None;sel=None;started=time.monotonic()
    first_rx=None;first_tx=None;max_rx=0;max_tx=0;exit_code=0;reason='deadline'
    def emit(event,**values):
        print(json.dumps(dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),run_id=a.run_id,
                             event=event,elapsed_s=time.monotonic()-started,role=a.role,**values),sort_keys=True),flush=True)
    def snapshot(event,**extra):
        usage=resource.getrusage(resource.RUSAGE_SELF)
        emit(event,counts=dict(counts),types=types,first_outer_rx_s=first_rx,first_outer_tx_s=first_tx,
             max_outer_rx=max_rx,max_outer_tx=max_tx,user_s=usage.ru_utime,system_s=usage.ru_stime,
             maxrss_kib=usage.ru_maxrss,**extra)
    def send_packet(sock,data,which,kind=None):
        nonlocal first_tx,max_tx
        try:
            n=sock.send(data)
            if n!=len(data):raise RuntimeError('partial_datagram_send')
        except (OSError,RuntimeError) as exc:
            counts['send_errors']+=1
            emit('SOCKET_SEND_ERROR',path=which,error=type(exc).__name__,errno=getattr(exc,'errno',None))
            return False
        counts[which+'_tx']+=1
        if which=='outer':
            counts['outer_bytes_tx']+=len(data);max_tx=max(max_tx,len(data))
            if first_tx is None:first_tx=time.monotonic()-started
            if kind:types['outer_tx'][str(kind)]=types['outer_tx'].get(str(kind),0)+1
        return True
    try:
        signal.signal(signal.SIGTERM,lambda *_:stop.__setitem__(0,True))
        signal.signal(signal.SIGINT,lambda *_:stop.__setitem__(0,True))
        origin=os.stat('/proc/self/ns/net')
        outer=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        outer.bind(a.outer_bind);outer.connect(a.outer_peer);outer.setblocking(False)
        outer.setsockopt(socket.IPPROTO_IP,10,2)  # IP_MTU_DISCOVER=IP_PMTUDISC_DO; socket-only.
        outer_identity=os.fstat(outer.fileno()).st_ino
        destination=enter_netns(a.netns_path) if a.netns_path else dict(device=origin.st_dev,inode=origin.st_ino)
        inner=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        inner.bind(a.inner_bind);inner.connect(a.inner_peer);inner.setblocking(False)
        sel=selectors.DefaultSelector();sel.register(outer,selectors.EVENT_READ,'outer');sel.register(inner,selectors.EVENT_READ,'inner')
        emit('READY',outer_local=outer.getsockname(),outer_peer=outer.getpeername(),outer_socket_inode=outer_identity,
             origin_netns=dict(device=origin.st_dev,inode=origin.st_ino),current_netns=destination,
             inner_local=inner.getsockname(),inner_peer=inner.getpeername(),introduction=a.introduction,
             authentication='not_observed_by_adapter',duration=a.duration)
        deadline=started+a.duration;next_report=time.monotonic()+5
        introduced=not a.introduction;settle_until=0;pending=[];candidate_seen=False
        while not stop[0] and time.monotonic()<deadline:
            now=time.monotonic()
            if pending and now>=settle_until:
                for data,kind in pending:send_packet(outer,data,'outer',kind)
                pending.clear()
            for key,_ in sel.select(min(.1,max(0,deadline-time.monotonic()))):
                which=key.data;sock=key.fileobj
                try:
                    data,anc,flags,peer=sock.recvmsg(a.max_datagram+1)
                except BlockingIOError:continue
                except OSError as exc:
                    emit('SOCKET_RECEIVE_ERROR',path=which,errno=exc.errno);continue
                if flags & socket.MSG_TRUNC or len(data)>a.max_datagram:
                    counts['truncated_'+which]+=1;continue
                counts[which+'_rx']+=1
                if which=='outer':
                    counts['outer_bytes_rx']+=len(data);max_rx=max(max_rx,len(data))
                    if first_rx is None:first_rx=time.monotonic()-started
                kind=wg_type(data)
                if kind is None:
                    counts['invalid_'+which]+=1;continue
                if which=='outer':
                    types['outer_rx'][str(kind)]=types['outer_rx'].get(str(kind),0)+1
                    candidate_seen=True
                    send_packet(inner,data,'inner')
                else:
                    if a.role=='listen' and not candidate_seen:
                        counts['listener_early_inner']+=1;continue
                    if not introduced:
                        intro=introduction(a.run_id,a.outer_bind[1])
                        if not send_packet(outer,intro,'outer'):raise RuntimeError('introduction_send_failed')
                        counts['introductions']+=1;introduced=True
                        settle_until=time.monotonic()+a.introduction_settle
                        emit('INTRODUCTION_SENT',bytes=len(intro),outer_socket_inode=outer_identity,settle_s=a.introduction_settle)
                    if time.monotonic()<settle_until:
                        if len(pending)<8:pending.append((data,kind))
                        else:counts['queue_dropped']+=1
                    else:send_packet(outer,data,'outer',kind)
            if time.monotonic()>=next_report:
                snapshot('COUNTERS');next_report=time.monotonic()+5
        if stop[0]:reason='signal'
    except Exception as exc:
        exit_code=2;reason='error'
        emit('ERROR',error=type(exc).__name__,detail=str(exc))
    finally:
        if sel is not None:sel.close()
        if inner is not None:inner.close()
        if outer is not None:outer.close()
        snapshot('STOPPED',reason=reason,exit_code=exit_code)
    return exit_code


if __name__=='__main__':
    raise SystemExit(main())
