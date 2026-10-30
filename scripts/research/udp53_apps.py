#!/usr/bin/env python3
"""Finite private-IP research traffic. This is not an STL product service."""
import argparse
import datetime
import hashlib
import json
import re
import select
import signal
import socket
import threading
import time


def emit(event, **fields):
    print(json.dumps(dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          event=event, **fields), sort_keys=True), flush=True)


def chunk(seed):
    return hashlib.shake_256(seed.encode()).digest(16384)


def blocks(seed, size):
    data = chunk(seed)
    while size:
        part = data[:min(size, len(data))]
        yield part
        size -= len(part)


def digest(seed, size):
    h = hashlib.sha256()
    for part in blocks(seed, size):
        h.update(part)
    return h.hexdigest()


def budget(deadline, stop=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or stop is not None and stop.is_set():
        raise TimeoutError('absolute_deadline_or_stop')
    return remaining


def receive(conn, size, deadline, stop=None):
    while True:
        conn.settimeout(min(1.0, budget(deadline, stop)))
        try:
            return conn.recv(size)
        except socket.timeout:
            continue


def send(conn, data, deadline, stop=None, progress=None):
    pending = memoryview(data)
    while pending:
        conn.settimeout(min(1.0, budget(deadline, stop)))
        try:
            count = conn.send(pending)
        except socket.timeout:
            continue
        if count <= 0:
            raise ConnectionError('send_closed')
        if progress is not None:
            progress['bytes'] += count
            progress['hash'].update(pending[:count])
        pending = pending[count:]


def line(conn, deadline, stop=None):
    data = bytearray()
    while len(data) < 1024:
        part = receive(conn, 1, deadline, stop)
        if not part:
            raise ValueError('header_eof')
        if part == b'\n':
            return json.loads(data)
        data.extend(part)
    raise ValueError('header_too_long')


def tcp_receive(conn, addr, args, stop, deadline, active, lock):
    count, h, started = 0, hashlib.sha256(), time.monotonic()
    phase, sender, size, expected, receipt_emitted = None, None, None, None, False
    with conn:
        try:
            deadline = min(deadline, time.monotonic() + args.tcp_seconds)
            if addr[0] != args.peer:
                raise ValueError('wrong_peer')
            head = line(conn, deadline, stop)
            requested_size, requested_phase, requested_sender = head['size'], head['phase'], head['sender']
            size, phase, sender = requested_size, requested_phase, requested_sender
            if (head['run'] != args.run or type(size) is not int or
                    not 1 <= size <= 67108864 or sender == args.side or
                    sender not in ('ir', 'de', 'a', 'b') or
                    not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', phase)):
                raise ValueError('request_rejected')
            seed = '|'.join((args.run, phase, sender))
            expected = digest(seed, size)
            started = time.monotonic()
            while count < size:
                part = receive(conn, min(65536, size - count), deadline, stop)
                if not part:
                    break
                count += len(part)
                h.update(part)
            elapsed = time.monotonic() - started
            actual = h.hexdigest()
            receipt = dict(run=args.run, phase=phase, sender=sender, receiver=args.side,
                           received=count, expected=size, sha256=actual,
                           expected_sha256=expected, seconds=elapsed,
                           mbps=count * 8 / max(elapsed, 1e-9) / 1e6,
                           ok=(count == size and actual == expected))
            emit('TCP_RECEIPT', **receipt)
            receipt_emitted = True
            send(conn, json.dumps(receipt).encode() + b'\n', deadline, stop)
        except Exception as exc:
            # Headers are only copied to receipts after validation below.
            safe_phase = phase if isinstance(phase,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,40}',phase) else None
            safe_sender = sender if sender in ('ir','de','a','b') else None
            safe_size = size if type(size) is int and 1 <= size <= 67108864 else None
            emit('TCP_ACK_ERROR' if receipt_emitted else 'TCP_PARTIAL_RECEIPT',
                 run=args.run,phase=safe_phase,sender=safe_sender,receiver=args.side,
                 received=count,expected=safe_size,sha256=h.hexdigest(),expected_sha256=expected,
                 seconds=time.monotonic()-started,ok=False,error=type(exc).__name__,detail=str(exc))
        finally:
            with lock:
                active.discard(conn)


def udp_packet(run, phase, side, seq, total, size):
    prefix = ('|'.join((run, phase, side, str(seq), str(total), ''))).encode()
    if size < len(prefix):
        raise ValueError('udp_size_too_small')
    return prefix + hashlib.shake_256(prefix).digest(size - len(prefix))


def serve(args):
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    groups, threads, active, lock = {}, [], set(), threading.Lock()
    udp_counts = dict(received=0, accepted=0, rejected=0)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind((args.bind, args.port)); tcp.listen(4)
        udp.bind((args.bind, args.port))
        tcp.setblocking(False); udp.setblocking(False)
        emit('READY', run=args.run, side=args.side, bind=args.bind, port=args.port)
        deadline = time.monotonic() + args.seconds
        while not stop.is_set() and time.monotonic() < deadline:
            for sock in select.select([tcp, udp], [], [], .2)[0]:
                if sock is tcp:
                    conn, addr = tcp.accept()
                    threads = [t for t in threads if t.is_alive()]
                    if len(threads) >= 4:
                        conn.close(); continue
                    with lock:
                        active.add(conn)
                    t = threading.Thread(target=tcp_receive, args=(conn, addr, args, stop, deadline, active, lock))
                    t.start(); threads.append(t)
                else:
                    data, addr = udp.recvfrom(2048)
                    udp_counts['received'] += 1
                    if addr[0] != args.peer or len(data) > 1024:
                        udp_counts['rejected'] += 1
                        continue
                    try:
                        parts = data.split(b'|', 5)
                        run, phase, side = [s.decode('ascii') for s in parts[:3]]
                        seq, total = int(parts[3]), int(parts[4])
                        if (run != args.run or side == args.side or side not in ('ir', 'de', 'a', 'b') or
                                not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', phase) or
                                not 0 <= seq < total <= 256 or len(groups) >= 32 and (phase, side) not in groups):
                            udp_counts['rejected'] += 1
                            continue
                        if data != udp_packet(run, phase, side, seq, total, len(data)):
                            udp_counts['rejected'] += 1
                            continue
                        g = groups.setdefault((phase, side), {'seen': set(), 'duplicate': 0, 'reordered': 0, 'maxseq': -1, 'bytes': 0, 'total': total, 'last': 0, 'reported': -1})
                        if g['total'] != total:
                            udp_counts['rejected'] += 1
                            continue
                        udp_counts['accepted'] += 1
                        if seq in g['seen']:
                            g['duplicate'] += 1
                        else:
                            g['reordered'] += int(seq < g['maxseq'])
                            g['maxseq'] = max(g['maxseq'], seq)
                            g['seen'].add(seq); g['bytes'] += len(data)
                        g['last'] = time.monotonic()
                        udp.sendto(json.dumps(dict(run=run, phase=phase, seq=seq, sha256=hashlib.sha256(data).hexdigest())).encode(), addr)
                    except (ValueError, UnicodeError, IndexError):
                        udp_counts['rejected'] += 1
                        continue
            for (phase, side), g in groups.items():
                if g['reported'] != len(g['seen']) and (len(g['seen']) == g['total'] or time.monotonic() - g['last'] > 1):
                    emit('UDP_RECEIPT', run=args.run, phase=phase, sender=side, receiver=args.side,
                         received=len(g['seen']), expected=g['total'], sequences=sorted(g['seen']),
                         duplicate=g['duplicate'], reordered=g['reordered'], bytes=g['bytes'])
                    g['reported'] = len(g['seen'])
        stop.set()
        with lock:
            for conn in active:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
        join_deadline = time.monotonic() + 3
        for t in threads:
            t.join(timeout=max(0, join_deadline-time.monotonic()))
        if any(t.is_alive() for t in threads):
            raise RuntimeError('server_stop_unconfirmed')
        for (phase, side), g in groups.items():
            emit('UDP_RECEIPT',run=args.run,phase=phase,sender=side,receiver=args.side,
                 received=len(g['seen']),expected=g['total'],sequences=sorted(g['seen']),
                 duplicate=g['duplicate'],reordered=g['reordered'],bytes=g['bytes'],final=True)
        emit('SERVER_STOPPED', run=args.run, side=args.side, udp_counts=udp_counts)


def send_tcp(args):
    seed = '|'.join((args.run, args.phase, args.side))
    expected = digest(seed, args.bytes)
    progress = dict(bytes=0, hash=hashlib.sha256())
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((args.bind, 0))
            deadline = started + args.tcp_seconds
            sock.settimeout(min(25, budget(deadline)))
            sock.connect((args.peer, args.port))
            send(sock, json.dumps(dict(run=args.run, phase=args.phase, sender=args.side, size=args.bytes)).encode() + b'\n', deadline)
            for part in blocks(seed, args.bytes):
                send(sock, part, deadline, progress=progress)
            receipt = line(sock, deadline)
            elapsed = time.monotonic() - started
            ok = receipt.get('ok') is True and receipt.get('received') == args.bytes and receipt.get('sha256') == expected
            emit('TCP_SENT', run=args.run, phase=args.phase, sender=args.side, bytes=progress['bytes'],
                 sha256=progress['hash'].hexdigest(), seconds=elapsed, mbps=args.bytes*8/max(elapsed,1e-9)/1e6,
                 peer_receipt=receipt, ok=ok)
            return 0 if ok else 2
    except Exception as exc:
        emit('TCP_PARTIAL_SENT',run=args.run,phase=args.phase,sender=args.side,
             bytes=progress['bytes'],expected=args.bytes,sha256=progress['hash'].hexdigest(),
             expected_sha256=expected,seconds=time.monotonic()-started,ok=False,
             error=type(exc).__name__,detail=str(exc))
        return 2


def send_udp(args):
    seen, sent = set(), 0
    started, error = time.monotonic(), None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((args.bind, 0)); sock.connect((args.peer, args.port)); sock.setblocking(False)
            deadline = started + 12
            next_send = started
            while time.monotonic() < deadline:
                now = time.monotonic()
                if sent < args.count and now >= next_send:
                    sock.send(udp_packet(args.run,args.phase,args.side,sent,args.count,args.size))
                    sent += 1; next_send = now + .01
                for _ in select.select([sock], [], [], .005)[0]:
                    raw = sock.recv(2048)
                    try:
                        result = json.loads(raw)
                        seq = result['seq']
                        if result['run'] == args.run and result['phase'] == args.phase and 0 <= seq < sent:
                            packet = udp_packet(args.run,args.phase,args.side,seq,args.count,args.size)
                            if result['sha256'] == hashlib.sha256(packet).hexdigest():
                                seen.add(seq)
                    except (ValueError, KeyError, TypeError):
                        pass
                if len(seen) == args.count:
                    break
    except Exception as exc:
        error = dict(type=type(exc).__name__,detail=str(exc))
    emit('UDP_SENT',run=args.run,phase=args.phase,sender=args.side,sent=sent,
         acknowledged=len(seen),ack_sequences=sorted(seen),bytes_each=args.size,
         seconds=time.monotonic()-started,ok=len(seen)==args.count and error is None,error=error)
    return 0 if len(seen) == args.count and error is None else 2


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['serve','tcp','udp'])
    for name in ['run','side','bind','peer']:
        p.add_argument('--'+name,required=True)
    p.add_argument('--port',type=int,default=42053)
    p.add_argument('--phase',default='smoke')
    p.add_argument('--seconds',type=int,default=600)
    p.add_argument('--tcp-seconds',type=int,default=120)
    p.add_argument('--bytes',type=int,default=65536)
    p.add_argument('--count',type=int,default=32)
    p.add_argument('--size',type=int,default=512)
    a=p.parse_args()
    if not 1 <= a.bytes <= 67108864 or not 1 <= a.count <= 256 or not 128 <= a.size <= 1024 or not 1 <= a.seconds <= 1800 or not 1 <= a.tcp_seconds <= 120:
        p.error('budget_out_of_range')
    try:
        if a.mode == 'serve':
            return serve(a) or 0
        return send_tcp(a) if a.mode == 'tcp' else send_udp(a)
    except Exception as exc:
        emit('ERROR',run=a.run,mode=a.mode,error=type(exc).__name__,detail=str(exc))
        return 2


if __name__=='__main__':
    raise SystemExit(main())
