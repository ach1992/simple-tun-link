#!/usr/bin/python3
"""Negative probes against an already active STL-managed WSS listener.
Executes only inside caller's isolated beta network namespace; never reads
or prints private certificate/header material beyond TLS socket controls.
"""
import sys, os, ssl, socket, base64, secrets, time
mode=sys.argv[1]
root="/lab/beta-state/credentials/wss/lnk_0123456789abcdef0123456789abcdef"
context=ssl.create_default_context(cafile=root+"/server-ca.pem")
if mode!="no-mtls":
    context.load_cert_chain(root+"/client-cert.pem",root+"/client-key.pem")
context.check_hostname=False
allowed_header=(open(root+"/authorization-headers","rb").read().strip().decode("ascii"))
auth="Authorization: Bearer " + "0"*64
path="/stl0123456789abcdef0123456789abcdef"
if mode=="wrong-path":
    path="/definitely-not-this-links-owned-path"
    auth=allowed_header
if mode=="no-mtls":
    auth=allowed_header
request=("GET "+path+" HTTP/1.1\r\n"
    "Host: 198.51.100.21:59443\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Key: "+base64.b64encode(os.urandom(16)).decode()+"\r\n"
    +auth+"\r\n\r\n").encode()
try:
    with socket.create_connection(("198.51.100.21",59443),timeout=4) as tcp:
        with context.wrap_socket(tcp,server_hostname="198.51.100.21") as tls:
            tls.settimeout(3)
            tls.sendall(request)
            response=tls.recv(2048)
            if b"101 Switching Protocols" in response or response.startswith(b"HTTP/1.1 101"):
                raise SystemExit("FAIL "+mode+": WSS upgrade accepted invalid identity/policy")
except (ssl.SSLError,OSError,TimeoutError,ConnectionError):
    pass
print("DENY_PASS",mode)
