#!/usr/bin/env python3
"""Disposable HTTPS mirror fixture for root-isolated installed-CLI acceptance.

The only external listener is 127.0.0.1 inside a disposable Docker guest.
Never run this against an Owner/production installation.
"""
import http.server
import pathlib
import ssl
import sys
import urllib.parse

root = pathlib.Path(sys.argv[1])
cert = sys.argv[2]
key = sys.argv[3]
mode_file = pathlib.Path(sys.argv[4])
release_path = "/releases/v999.0.1"
target_bin = "stl_v999.0.1_linux_" + sys.argv[5]

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(root), **kwargs)

    def log_message(self, fmt, *args):
        pass

    def response(self, count, chunked):
        self.send_response(200)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(count))
        self.end_headers()
        # Send the declared amount, bounded in-memory and across the socket.
        remaining = count
        try:
            while remaining:
                chunk = b"X" * min(32768, remaining)
                if chunked:
                    self.wfile.write(("%x\r\n" % len(chunk)).encode("ascii"))
                    self.wfile.write(chunk + b"\r\n")
                else:
                    self.wfile.write(chunk)
                remaining -= len(chunk)
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        mode = mode_file.read_text(encoding="ascii").strip()
        if mode == "bootstrap-tamper" and path == "/install.sh":
            self.response(32, False)
            return
        if path == release_path + "/install.sh":
            if mode == "installer-oversize-known":
                self.response(1048577, False)
                return
            if mode == "installer-oversize-chunked":
                self.response(1048577, True)
                return
        if path == release_path + "/SHA256SUMS":
            if mode == "sums-oversize-chunked":
                self.response(65537, True)
                return
            if mode == "sums-tamper":
                self.response(128, False)
                return
        if path == release_path + "/BUILD-MANIFEST.txt":
            if mode == "manifest-oversize-known":
                self.response(65537, False)
                return
            if mode == "manifest-truncated":
                self.send_response(200)
                self.send_header("Content-Length", "1024")
                self.end_headers()
                self.wfile.write(b"incomplete")
                self.close_connection = True
                return
        if path == release_path + "/" + target_bin:
            if mode == "asset-oversize-chunked":
                self.response(134217729, True)
                return
            if mode == "asset-tamper":
                self.response(1024, False)
                return
        return super().do_GET()

server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(cert, key)
server.socket = tls.wrap_socket(server.socket, server_side=True)
print("DISPOSABLE_MIRROR_HTTPS_READY", flush=True)
server.serve_forever()
