#!/usr/bin/env python3
"""Mock Kirimochi registry.

Serves a manifest, a registry-generated public key, and an empty package payload.
Manifest signatures use ECDSA via OpenSSL.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class Registry:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="kirimochi-registry-")
        self.dir = self.tmp.name
        self.key = os.path.join(self.dir, "publisher.key.pem")
        self.pub = os.path.join(self.dir, "publisher.pub.pem")
        self.manifest = os.path.join(self.dir, "manifest.json")
        self.sig = os.path.join(self.dir, "manifest.sig")
        openssl = shutil.which("openssl")
        if not openssl:
            raise SystemExit("OpenSSL not found")
        subprocess.run([openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.key], check=True)
        subprocess.run([openssl, "ec", "-in", self.key, "-pubout", "-out", self.pub], check=True,
                       stdout=subprocess.DEVNULL)
        empty = b""
        manifest = {
            "name": "demo-lib",
            "version": "0.0.1",
            "tarball_url": "/package.tar.gz",
            "tarball_sha256": hashlib.sha256(empty).hexdigest(),
            "public_key_url": "/public_key.pem"
        }
        self.manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        with open(self.manifest, "wb") as f:
            f.write(self.manifest_bytes)
        subprocess.run([openssl, "dgst", "-sha256", "-sign", self.key, "-out", self.sig, self.manifest], check=True)
        self.signature = base64.b64encode(open(self.sig, "rb").read()).decode()
        self.public_key = open(self.pub, "rb").read()
        self.empty = empty


class Handler(BaseHTTPRequestHandler):
    server_version = "kirimochi-registry/0.1"

    def _send(self, code, body, ctype="application/octet-stream", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        r = self.server.registry
        print("GET %s (host: %s)" % (path, self.headers.get("Host", "")), flush=True)
        if path == "/manifest.json":
            self._send(200, r.manifest_bytes, "application/json",
                       {"X-Kirimochi-Signature": r.signature})
        elif path == "/public_key.pem":
            self._send(200, r.public_key, "application/x-pem-file")
        elif path == "/package.tar.gz":
            self._send(200, r.empty, "application/gzip")
        elif path == "/healthz":
            self._send(200, b'{"ok":true}', "application/json")
        else:
            self._send(404, b'{"error":"not found"}', "application/json")

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser(description="Mock Kirimochi package registry")
    ap.add_argument("--bind", default="127.0.0.1", help="address to bind (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=9445, help="port to listen on (default: 9445)")
    ap.add_argument("--cert", required=True, help="path to TLS certificate")
    ap.add_argument("--key", required=True, help="path to TLS private key")
    args = ap.parse_args()
    registry = Registry()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.registry = registry
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("Kirimochi mock registry running on https://%s:%d" % (args.bind, args.port), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
