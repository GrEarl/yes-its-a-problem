#!/usr/bin/env python3
"""Mock Kirimochi registry.

Serves or exports a manifest, a registry-generated public key, and an empty
package payload. Manifest signatures use ECDSA via OpenSSL.

Update stage (the demo chain's RCE stage, lab only): the registry also serves an
update feed plus Brotli-compressed update bodies. The bodies are VALID Brotli
lab markers (poc/lab/http/check_brotli.py) - never a malformed stream, never an
exploit payload. The feed's digest and signature cover the genuine body; with
--poison-update the registry serves the attacker variant instead, which is the
registry-side model of a MITM substituting the body (the client must reject it
before any decoder sees it).
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    "check_brotli", REPO_ROOT / "poc/lab/http/check_brotli.py")
check_brotli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_brotli)


class Registry:
    def __init__(self, poison_update=False, signing_key=None):
        self.tmp = tempfile.TemporaryDirectory(prefix="kirimochi-registry-")
        self.dir = self.tmp.name
        self.key = os.path.join(self.dir, "publisher.key.pem")
        self.pub = os.path.join(self.dir, "publisher.pub.pem")
        self.manifest = os.path.join(self.dir, "manifest.json")
        self.sig = os.path.join(self.dir, "manifest.sig")
        self.poison_update = poison_update
        openssl = shutil.which("openssl")
        if not openssl:
            raise SystemExit("OpenSSL not found")
        if signing_key:
            # Use a supplied artifact-signing key so an export and a running
            # registry can share one publisher identity; the client then pins
            # the public half the way a real build bakes it in.
            self.key = str(Path(signing_key).resolve())
        else:
            subprocess.run([openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.key], check=True)
        subprocess.run([openssl, "ec", "-in", self.key, "-pubout", "-out", self.pub], check=True,
                       stdout=subprocess.DEVNULL)
        empty = b""
        manifest = {
            "name": "demo-lib",
            "version": "0.0.1",
            "tarball_url": "/package.tar.gz",
            "tarball_sha256": hashlib.sha256(empty).hexdigest(),
            "public_key_url": "/public_key.pem",
            "update_url": "/update/feed.json",
        }
        self.manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        with open(self.manifest, "wb") as f:
            f.write(self.manifest_bytes)
        subprocess.run([openssl, "dgst", "-sha256", "-sign", self.key, "-out", self.sig, self.manifest], check=True)
        self.signature = base64.b64encode(open(self.sig, "rb").read()).decode()
        self.public_key = open(self.pub, "rb").read()
        self.empty = empty
        self._build_update_artifacts()

    def _build_update_artifacts(self):
        """Feed + genuine/attacker Brotli lab marker bodies, signed with the registry key."""
        self.update_nonce = uuid.uuid4().hex
        genuine = check_brotli.artifact_digests(check_brotli.payload_doc("genuine", self.update_nonce))
        attacker = check_brotli.artifact_digests(check_brotli.payload_doc("attacker", self.update_nonce))
        self.update_bodies = {
            "genuine": {"br": genuine["bytes"], "plain": genuine["plain_bytes"], "nonce": self.update_nonce},
            "attacker": {"br": attacker["bytes"], "plain": attacker["plain_bytes"], "nonce": self.update_nonce},
        }
        feed = {
            "name": "demo-lib",
            "version": "0.0.2",
            "marker": check_brotli.ARTIFACT_MARKER,
            "publisher_key_url": "/public_key.pem",
            "artifacts": {
                "br": {
                    "url": "/update_body.br",
                    "encoding": "br",
                    "sha256": genuine["sha256"],
                    "signature": self.sign_bytes(genuine["bytes"]),
                },
                "plain": {
                    "url": "/update_body.json",
                    "encoding": "identity",
                    "sha256": genuine["plain_sha256"],
                    "signature": self.sign_bytes(genuine["plain_bytes"]),
                },
            },
        }
        self.update_feed_bytes = json.dumps(feed, separators=(",", ":")).encode()
        self.update_feed = feed

    def sign_bytes(self, data):
        with tempfile.TemporaryDirectory(prefix="kirimochi-sign-") as tmp:
            target = os.path.join(tmp, "body")
            signature = os.path.join(tmp, "body.sig")
            with open(target, "wb") as f:
                f.write(data)
            subprocess.run([shutil.which("openssl"), "dgst", "-sha256", "-sign", self.key,
                            "-out", signature, target], check=True, capture_output=True)
            return base64.b64encode(open(signature, "rb").read()).decode()

    def served_variant(self):
        return "attacker" if self.poison_update else "genuine"


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
        elif path == "/update/feed.json":
            self._send(200, r.update_feed_bytes, "application/json")
        elif path in ("/update_body.br", "/update_body.json"):
            variant = r.served_variant()
            key = "br" if path.endswith(".br") else "plain"
            body = r.update_bodies[variant][key]
            ctype = "application/octet-stream" if key == "br" else "application/json"
            # Server-side marker evidence: which body this request actually carried.
            print("    update body: variant=%s nonce=%s bytes=%d" %
                  (variant, r.update_bodies[variant]["nonce"], len(body)), flush=True)
            self._send(200, body, ctype)
        elif path == "/healthz":
            self._send(200, b'{"ok":true}', "application/json")
        else:
            self._send(404, b'{"error":"not found"}', "application/json")

    def log_message(self, fmt, *args):
        pass


def export_registry(registry, directory):
    """Write the public registry files; the temporary signing key is never exported."""
    os.makedirs(directory, exist_ok=True)
    variant = "attacker"
    files = (
        ("manifest.json", registry.manifest_bytes),
        ("manifest.sig.b64", (registry.signature + "\n").encode("ascii")),
        ("public_key.pem", registry.public_key),
        ("package.tar.gz", registry.empty),
        ("update_feed.json", registry.update_feed_bytes),
        ("update_body.br", registry.update_bodies["genuine"]["br"]),
        ("update_body.json", registry.update_bodies["genuine"]["plain"]),
        ("update_body.attacker.br", registry.update_bodies[variant]["br"]),
        ("update_body.attacker.json", registry.update_bodies[variant]["plain"]),
    )
    for name, body in files:
        with open(os.path.join(directory, name), "wb") as f:
            f.write(body)
    print("Public registry files written to %s; no private key exported." % directory)
    print("Update stage: marker=%s nonce=%s (genuine and attacker variants exported)"
          % (check_brotli.ARTIFACT_MARKER, registry.update_nonce))


def main():
    ap = argparse.ArgumentParser(description="Mock Kirimochi package registry")
    ap.add_argument("--bind", default="127.0.0.1", help="address to bind (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=9445, help="port to listen on (default: 9445)")
    ap.add_argument("--cert", help="path to TLS certificate (required to serve HTTPS)")
    ap.add_argument("--key", help="path to TLS private key (required to serve HTTPS)")
    ap.add_argument("--export", metavar="DIR", help="write public registry files and exit")
    ap.add_argument("--poison-update", action="store_true",
                    help="serve the attacker update body instead of the signed genuine one "
                         "(lab model of a body substitution; the feed is left untouched)")
    ap.add_argument("--signing-key", metavar="PEM",
                    help="EC private key to sign the manifest and update artifacts with "
                         "(default: a fresh key discarded on exit)")
    args = ap.parse_args()
    if not args.export and not (args.cert and args.key):
        ap.error("--cert and --key are required unless --export is used")
    registry = Registry(poison_update=args.poison_update, signing_key=args.signing_key)
    with registry.tmp:
        if args.export:
            export_registry(registry, args.export)
            return

        with ThreadingHTTPServer((args.bind, args.port), Handler) as httpd:
            httpd.registry = registry
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            print("Kirimochi mock registry running on https://%s:%d" % (args.bind, httpd.server_port), flush=True)
            if args.poison_update:
                print("Update stage: POISONED (attacker body served for /update_body.*)", flush=True)
            else:
                print("Update stage: genuine (signed body served; nonce=%s)" % registry.update_nonce, flush=True)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    main()
