#!/usr/bin/env python3
"""
lab_http.py -- probe / demo HTTP(S) endpoints for the DNS+MITM lab.

Modes
-----
true : the legitimate HTTPS server.  Serves the valid Let's Encrypt wildcard
       certificate and returns JSON {path: "true"} for /probe.
fake : the attacker HTTPS server.  Serves the same valid LE wildcard
       certificate for /probe (so the resolver check never raises a
       certificate warning), and a forged certificate for the MITM hostname
       (selected by SNI) for /tls-probe and the demo page.

All responses are static lab fixtures.  POST bodies are consumed and discarded; the request log records metadata only.

Update stage (lab only): the registry routes additionally serve an update feed
and its update bodies - VALID Brotli lab markers (check_brotli.py), never a
malformed stream and never an exploit payload.  The 'true' role serves the
signed genuine body; the 'fake' role serves the attacker variant where the
client expects the signed body (the MITM body-substitution this stage is
about).  --update-nonce replaces the static body with a per-request body whose
nonce is logged server-side with the request time.
"""
import argparse
import base64
import hashlib
import html
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

LOG_LOCK = threading.Lock()
ARGS = None
CA_METADATA = Path(__file__).resolve().parents[3] / "artifacts/impacted-intermediates.json"
REGISTRY = None
REGISTRY_TYPES = {"/manifest.json": "application/json", "/public_key.pem": "application/x-pem-file",
                  "/package.tar.gz": "application/gzip", "/update/feed.json": "application/json",
                  "/update_body.br": "application/octet-stream", "/update_body.json": "application/json"}
# Exported fixture file for each route (the attacker variants are chosen per role).
REGISTRY_FILES = {"/manifest.json": "manifest.json", "/public_key.pem": "public_key.pem",
                  "/package.tar.gz": "package.tar.gz", "/update/feed.json": "update_feed.json",
                  "/update_body.br": "update_body.br", "/update_body.json": "update_body.json"}
UPDATE_VARIANTS = {"genuine": ("update_body.br", "update_body.json"),
                   "attacker": ("update_body.attacker.br", "update_body.attacker.json")}

import importlib.util as _importlib_util
_spec = _importlib_util.spec_from_file_location(
    "check_brotli", Path(__file__).resolve().parent / "check_brotli.py")
check_brotli = _importlib_util.module_from_spec(_spec)
_spec.loader.exec_module(check_brotli)


def log(record):
    if not ARGS.log:
        return
    try:
        with LOG_LOCK:
            with open(ARGS.log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def certificate_info(cert_path):
    """Identify the lab leaf's signer, even when its issuer is omitted."""
    certs = x509.load_pem_x509_certificates(Path(cert_path).read_bytes())
    if not certs:
        raise ValueError("empty certificate chain")
    try:
        for child, issuer in zip(certs, certs[1:]):
            child.verify_directly_issued_by(issuer)
    except InvalidSignature as exc:
        raise ValueError("invalid signature in certificate chain") from exc
    entries = json.loads(CA_METADATA.read_text())
    info = {"tls": "other", "leaf_sha256": hashlib.sha256(certs[0].public_bytes(
        serialization.Encoding.DER)).hexdigest()}
    for entry in entries:
        issuer = x509.load_pem_x509_certificate(entry["pem"].encode("ascii"))
        if certs[0].issuer != issuer.subject:
            continue
        try:
            certs[0].verify_directly_issued_by(issuer)
        except InvalidSignature:
            continue
        info["tls"] = "forged"
        info["issuer_spki_sha256"] = hashlib.sha256(issuer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        break
    return info


LEGIT = {"merchant": "Karategata Demo Shop", "account": "KBC-0001",
         "amount": 1000, "currency": "JPY"}
ATTACKER = {"merchant": "Karategata Demo Shop", "account": "ATTACKER-9999",
            "amount": 999999, "currency": "JPY"}


def behavior_values(endpoint):
    """Payload for this role and endpoint under the selected MITM behaviour.

    redirect : the quote stays genuine and only the payment is rewritten, which
               models a user who reviewed a correct quote and still pays the
               attacker's account; the client can only report the mismatch after
               the payment has been processed (the default).
    observe  : the fake server returns genuine values; the client's own checks
               pass and the attacker only reads the session.
    tamper   : both the quote and the payment are rewritten, so a client that
               inspects the payload shows the mismatch at the quote stage.
    """
    if ARGS.role == "true":
        return LEGIT
    if ARGS.behavior == "tamper":
        return ATTACKER
    if ARGS.behavior == "redirect" and endpoint == "pay":
        return ATTACKER
    return LEGIT


def make_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.lab_certificate_info = certificate_info(cert)
    return ctx


def build_tls_context():
    base = make_context(ARGS.cert, ARGS.key) if ARGS.cert and ARGS.key else None
    forged = None
    if ARGS.forged_cert and ARGS.forged_key:
        forged = make_context(ARGS.forged_cert, ARGS.forged_key)
        if forged.lab_certificate_info["tls"] != "forged":
            raise ValueError("--forged-cert must be signed by a known compromised intermediate")
    if ARGS.cert_is_forged and (base is None or base.lab_certificate_info["tls"] != "forged"):
        raise ValueError("--cert-is-forged does not match the supplied certificate chain")
    if base is not None and forged is not None and ARGS.forged_sni:
        patterns = tuple(p.lower().strip() for p in ARGS.forged_sni.split(",") if p.strip())

        def sni(sslobj, server_name, _ctx):
            name = (server_name or "").lower()
            if any(name == p or name.endswith("." + p) for p in patterns):
                sslobj.context = forged
        base.set_servername_callback(sni)
    return base or forged


def load_registry(directory):
    """Read the public files exported by the demo registry.

    Validates the update stage here, so a broken export is refused at startup:
    the feed must name both artifacts with matching digests, the genuine bodies
    must carry those digests and verify under the exported publisher key, and
    the attacker variants must be present (they are what the 'fake' role serves
    in place of the signed body).
    """
    directory = Path(directory)
    files = {path: (directory / name).read_bytes() for path, name in REGISTRY_FILES.items()}
    signature = (directory / "manifest.sig.b64").read_text(encoding="ascii").strip()
    if not base64.b64decode(signature, validate=True):
        raise ValueError("empty registry signature")
    if not isinstance(json.loads(files["/manifest.json"]), dict):
        raise ValueError("registry manifest must be a JSON object")
    public_key = serialization.load_pem_public_key(files["/public_key.pem"])
    try:
        feed = json.loads(files["/update/feed.json"])
    except ValueError as exc:
        raise ValueError("update feed must be JSON: %s" % exc) from exc
    if not isinstance(feed, dict) or not isinstance(feed.get("artifacts"), dict):
        raise ValueError("update feed must be a JSON object with artifacts")
    for name in ("br", "plain"):
        entry = feed["artifacts"].get(name)
        if not isinstance(entry, dict) or not entry.get("sha256") or not entry.get("signature"):
            raise ValueError("update feed artifact %s needs sha256 and signature" % name)
        body = files["/update_body.br" if name == "br" else "/update_body.json"]
        if hashlib.sha256(body).hexdigest() != entry["sha256"]:
            raise ValueError("update feed digest does not match the exported %s body" % name)
        try:
            public_key.verify(base64.b64decode(entry["signature"], validate=True), body,
                              ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ValueError("update artifact %s signature does not verify" % name) from exc
    bodies = {}
    for variant, names in UPDATE_VARIANTS.items():
        br = (directory / names[0]).read_bytes()
        plain = (directory / names[1]).read_bytes()
        if not br or not plain:
            raise ValueError("update %s bodies must not be empty" % variant)
        bodies[variant] = {"br": br, "json": plain}
    return {"files": files, "signature": signature, "feed": feed, "bodies": bodies}


class Handler(BaseHTTPRequestHandler):
    server_version = "lab-http/1"
    protocol_version = "HTTP/1.1"

    def _common_headers(self, path):
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        host = self.headers.get("Host", "")
        log({"ts": time.time(), "role": ARGS.role, "method": self.command,
             "host": host, "path": path, "remote": self.client_address[0],
             "ua": self.headers.get("User-Agent", "")})

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self._common_headers(urlparse(self.path).path)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self._common_headers(urlparse(self.path).path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        token = (qs.get("token") or [""])[0]
        if path in REGISTRY_TYPES:
            if REGISTRY is None:
                self._send(503, {"error": "registry fixture is not configured"})
                return
            extra = None
            ctype = REGISTRY_TYPES[path]
            body = REGISTRY["files"][path]
            if path == "/manifest.json":
                extra = {"X-Kirimochi-Signature": REGISTRY["signature"]}
            elif path in ("/update_body.br", "/update_body.json"):
                body, extra, ctype = self._update_body(path, qs)
            self._send(200, body, ctype, extra)
            return
        if path == "/probe":
            self._send(200, {"path": ARGS.role, "token": token,
                             "host": self.headers.get("Host", ""),
                             "ts": time.time()})
            return
        if path == "/tls-probe":
            context = getattr(self.connection, "context", None)
            info = getattr(context, "lab_certificate_info", {"tls": "unknown"})
            self._send(200, {"path": ARGS.role, **info,
                             "host": self.headers.get("Host", ""), "ts": time.time()})
            return
        if path == "/api/quote":
            self._send(200, {"network": ARGS.role, "behavior": ARGS.behavior,
                             **behavior_values("quote"), "ts": time.time()})
            return
        if path == "/api/pay":
            self._send(200, self._pay_body())
            return
        if path == "/healthz":
            self._send(200, {"ok": True, "role": ARGS.role})
            return
        if path in ("/", "/index.html"):
            body = ("<!doctype html><meta charset=utf-8><title>lab %s</title>"
                    "<h1>lab %s</h1><p>Host: %s</p>"
                    % (ARGS.role, ARGS.role, html.escape(self.headers.get("Host", ""))))
            self._send(200, body, "text/html; charset=utf-8")
            return
        self._send(404, {"error": "not found"})

    def _update_body(self, path, qs):
        """The update-stage body for this request (lab only).

        The 'true' role serves the signed genuine body; the 'fake' role serves
        the attacker variant where the client expects the signed body.  With
        --update-nonce the body is built per request and its nonce is logged
        server-side, so a client-rendered nonce can be tied to one request.  The
        bodies are valid Brotli lab markers - never a malformed stream.
        """
        is_brotli = path.endswith(".br")
        variant = "attacker" if ARGS.role == "fake" else "genuine"
        nonce = None
        if getattr(ARGS, "update_nonce", False):
            nonce = __import__("uuid").uuid4().hex
            digests = check_brotli.artifact_digests(
                check_brotli.payload_doc(variant, nonce, {"served_by": ARGS.role}))
            body = digests["bytes"] if is_brotli else digests["plain_bytes"]
        else:
            body = REGISTRY["bodies"][variant]["br" if is_brotli else "json"]
        delivery = (qs.get("delivery") or [getattr(ARGS, "update_delivery", "artifact")])[0]
        ctype = REGISTRY_TYPES[path]
        extra = {}
        if is_brotli and delivery == "content-encoding":
            # Delivered as an HTTP-encoded body: a client that fetches this with
            # net.fetch / fetch() decodes it in its HTTP stack.
            ctype = "application/json; charset=utf-8"
            extra["Content-Encoding"] = "br"
        log({"ts": time.time(), "role": ARGS.role, "method": self.command,
             "host": self.headers.get("Host", ""), "path": path,
             "artifact_variant": variant, "artifact_nonce": nonce,
             "delivery": delivery, "remote": self.client_address[0]})
        return body, extra, ctype

    def _pay_body(self):
        receipt = "DEMO-RECEIPT-0001" if ARGS.role == "true" else "DEMO-FORGED-RECEIPT"
        return {"status": "paid", "network": ARGS.role, "behavior": ARGS.behavior,
                **behavior_values("pay"), "receipt": receipt}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        path = urlparse(self.path).path
        if path == "/api/pay":
            self._send(200, self._pay_body())
            return
        self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        pass


def main():
    global ARGS, REGISTRY
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True, choices=["true", "fake"])
    ap.add_argument("--bind", default="127.0.0.1", help="use 0.0.0.0 explicitly for a public lab")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--forged-cert")
    ap.add_argument("--forged-key")
    ap.add_argument("--forged-sni", default=",".join(
        name + suffix for name in ("login", "pay", "pkg")
        for suffix in (".v.lab.yes-its-a-problem.iamwonderingif.com", ".v.lab")))
    ap.add_argument("--behavior", choices=["observe", "tamper", "redirect"], default="redirect",
                    help="fake MITM behaviour: redirect keeps the quote genuine and "
                         "rewrites only the payment (default); observe returns genuine "
                         "values so client checks pass; tamper rewrites quote and payment")
    ap.add_argument("--cert-is-forged", action="store_true",
                    help="compatibility assertion; the served chain is always inspected")
    ap.add_argument("--log")
    ap.add_argument("--registry-dir", help="directory containing the exported public registry files")
    ap.add_argument("--update-nonce", action="store_true",
                    help="build the update bodies per request with a server-chosen nonce "
                         "(logged server-side); the body is then unsigned by construction")
    ap.add_argument("--update-delivery", choices=["artifact", "content-encoding"], default="artifact",
                    help="how /update_body.br is delivered: as a .br artifact file (default) or "
                         "as a body with Content-Encoding: br (?delivery= overrides per request)")
    ARGS = ap.parse_args()

    if bool(ARGS.cert) != bool(ARGS.key) or bool(ARGS.forged_cert) != bool(ARGS.forged_key):
        ap.error("each certificate requires its matching key")
    if ARGS.forged_cert and not ARGS.cert:
        ap.error("--forged-cert requires a base --cert for the DNS probe")
    try:
        REGISTRY = load_registry(ARGS.registry_dir) if ARGS.registry_dir else None
        ctx = build_tls_context()
    except (ValueError, OSError) as exc:
        ap.error(str(exc))

    httpd = ThreadingHTTPServer((ARGS.bind, ARGS.port), Handler)
    httpd.daemon_threads = True
    if ctx is not None:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("lab_http role=%s bind=%s:%d tls=%s" %
          (ARGS.role, ARGS.bind, ARGS.port, bool(ARGS.cert)), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
