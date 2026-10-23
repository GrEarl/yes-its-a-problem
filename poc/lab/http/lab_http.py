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

All responses are deliberately harmless.  No credentials are read or stored.
"""
import argparse
import html
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOG_LOCK = threading.Lock()
ARGS = None


def log(record):
    if not ARGS.log:
        return
    try:
        with LOG_LOCK:
            with open(ARGS.log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def make_context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def build_tls_context():
    base = make_context(ARGS.cert, ARGS.key) if ARGS.cert and ARGS.key else None
    forged = None
    if ARGS.forged_cert and ARGS.forged_key:
        forged = make_context(ARGS.forged_cert, ARGS.forged_key)
    if base is not None and forged is not None and ARGS.forged_sni:
        patterns = tuple(p.lower().strip() for p in ARGS.forged_sni.split(",") if p.strip())

        def sni(sslobj, server_name, _ctx):
            name = (server_name or "").lower()
            if any(name == p or name.endswith("." + p) for p in patterns):
                sslobj.context = forged
                sslobj._yip_forged = True
        base.set_servername_callback(sni)
    return base or forged


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

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self._common_headers(urlparse(self.path).path)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
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
        if path == "/probe":
            self._send(200, {"path": ARGS.role, "token": token,
                             "host": self.headers.get("Host", ""),
                             "ts": time.time()})
            return
        if path == "/tls-probe":
            forged = bool(getattr(self.connection, "_yip_forged", False) or ARGS.cert_is_forged)
            self._send(200, {"path": ARGS.role, "tls": "forged" if forged else "valid",
                             "host": self.headers.get("Host", ""), "ts": time.time()})
            return
        if path == "/api/quote":
            if ARGS.role == "true":
                self._send(200, {"network": "true", "merchant": "Karategata Demo Shop",
                                 "account": "KBC-0001", "amount": 1000, "currency": "JPY",
                                 "ts": time.time()})
            else:
                self._send(200, {"network": "fake", "merchant": "Karategata Demo Shop",
                                 "account": "ATTACKER-9999", "amount": 999999, "currency": "JPY",
                                 "ts": time.time()})
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

    def _pay_body(self):
        if ARGS.role == "true":
            return {"status": "paid", "network": "true", "merchant": "Karategata Demo Shop",
                    "account": "KBC-0001", "amount": 1000, "currency": "JPY",
                    "receipt": "DEMO-RECEIPT-0001"}
        return {"status": "paid", "network": "fake", "merchant": "Karategata Demo Shop",
                "account": "ATTACKER-9999", "amount": 999999, "currency": "JPY",
                "receipt": "DEMO-FORGED-RECEIPT"}

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
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True, choices=["true", "fake"])
    ap.add_argument("--bind", default="127.0.0.1", help="use 0.0.0.0 explicitly for a public lab")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--forged-cert")
    ap.add_argument("--forged-key")
    ap.add_argument("--forged-sni", default="login.v.lab.yes-its-a-problem.iamwonderingif.com,login.v.lab")
    ap.add_argument("--cert-is-forged", action="store_true", help="the --cert used for every SNI is the forged leaf")
    ap.add_argument("--log")
    ARGS = ap.parse_args()

    httpd = ThreadingHTTPServer((ARGS.bind, ARGS.port), Handler)
    httpd.daemon_threads = True
    if ARGS.cert and ARGS.key:
        ctx = build_tls_context()
        if ctx is None:
            raise SystemExit("no TLS context")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("lab_http role=%s bind=%s:%d tls=%s" %
          (ARGS.role, ARGS.bind, ARGS.port, bool(ARGS.cert)), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
