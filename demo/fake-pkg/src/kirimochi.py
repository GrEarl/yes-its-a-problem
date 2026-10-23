#!/usr/bin/env python3
"""Kirimochi: package manager demo (English only).

Fetches a manifest, a registry-provided public key, and an empty package, then
verifies the manifest signature with OpenSSL. Does not install or execute the
package.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

VERSION = "0.1.0"
DEMO_NAME = "kirimochi"
DEFAULT_URL = "https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com"


class ConnectHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection supporting optional host and port overrides for local lab testing."""

    def __init__(self, host, port, context, connect_host=None, connect_port=None, timeout=10):
        self._connect_host = connect_host
        self._connect_port = connect_port
        self._context = context
        self._timeout = timeout
        super().__init__(host, port, context=context, timeout=timeout)

    def connect(self):
        target = self._connect_host or self.host
        port = self._connect_port or self.port
        sock = socket.create_connection((target, port), self._timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def eprint(*a):
    print(*a, file=sys.stderr)


def fetch(conn, path, host):
    conn.request("GET", path, headers={"Host": host, "User-Agent": "kirimochi-demo/0.1",
                                       "Accept": "*/*", "Connection": "close"})
    resp = conn.getresponse()
    body = resp.read()
    headers = {k.lower(): v for k, v in resp.getheaders()}
    return resp.status, headers, body


def verify_with_openssl(manifest_bytes, signature_b64, public_key_pem):
    openssl = shutil.which("openssl")
    if not openssl:
        return None, "OpenSSL not found"
    with tempfile.TemporaryDirectory(prefix="kirimochi-") as td:
        m = os.path.join(td, "manifest.json")
        s = os.path.join(td, "manifest.sig")
        p = os.path.join(td, "publisher.pem")
        with open(m, "wb") as f:
            f.write(manifest_bytes)
        with open(s, "wb") as f:
            f.write(base64.b64decode(signature_b64))
        with open(p, "wb") as f:
            f.write(public_key_pem)
        res = subprocess.run([openssl, "dgst", "-sha256", "-verify", p, "-signature", s, m],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return res.returncode == 0, (res.stdout or "").strip()


def parse_args(argv):
    ap = argparse.ArgumentParser(prog=DEMO_NAME, description="Kirimochi package manager demo")
    ap.add_argument("command", choices=["install"], help="demo command ('install' only)")
    ap.add_argument("name", nargs="?", default="demo-lib", help="package name (default: demo-lib)")
    ap.add_argument("--url", default=DEFAULT_URL, help="registry URL")
    ap.add_argument("--connect", help="connect directly to HOST:PORT (local lab)")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    parsed = urlparse(args.url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme != "https":
        eprint("kirimochi: error: HTTPS is required")
        return 3
    connect_host = None
    connect_port = None
    if args.connect:
        ch, _, cp = args.connect.partition(":")
        connect_host = ch
        connect_port = int(cp) if cp else None

    print("Kirimochi %s (Demo Package Manager)" % VERSION)
    print("Registry: %s" % args.url)
    print("Package : %s" % args.name)
    print("-" * 64)

    ctx = ssl.create_default_context()
    try:
        conn = ConnectHTTPSConnection(host, port, ctx, connect_host=connect_host,
                                      connect_port=connect_port, timeout=10)
        status, headers, manifest_bytes = fetch(conn, "/manifest.json", host)
        print("[1/4] GET /manifest.json      -> %d (%d bytes)" % (status, len(manifest_bytes)))
        if status != 200:
            eprint("kirimochi: failed to fetch manifest")
            return 3
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        signature = headers.get("x-kirimochi-signature", "")
        key_url = manifest.get("public_key_url") or "/public_key.pem"
        print("      Package: %s@%s" % (manifest.get("name", "?"), manifest.get("version", "?")))

        status, _, key_bytes = fetch(conn, key_url, host)
        print("[2/4] GET %-19s -> %d (%d bytes)" % (key_url, status, len(key_bytes)))
        if status != 200:
            eprint("kirimochi: failed to fetch public key")
            return 3

        status, _, pkg = fetch(conn, manifest.get("tarball_url") or "/package.tar.gz", host)
        print("[3/4] GET %-19s -> %d (%d bytes)" % (manifest.get("tarball_url") or "/package.tar.gz", status, len(pkg)))
        if status != 200:
            eprint("kirimochi: failed to fetch package payload")
            return 3
    except ssl.SSLCertVerificationError as e:
        print()
        print("BLOCKED: TLS certificate verification failed.")
        print("This runtime rejected the forged certificate chain.")
        print("Detail: %s" % (e.reason or e))
        print("No files were installed.")
        return 2
    except ssl.SSLError as e:
        print()
        print("BLOCKED: TLS error: %s" % e)
        print("No files were installed.")
        return 2
    except Exception as e:
        print()
        print("Error: %s: %s" % (type(e).__name__, e))
        return 3

    expected = manifest.get("tarball_sha256", "")
    actual = hashlib.sha256(pkg).hexdigest()
    ok_hash = (expected == actual)
    print("[4/4] Verify SHA-256          -> %s" % ("PASS" if ok_hash else "FAIL"))
    print("      Expected: %s" % expected)
    print("      Actual  : %s" % actual)
    if not ok_hash:
        eprint("kirimochi: checksum mismatch")
        return 3

    ok_sig, sig_detail = verify_with_openssl(manifest_bytes, signature, key_bytes)
    if ok_sig is None:
        print("      Signature: UNAVAILABLE (%s)" % sig_detail)
        return 3
    print("      Signature: %s (registry-provided key; unpinned)" % ("PASS" if ok_sig else "FAIL"))
    if not ok_sig:
        print("      %s" % sig_detail)
        return 3

    print()
    print("KIRIMOCHI DEMO")
    print("  Oh no! Your DNS is poisoned, so you're on a forged network path!")
    print("  Uh-oh! Your environment cannot detect forged application signatures!")
    print()
    print("  The registry supplied both the package and the public key,")
    print("  so signature verification passed despite the untrusted source.")
    print()
    print("Signature verification passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
