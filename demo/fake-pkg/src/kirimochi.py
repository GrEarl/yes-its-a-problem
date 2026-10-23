#!/usr/bin/env python3
"""Kirimochi: package manager demo (English only).

Fetches a manifest, a registry-provided public key, and an empty package, then
verifies the manifest signature with OpenSSL. Does not install or execute the
package.

Two integrity postures are modelled deliberately:

  legacy    the verification key comes from the registry (unpinned) and the
            payload is transported before its integrity is established.
  hardened  --pinned-key supplies a publisher key the registry does not
            control; the manifest signature is verified against it BEFORE the
            payload is fetched, and the update body must pass digest + signature
            before any decoder sees it.

The "update" command models the update stage of the demo chain (lab only): it
downloads a registry update body and - in the legacy posture - hands it to the
client's Brotli decoder before any integrity check. The bodies are valid Brotli
lab markers (see poc/lab/http/check_brotli.py). This file contains no
malformed-stream generator and no exploit code.
"""
import argparse
import base64
import hashlib
import http.client
import importlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

VERSION = "0.1.1"
PROG = "kirimochi"
DEFAULT_URL = "https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com"
SITE_URL = "https://yes-its-a-problem.iamwonderingif.com/"

# Decision markers (one per request), shared vocabulary with
# demo/electron-payment/update-policy.js.
DECISIONS = ("DECODED", "ACCEPTED", "SIG_REJECTED", "ENCODING_REJECTED", "TLS_REJECTED", "INCONCLUSIVE")


class DecoderUnavailable(RuntimeError):
    """No Brotli decoder is available in this interpreter."""


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
    # Every request announces "Connection: close", so this connection is dead
    # once the body is read. http.client does not reopen a socket that the
    # server closed; without this the next fetch() writes into a half-closed
    # socket and dies with RemoteDisconnected on servers that honor the header.
    conn.close()
    return resp.status, headers, body


def verify_with_openssl(data_bytes, signature_b64, public_key_pem):
    openssl = shutil.which("openssl")
    if not openssl:
        return None, "OpenSSL not found"
    with tempfile.TemporaryDirectory(prefix="kirimochi-") as td:
        m = os.path.join(td, "body")
        s = os.path.join(td, "body.sig")
        p = os.path.join(td, "publisher.pem")
        with open(m, "wb") as f:
            f.write(data_bytes)
        try:
            sig = base64.b64decode(signature_b64, validate=True)
        except Exception as e:
            return None, "invalid signature encoding: %s" % e
        with open(s, "wb") as f:
            f.write(sig)
        with open(p, "wb") as f:
            f.write(public_key_pem)
        res = subprocess.run([openssl, "dgst", "-sha256", "-verify", p, "-signature", s, m],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return res.returncode == 0, (res.stdout or "").strip()


def decode_brotli(data_bytes):
    """Decode a Brotli body with the client's own decoder stack.

    Order: the PyPI decoders named in GHSA-9v8h-qqgm-4m35 (brotli, brotlicffi),
    then the system libbrotlidec through ctypes. Nothing is installed or
    downloaded here; if no decoder exists the caller gets DecoderUnavailable and
    must report INCONCLUSIVE rather than pretend a decode happened.
    """
    for name in ("brotli", "brotlicffi"):
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        return module.decompress(data_bytes), "module:" + name
    import ctypes
    import ctypes.util
    path = ctypes.util.find_library("brotlidec") or ctypes.util.find_library("brotli")
    if path:
        try:
            lib = ctypes.CDLL(path)
            lib.BrotliDecoderDecompress.argtypes = [ctypes.c_size_t, ctypes.c_void_p,
                                                    ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
            lib.BrotliDecoderDecompress.restype = ctypes.c_int
            capacity = max(4096, len(data_bytes) * 8)
            for _ in range(8):
                out = ctypes.create_string_buffer(capacity)
                size = ctypes.c_size_t(capacity)
                result = lib.BrotliDecoderDecompress(len(data_bytes), data_bytes,
                                                     ctypes.byref(size), out)
                if result == 1:
                    return out.raw[:size.value], "ctypes:" + os.path.basename(path)
                if result != 3:
                    break
                capacity *= 4
        except OSError:
            pass
    raise DecoderUnavailable("no Brotli decoder (brotli, brotlicffi or libbrotlidec)")


def normalize_encoding(value):
    text = (value or "").split(",")[0].strip().lower()
    return "identity" if text in ("", "identity") else text


def parse_args(argv):
    ap = argparse.ArgumentParser(prog=PROG, description="Kirimochi package manager PoC")
    ap.add_argument("command", choices=["install", "update"], help="demo command")
    ap.add_argument("name", nargs="?", default="demo-lib", choices=["demo-lib"],
                    help="demo package (default: demo-lib)")
    ap.add_argument("--url", default=DEFAULT_URL, help="registry URL")
    ap.add_argument("--connect", help="connect directly to HOST:PORT (local lab)")
    ap.add_argument("--pinned-key", metavar="PEM",
                    help="publisher public key PEM pinned by the client; when given, the "
                         "registry-supplied key is not used and the manifest signature is "
                         "checked before the payload is fetched")
    ap.add_argument("--policy", choices=["legacy", "hardened"], default="legacy",
                    help="update-stage posture (default: legacy = decode before any check)")
    ap.add_argument("--artifact", choices=["br", "plain"], default="br",
                    help="update artifact to fetch: br (Brotli body) or plain (negative control)")
    ap.add_argument("--allow-encoding", default="identity",
                    help="comma-separated Content-Encoding allow-list for the hardened policy")
    return ap.parse_args(argv)


def banner(args):
    parsed = urlparse(args.url)
    print("Kirimochi %s (PoC demo package manager)" % VERSION)
    print("PoC: Kirimochi and this registry are fictional. No package is installed.")
    print("PoC site: %s" % SITE_URL)
    print("Registry: %s" % args.url)
    if args.connect:
        print("Connect : %s (--connect; registry hostname DNS bypassed)" % args.connect)
    else:
        print("Connect : registry URL (no --connect override)")
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        print("Trust   : %s %s (process environment)" % (name, "set" if name in os.environ else "unset"))
    print("Package : %s" % args.name)
    if args.pinned_key:
        print("Key     : pinned publisher key %s (registry-supplied key not used)" % args.pinned_key)
    else:
        print("Key     : registry-supplied (unpinned)")
    print("-" * 64)
    return parsed


def connect_registry(args, parsed):
    """Open the TLS connection; returns (conn, host) or (None, exit code)."""
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme != "https":
        eprint("INCONCLUSIVE: HTTPS is required; no package was installed.")
        return None, 3
    connect_host = None
    connect_port = None
    if args.connect:
        ch, _, cp = args.connect.partition(":")
        connect_host = ch
        connect_port = int(cp) if cp else None
    ctx = ssl.create_default_context()
    try:
        conn = ConnectHTTPSConnection(host, port, ctx, connect_host=connect_host,
                                      connect_port=connect_port, timeout=10)
    except Exception as e:
        eprint("INCONCLUSIVE: %s: %s; no package was installed." % (type(e).__name__, e))
        return None, 3
    return (conn, host), None


def run_install(args, parsed):
    outcome = connect_registry(args, parsed)
    conn, host = outcome[0] if outcome[1] is None else (None, None)
    if conn is None:
        return outcome[1]
    try:
        status, headers, manifest_bytes = fetch(conn, "/manifest.json", host)
        print("[1/4] GET /manifest.json      -> %d (%d bytes)" % (status, len(manifest_bytes)))
        if status != 200:
            eprint("INCONCLUSIVE: could not fetch the manifest; no package was installed.")
            return 3
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        if manifest.get("name") != args.name:
            eprint("INCONCLUSIVE: manifest package name does not match demo-lib; no package was installed.")
            return 3
        signature = headers.get("x-kirimochi-signature", "")
        print("      Package: %s@%s" % (manifest.get("name", "?"), manifest.get("version", "?")))

        if args.pinned_key:
            # Hardened posture: establish manifest integrity with a key the
            # registry does not control BEFORE transporting the payload.
            with open(args.pinned_key, "rb") as f:
                pinned_key = f.read()
            ok_sig, sig_detail = verify_with_openssl(manifest_bytes, signature, pinned_key)
            if ok_sig is None:
                print("      Signature: UNAVAILABLE (%s)" % sig_detail)
                eprint("INCONCLUSIVE: the signature could not be checked; no package was installed.")
                return 3
            print("      Signature: %s (pinned publisher key)" % ("PASS" if ok_sig else "FAIL"))
            if not ok_sig:
                print("      %s" % sig_detail)
                print("REJECTED: manifest signature failed under the pinned key; no payload was fetched.")
                return 2
            key_bytes = pinned_key
        else:
            key_url = manifest.get("public_key_url") or "/public_key.pem"
            status, _, key_bytes = fetch(conn, key_url, host)
            print("[2/4] GET %-19s -> %d (%d bytes)" % (key_url, status, len(key_bytes)))
            if status != 200:
                eprint("INCONCLUSIVE: could not fetch the public key; no package was installed.")
                return 3

        status, _, pkg = fetch(conn, manifest.get("tarball_url") or "/package.tar.gz", host)
        print("[3/4] GET %-19s -> %d (%d bytes)" % (manifest.get("tarball_url") or "/package.tar.gz",
                                                    status, len(pkg)))
        if status != 200:
            eprint("INCONCLUSIVE: could not fetch the package payload; no package was installed.")
            return 3
    except ssl.SSLCertVerificationError as e:
        print()
        print("REJECTED: TLS certificate verification failed; no package was installed.")
        print("Detail: %s" % (getattr(e, "verify_message", None) or str(e)))
        return 2
    except ssl.SSLError as e:
        print()
        print("INCONCLUSIVE: TLS error: %s; no package was installed." % e)
        return 3
    except Exception as e:
        print()
        print("INCONCLUSIVE: %s: %s; no package was installed." % (type(e).__name__, e))
        return 3

    expected = manifest.get("tarball_sha256", "")
    actual = hashlib.sha256(pkg).hexdigest()
    ok_hash = (expected == actual)
    print("[4/4] Verify SHA-256          -> %s" % ("PASS" if ok_hash else "FAIL"))
    print("      Expected: %s" % expected)
    print("      Actual  : %s" % actual)
    if not ok_hash:
        eprint("DANGER: checksum mismatch; no package was installed.")
        return 3

    if args.pinned_key:
        print()
        print("OBSERVED: pinned manifest signature, TLS verification and package checksum passed; no package was installed.")
        print("The publisher key was pinned by the client, so the registry cannot substitute the manifest or the payload.")
        print("This result does not demonstrate signature forgery or DNS poisoning.")
        return 0

    ok_sig, sig_detail = verify_with_openssl(manifest_bytes, signature, key_bytes)
    if ok_sig is None:
        print("      Signature: UNAVAILABLE (%s)" % sig_detail)
        print("INCONCLUSIVE: the signature could not be checked; no package was installed.")
        return 3
    print("      Signature: %s (registry-provided key; unpinned)" % ("PASS" if ok_sig else "FAIL"))
    if not ok_sig:
        print("      %s" % sig_detail)
        print("DANGER: signature verification failed; no package was installed.")
        return 3

    print()
    print("OBSERVED: TLS verification, package checksum, and manifest signature passed; no package was installed.")
    print("The registry supplied the unpinned verification key, so the signature's trust depends on the registry.")
    print("This result does not demonstrate signature forgery or DNS poisoning.")
    return 0


def run_update(args, parsed):
    """The update stage: download the registry update body and decide.

    legacy   : the body goes to the Brotli decoder before any integrity check -
               the delivery precondition of CVE-2026-111497.
    hardened : content-encoding policy and digest+signature (pinned key) must
               pass before any decoder sees the bytes.
    """
    print("Update  : policy=%s artifact=%s stack=python-brotli" % (args.policy, args.artifact))
    outcome = connect_registry(args, parsed)
    conn, host = outcome[0] if outcome[1] is None else (None, None)
    if conn is None:
        return outcome[1]
    decision = "INCONCLUSIVE"
    try:
        status, _, feed_bytes = fetch(conn, "/update/feed.json", host)
        print("[1/2] GET /update/feed.json     -> %d (%d bytes)" % (status, len(feed_bytes)))
        if status != 200:
            eprint("INCONCLUSIVE: could not fetch the update feed; nothing was decoded.")
            return 3
        feed = json.loads(feed_bytes.decode("utf-8"))
        entry = (feed.get("artifacts") or {}).get(args.artifact)
        if not entry:
            eprint("INCONCLUSIVE: the update feed has no artifact named %s." % args.artifact)
            return 3

        status, headers, body = fetch(conn, entry.get("url", "/update_body.br"), host)
        encoding = normalize_encoding(headers.get("content-encoding"))
        print("[2/2] GET %-21s -> %d (%d bytes, Content-Encoding: %s)"
              % (entry.get("url", "/update_body.br"), status, len(body), encoding))
        if status != 200:
            eprint("INCONCLUSIVE: could not fetch the update body; nothing was decoded.")
            return 3

        if args.policy == "hardened":
            allowed = [normalize_encoding(x) for x in args.allow_encoding.split(",") if x.strip()]
            if encoding not in allowed:
                decision = "ENCODING_REJECTED"
                print("      Decision: ENCODING_REJECTED (Content-Encoding %s not in %s)"
                      % (encoding, allowed))
                print("REJECTED: content-encoding policy refused the response; no decoder was invoked.")
                return 2
            if not args.pinned_key:
                decision = "SIG_REJECTED"
                print("      Decision: SIG_REJECTED (no pinned publisher key)")
                print("REJECTED: hardened policy requires a pinned publisher key; no decoder was invoked.")
                return 2
            with open(args.pinned_key, "rb") as f:
                pinned_key = f.read()
            digest_ok = hashlib.sha256(body).hexdigest() == entry.get("sha256", "")
            ok_sig, sig_detail = verify_with_openssl(body, entry.get("signature", ""), pinned_key)
            print("      Integrity: digest %s, signature %s"
                  % ("PASS" if digest_ok else "FAIL", "PASS" if ok_sig else "FAIL"))
            if not digest_ok or not ok_sig:
                decision = "SIG_REJECTED"
                print("      Decision: SIG_REJECTED (%s)" % sig_detail)
                print("REJECTED: update body failed the pre-decode integrity check; no decoder was invoked.")
                return 2

        wants_decode = args.artifact == "br" or encoding == "br"
        if not wants_decode:
            decision = "ACCEPTED"
            print("      Decision: ACCEPTED (plain body; no decode step)")
            print("OBSERVED: decision=ACCEPTED policy=%s; no decoder was needed." % args.policy)
            return 0

        try:
            decoded, backend = decode_brotli(body)
        except DecoderUnavailable as e:
            print("      Decision: INCONCLUSIVE (%s)" % e)
            eprint("INCONCLUSIVE: no Brotli decoder available; nothing was decoded.")
            return 3
        doc = json.loads(decoded.decode("utf-8"))
        decision = "DECODED"
        print("      Decision: DECODED")
        print("      Decoder : %s" % backend)
        print("      Marker  : %s variant=%s nonce=%s"
              % (doc.get("artifact"), doc.get("variant"), doc.get("nonce")))
    except ssl.SSLCertVerificationError as e:
        print()
        print("REJECTED: TLS certificate verification failed; nothing was decoded.")
        print("Detail: %s" % (getattr(e, "verify_message", None) or str(e)))
        return 2
    except ssl.SSLError as e:
        print()
        print("INCONCLUSIVE: TLS error: %s; nothing was decoded." % e)
        return 3
    except Exception as e:
        print()
        print("INCONCLUSIVE: %s: %s; nothing was decoded." % (type(e).__name__, e))
        return 3

    print()
    if decision == "DECODED":
        print("OBSERVED: decision=DECODED policy=%s; the update body reached the client's Brotli decoder." % args.policy)
        if args.policy == "legacy":
            print("The legacy posture decodes attacker-supplied bytes before any integrity check "
                  "(CVE-2026-111497 delivery precondition).")
        else:
            print("The hardened posture verified the body before decode (digest + pinned-key signature).")
    return 0


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    parsed = banner(args)
    if args.command == "update":
        return run_update(args, parsed)
    return run_install(args, parsed)


if __name__ == "__main__":
    sys.exit(main())
