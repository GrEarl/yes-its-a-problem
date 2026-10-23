#!/usr/bin/env python3
"""check_brotli.py -- Brotli decoder-path lab tooling for the demo chain (lab only).

CVE-2026-111497 ("Node2Shell" / "HTTP2Shell") is an out-of-bounds write in
Google's Brotli C streaming decoder, versions 1.0.3 through 1.2.0: a malformed
block switch is treated as "need more input" instead of a format error. This
tool never produces such a stream. It contains no malformed-stream generator
and no exploit code. Every artifact it builds is a VALID Brotli lab marker,
and the only thing this tool proves is where attacker-supplied bytes would
reach a decoder.

What it does:

  --report              read-only decoder inventory: Python brotli/brotlicffi
                        versions, the system libbrotli, the Node runtime, the
                        automatic-br client frameworks, and a static audit of
                        which repo files decode Brotli at all. Exit 1 only when
                        a VULNERABLE row is found; UNKNOWN rows do not fail.
  --make-artifact DIR   write the lab update artifacts (valid Brotli marker
                        bodies and their plain twins) into DIR.
  --check-artifact F    decompress F and print the marker document plus the
                        identity of the decoder that produced it.
  --emit-evidence OUT   run poc/lab/http/brotli_decode_probe.js (the demo
                        client's update-decode step) under the host Node
                        runtime and, optionally, under pinned runtimes, and
                        write one evidence JSON with all runtime versions.

Pinned runtimes (for the "path reached on a vulnerable decoder" evidence):

  --runtime-bin PATH    run the probe with this node binary
  --runtime-image IMG   run the probe inside a Docker image (e.g.
                        docker.io/library/node:22.22.3), mounting a scratch
                        directory read-write

This script is lab-only and loopback/file-only: apart from an explicitly
requested Docker run it never opens a socket.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
SCAN_DIRS = ("poc", "demo")
SCAN_SKIP_DIRS = {"dist", "node_modules", "__pycache__", "vendor", ".git"}
AUTO_CLIENTS = ("requests", "urllib3", "httpx", "aiohttp")

# Fix baselines. PyPI package versions key on the package release; vendored
# copies (Node's, Chromium's) key on the RUNTIME version, because the fix is a
# cherry-pick that leaves the vendored version string at 1.2.0.
BROTLI_FIXED = (1, 2, 1)
BROTLI_RANGE = ((1, 0, 3), (1, 2, 0))
BROTLICFFI_FIXED = (1, 2, 1, 0)
BROTLICFFI_RANGE = ((1, 0, 3), (1, 2, 0, 2))
NODE_FIXED = ((22, 23, 4), (24, 22, 1), (26, 12, 1))

ARTIFACT_MARKER = "LAB-BROTLI-ARTIFACT"
ARTIFACT_NOTE = ("Lab marker body for the update stage of the demo chain. "
                 "Valid Brotli only: no malformed stream, no memory-corruption "
                 "payload, no exploit code.")
DECODE_CALL_SITES = ("brotliDecompress", "createBrotliDecompress", "BrotliDecoderDecompress",
                     "decode_brotli", "decompress(")


class DecoderUnavailable(RuntimeError):
    pass


def parse_version(text):
    parts = []
    for token in str(text).replace("-", ".").split("."):
        digits = ""
        started = False
        for ch in token:
            if ch.isdigit():
                digits += ch
                started = True
            elif started:
                break
        if not digits:
            if started or parts:
                break
            continue
        parts.append(int(digits))
        if len(parts) == len(BROTLICFFI_FIXED):
            break
    return tuple(parts) or None


def _lib_version(lib):
    """Query BrotliDecoderVersion()/BrotliEncoderVersion().

    Current brotli packs the release as (major << 24) | (minor << 12) | revision;
    older releases used major*1000000 + minor*1000 + revision. Try both and
    return the one that looks like a release triple.
    """
    for name in ("BrotliDecoderVersion", "BrotliEncoderVersion"):
        function = getattr(lib, name, None)
        if function is None:
            continue
        function.restype = ctypes.c_uint
        packed = function()
        shifted = (packed >> 24, (packed >> 12) & 0xFFF, packed & 0xFFF)
        if shifted[0] <= 9 and shifted[1] < 100 and shifted[2] < 100:
            return shifted
        decimal = (packed // 1000000, (packed // 1000) % 1000, packed % 1000)
        if decimal[0] <= 9:
            return decimal
    return None


def compare(a, b):
    width = max(len(a), len(b))
    left = tuple(a) + (0,) * (width - len(a))
    right = tuple(b) + (0,) * (width - len(b))
    return (left > right) - (left < right)


def status_for(version, fixed, vulnerable_range):
    if not version:
        return "UNKNOWN"
    if vulnerable_range and compare(version, vulnerable_range[0]) >= 0 and compare(version, vulnerable_range[1]) <= 0:
        return "VULNERABLE"
    if compare(version, fixed) >= 0:
        return "FIXED"
    return "UNKNOWN"


def node_status(version_text):
    version = parse_version(version_text)
    if not version:
        return "UNKNOWN"
    for line in NODE_FIXED:
        if version[0] == line[0]:
            return "FIXED" if compare(version, line) >= 0 else "VULNERABLE"
    return "UNKNOWN"


# --------------------------------------------------------------------------
# Codec backends. Compression prefers a real encoder; the pure-Python fallback
# writes a valid Brotli stream with an uncompressed meta-block (RFC 7932 9.2)
# so the tool works without any third-party dependency.
# --------------------------------------------------------------------------

def _module_codec():
    for name in ("brotli", "brotlicffi"):
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        if hasattr(module, "compress") and hasattr(module, "decompress"):
            return name, module
    return None, None


def _load_lib(kind):
    path = ctypes.util.find_library("brotli" + kind) or ctypes.util.find_library("brotli")
    if not path:
        return None
    try:
        return ctypes.CDLL(path), path
    except OSError:
        return None, None


def _ctypes_compress(data):
    loaded = _load_lib("enc")
    if not loaded:
        return None
    lib, path = loaded
    lib.BrotliEncoderMaxCompressedSize.argtypes = [ctypes.c_size_t]
    lib.BrotliEncoderMaxCompressedSize.restype = ctypes.c_size_t
    lib.BrotliEncoderCompress.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                          ctypes.c_size_t, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
    lib.BrotliEncoderCompress.restype = ctypes.c_int
    capacity = lib.BrotliEncoderMaxCompressedSize(len(data)) or (len(data) + 1024)
    out = ctypes.create_string_buffer(capacity)
    size = ctypes.c_size_t(capacity)
    ok = lib.BrotliEncoderCompress(5, 22, 0, len(data), data, ctypes.byref(size), out)
    if not ok:
        return None
    return out.raw[:size.value], "ctypes:" + os.path.basename(path)


def _ctypes_decompress(data):
    loaded = _load_lib("dec")
    if not loaded:
        return None
    lib, path = loaded
    lib.BrotliDecoderDecompress.argtypes = [ctypes.c_size_t, ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
    lib.BrotliDecoderDecompress.restype = ctypes.c_int
    capacity = max(4096, len(data) * 8)
    for _ in range(8):
        out = ctypes.create_string_buffer(capacity)
        size = ctypes.c_size_t(capacity)
        result = lib.BrotliDecoderDecompress(len(data), data, ctypes.byref(size), out)
        if result == 1:
            return out.raw[:size.value], "ctypes:" + os.path.basename(path)
        if result != 3:  # not SUCCESS and not NEEDS_MORE_OUTPUT
            break
        capacity *= 4
    return None


class _BitWriter:
    def __init__(self):
        self.buf = bytearray()
        self.acc = 0
        self.nbits = 0

    def put(self, value, nbits):
        self.acc |= (value & ((1 << nbits) - 1)) << self.nbits
        self.nbits += nbits
        while self.nbits >= 8:
            self.buf.append(self.acc & 0xFF)
            self.acc >>= 8
            self.nbits -= 8

    def align(self):
        if self.nbits:
            self.buf.append(self.acc & 0xFF)
            self.acc = 0
            self.nbits = 0


def pack_uncompressed(data):
    """Write data as a valid Brotli stream (window 16, one uncompressed meta-block).

    This is a fallback encoder for dependency-free lab fixtures. It emits valid
    Brotli only: uncompressed meta-blocks plus an empty final meta-block.
    """
    if not 1 <= len(data) <= 65536:
        raise ValueError("pure-python Brotli writer handles 1..65536 bytes")
    writer = _BitWriter()
    writer.put(0, 1)                       # WBITS = 16
    writer.put(0, 1)                       # ISLAST = 0
    writer.put(0, 2)                       # MNIBBLES = 0 -> 4 nibbles
    writer.put(len(data) - 1, 16)          # MLEN - 1
    writer.put(1, 1)                       # ISUNCOMPRESSED = 1
    writer.align()
    writer.buf.extend(data)
    writer.put(1, 1)                       # ISLAST = 1
    writer.put(1, 1)                       # ISLASTEMPTY = 1
    writer.align()
    return bytes(writer.buf)


def compress(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    name, module = _module_codec()
    if module is not None:
        return module.compress(data), "module:" + name
    packed = _ctypes_compress(data)
    if packed is not None:
        return packed
    return pack_uncompressed(data), "builtin:uncompressed-metablock"


def decompress(data, allow_node=True):
    name, module = _module_codec()
    if module is not None:
        return module.decompress(data), "module:" + name
    unpacked = _ctypes_decompress(data)
    if unpacked is not None:
        return unpacked
    if allow_node and shutil.which("node"):
        script = ("process.stdout.write(require('node:zlib')"
                  ".brotliDecompressSync(require('node:fs').readFileSync(0)))")
        result = subprocess.run(["node", "-e", script], input=data, capture_output=True)
        if result.returncode == 0:
            return result.stdout, "node:zlib(subprocess)"
    raise DecoderUnavailable("no Brotli decoder: install brotli/brotlicffi or libbrotlidec")


def decoder_identity():
    name, module = _module_codec()
    if module is not None:
        version = parse_version(getattr(module, "__version__", ""))
        return {"backend": "module:" + name, "version": getattr(module, "__version__", None),
                "status": status_for(version, BROTLI_FIXED if name == "brotli" else BROTLICFFI_FIXED,
                                     BROTLI_RANGE if name == "brotli" else BROTLICFFI_RANGE)}
    loaded = _load_lib("dec")
    if loaded:
        version = _lib_version(loaded[0])
        return {"backend": "ctypes:" + os.path.basename(loaded[1]), "path": loaded[1],
                "version": ".".join(str(v) for v in version) if version else None,
                "status": status_for(version, BROTLI_FIXED, BROTLI_RANGE)}
    if shutil.which("node"):
        return {"backend": "node:zlib(subprocess)", "version": None, "status": "UNKNOWN"}
    raise DecoderUnavailable("no Brotli decoder available")


# --------------------------------------------------------------------------
# Lab artifacts: valid Brotli marker documents.
# --------------------------------------------------------------------------

def payload_doc(variant, nonce, extra=None):
    doc = {
        "artifact": ARTIFACT_MARKER,
        "variant": variant,
        "nonce": nonce,
        "note": ARTIFACT_NOTE,
    }
    if extra:
        doc.update(extra)
    return doc


def canonical(doc):
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode("utf-8")


def openssl_binary():
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL not found")
    return openssl


def generate_signing_key(directory):
    """Fresh ECDSA P-256 key for lab artifacts. Returns (private key path, public PEM)."""
    directory = Path(directory)
    key = directory / "artifact.key.pem"
    pub = directory / "artifact.pub.pem"
    subprocess.run([openssl_binary(), "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                    "-out", str(key)], check=True, capture_output=True)
    subprocess.run([openssl_binary(), "ec", "-in", str(key), "-pubout", "-out", str(pub)],
                   check=True, capture_output=True)
    key.chmod(0o600)
    return key, pub.read_bytes()


def sign(data, key_path):
    """ECDSA-SHA256 signature (DER, base64) over data, matching mock_registry."""
    with tempfile.TemporaryDirectory(prefix="brotli-sign-") as tmp:
        target = Path(tmp) / "body"
        signature = Path(tmp) / "body.sig"
        target.write_bytes(data)
        subprocess.run([openssl_binary(), "dgst", "-sha256", "-sign", str(key_path),
                        "-out", str(signature), str(target)], check=True, capture_output=True)
        import base64
        return base64.b64encode(signature.read_bytes()).decode("ascii")


def verify(data, signature_b64, public_key_pem):
    """OpenSSL verification of a sign() signature. Returns (ok, detail)."""
    import base64
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        return False, "invalid signature encoding: %s" % exc
    with tempfile.TemporaryDirectory(prefix="brotli-verify-") as tmp:
        target = Path(tmp) / "body"
        sig = Path(tmp) / "body.sig"
        pub = Path(tmp) / "pub.pem"
        target.write_bytes(data)
        sig.write_bytes(signature)
        pub.write_bytes(public_key_pem if isinstance(public_key_pem, bytes) else public_key_pem.encode("ascii"))
        result = subprocess.run([openssl_binary(), "dgst", "-sha256", "-verify", str(pub),
                                 "-signature", str(sig), str(target)],
                                capture_output=True, text=True)
        return result.returncode == 0, (result.stdout or result.stderr or "").strip()


def make_artifact_bytes(doc):
    body, backend = compress(canonical(doc))
    return body, backend


def artifact_digests(doc):
    """sha256 of the compressed body and of the plain body, for the update feed."""
    plain = canonical(doc)
    compressed, backend = make_artifact_bytes(doc)
    return {
        "sha256": hashlib.sha256(compressed).hexdigest(),
        "plain_sha256": hashlib.sha256(plain).hexdigest(),
        "encoder_backend": backend,
        "bytes": compressed,
        "plain_bytes": plain,
    }


# --------------------------------------------------------------------------
# Read-only decoder inventory
# --------------------------------------------------------------------------

def scan_decode_sites():
    sites = []
    for name in SCAN_DIRS:
        base = ROOT / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in (".js", ".py", ".mjs", ".cjs"):
                continue
            if SCAN_SKIP_DIRS.intersection(path.parts):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*", '"""', "'''")):
                    continue
                if any(site in line for site in DECODE_CALL_SITES) and "check_brotli" not in path.name:
                    sites.append("%s:%d" % (path.relative_to(ROOT), number))
    return sites


def report_rows():
    rows = []
    identity = None
    try:
        identity = decoder_identity()
    except DecoderUnavailable:
        identity = {"backend": "none", "status": "UNKNOWN"}
    rows.append({"name": "python brotli decoder", "detail": json.dumps(identity),
                 "status": identity.get("status", "UNKNOWN")})
    for name, fixed, vulnerable in (("brotli", BROTLI_FIXED, BROTLI_RANGE),
                                    ("brotlicffi", BROTLICFFI_FIXED, BROTLICFFI_RANGE)):
        try:
            module = importlib.import_module(name)
        except Exception:
            rows.append({"name": "module " + name, "detail": "not installed", "status": "UNKNOWN"})
            continue
        version = getattr(module, "__version__", "")
        rows.append({"name": "module " + name, "detail": "version " + str(version),
                     "status": status_for(parse_version(version), fixed, vulnerable)})
    for name in AUTO_CLIENTS:
        try:
            module = importlib.import_module(name)
        except Exception:
            rows.append({"name": "auto-br client " + name, "detail": "not installed", "status": "UNKNOWN"})
            continue
        rows.append({"name": "auto-br client " + name,
                     "detail": "installed; decodes Content-Encoding: br automatically",
                     "status": "VULNERABLE"})
    node = shutil.which("node")
    if node:
        version = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip()
        rows.append({"name": "node runtime (host)", "detail": version,
                     "status": node_status(version)})
    else:
        rows.append({"name": "node runtime (host)", "detail": "not found", "status": "UNKNOWN"})
    # Electron links exactly ONE Brotli: Chromium's //third_party/brotli (the GN
    # patch drops Node's deps/brotli). The fix boundary is the CHROMIUM major
    # version (>= 148 = Electron >= 42), not the bundled Node version.
    rows.append({"name": "electron legacy 36.9.5",
                 "detail": "Chromium 136.0.7103.177, brotli 1.0.9-era snapshot "
                           "(single decoder: net.fetch, renderer, fetch(), node:zlib)",
                 "status": "VULNERABLE"})
    rows.append({"name": "electron hardened 45.0.0",
                 "detail": "Chromium 156.0.8078.48, brotli pin cfa184a9 (fix present); "
                           "boundary: Chromium >= 148 = Electron >= 42",
                 "status": "FIXED"})
    sites = scan_decode_sites()
    rows.append({"name": "repo decode call sites",
                 "detail": ("; ".join(sites) if sites else "none"),
                 "status": "INFO"})
    return rows


# --------------------------------------------------------------------------
# Runtime probe driver (poc/lab/http/brotli_decode_probe.js)
# --------------------------------------------------------------------------

PROBE = Path(__file__).resolve().parent / "brotli_decode_probe.js"
POLICY_MODULE = ROOT / "demo/electron-payment/update-policy.js"


def probe_command(runtime, workdir):
    """Return the argv prefix for the probe under the requested runtime."""
    if runtime.startswith("docker:"):
        image = runtime.split(":", 1)[1]
        return ["docker", "run", "--rm", "-v", str(workdir) + ":/work", "-w", "/work",
                "--entrypoint", "node", image, "/work/brotli_decode_probe.js"]
    binary = runtime or shutil.which("node") or "node"
    return [binary, str(PROBE)]


def run_probe(runtime, feed, artifact, options, workdir=None):
    workdir = Path(workdir) if workdir else PROBE.parent
    command = probe_command(runtime, str(workdir))
    args = ["--feed", str(feed), "--artifact", str(artifact)]
    for key, value in options.items():
        args += ["--" + key, str(value)]
    environment = dict(os.environ)
    if runtime.startswith("docker:"):
        # Docker mounts the scratch directory at /work; ship the probe and the
        # policy module there and rewrite every path argument.
        shutil.copyfile(PROBE, workdir / "brotli_decode_probe.js")
        shutil.copyfile(POLICY_MODULE, workdir / "update-policy.js")
        environment["UPDATE_POLICY_MODULE"] = "/work/update-policy.js"
        prefix = str(workdir) + os.sep
        args = ["/work/" + a[len(prefix):] if a.startswith(prefix) else a for a in args]
    result = subprocess.run(command + args, capture_output=True, text=True, env=environment)
    if result.returncode != 0:
        return {"runtime": runtime, "error": (result.stderr or result.stdout).strip()[:400]}
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except Exception:
        return {"runtime": runtime, "error": "unparseable probe output", "raw": result.stdout[:400]}


def emit_evidence(out_path, runtimes, pinned_key=None):
    """Run the decode-step probe matrix and write one evidence JSON.

    Matrix: every runtime x {legacy, hardened} x {attacker body, genuine body},
    plus a hardened run without a pinned key (fail-closed control).
    """
    import base64
    import datetime
    import uuid
    work = Path(tempfile.mkdtemp(prefix="brotli-evidence-"))
    try:
        nonce = uuid.uuid4().hex
        attacker_body, _ = make_artifact_bytes(payload_doc("attacker", nonce))
        genuine_doc = payload_doc("genuine", nonce)
        genuine = artifact_digests(genuine_doc)
        key_path, public_pem = generate_signing_key(work)
        (work / "update_body.attacker.br").write_bytes(attacker_body)
        (work / "update_body.br").write_bytes(genuine["bytes"])
        (work / "update_body.json").write_bytes(genuine["plain_bytes"])
        feed = {
            "name": "demo-lib",
            "version": "0.0.2",
            "marker": ARTIFACT_MARKER,
            "artifacts": {
                "br": {"url": "/update_body.br", "encoding": "br",
                       "sha256": genuine["sha256"],
                       "signature": sign(genuine["bytes"], key_path)},
                "plain": {"url": "/update_body.json", "encoding": "identity",
                          "sha256": genuine["plain_sha256"],
                          "signature": sign(genuine["plain_bytes"], key_path)},
            },
        }
        (work / "feed.json").write_text(json.dumps(feed, indent=2))
        pin = Path(pinned_key) if pinned_key else (work / "artifact.pub.pem")
        if pinned_key:
            shutil.copyfile(pinned_key, work / Path(pinned_key).name)
            pin = work / Path(pinned_key).name
        runs = []
        for runtime in runtimes:
            for policy_name, body, use_key, label in (
                    ("legacy", "update_body.attacker.br", False, "attacker body, no checks"),
                    ("legacy", "update_body.br", False, "genuine body, no checks"),
                    ("hardened", "update_body.attacker.br", True, "attacker body, pinned key"),
                    ("hardened", "update_body.br", True, "genuine body, pinned key"),
                    ("hardened", "update_body.attacker.br", False, "attacker body, hardened without pinned key")):
                options = {"policy": policy_name, "stack": "node:zlib", "artifact-name": "br"}
                if use_key:
                    options["pinned-key"] = str(pin)
                record = run_probe(runtime, work / "feed.json", work / body, options, workdir=work)
                record["run"] = "%s / %s / %s" % (runtime or "host-node", policy_name, label)
                runs.append(record)
        evidence = {
            "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "host": {
                "python": sys.version.split()[0],
                "node": subprocess.run([shutil.which("node") or "node", "--version"],
                                       capture_output=True, text=True).stdout.strip()
                        if shutil.which("node") else None,
                "decoder": None,
            },
            "artifact": {
                "marker": ARTIFACT_MARKER, "nonce": nonce,
                "attacker_sha256": hashlib.sha256(attacker_body).hexdigest(),
                "genuine_sha256": genuine["sha256"],
                "encoder_backend": genuine["encoder_backend"],
                "pinned_key_sha256": hashlib.sha256(public_pem).hexdigest(),
            },
            "decode_runs": runs,
            "note": ("Valid Brotli lab markers only: no malformed stream, no memory-corruption "
                     "payload, no exploit code. decode_calls is the number of node:zlib decoder "
                     "invocations the policy performed; decision is the per-request marker "
                     "(DECODED / SIG_REJECTED / ACCEPTED)."),
        }
        try:
            evidence["host"]["decoder"] = decoder_identity()
        except DecoderUnavailable:
            evidence["host"]["decoder"] = {"backend": "none"}
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(evidence, indent=2) + "\n")
        return evidence
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", action="store_true", help="read-only decoder inventory")
    ap.add_argument("--make-artifact", metavar="DIR", help="write lab update artifacts into DIR")
    ap.add_argument("--check-artifact", metavar="FILE", help="decompress FILE and print the marker doc")
    ap.add_argument("--variant", default="attacker", choices=["genuine", "attacker"])
    ap.add_argument("--nonce", help="nonce to embed in the marker document")
    ap.add_argument("--emit-evidence", metavar="OUT", help="write decode-step evidence JSON")
    ap.add_argument("--runtime-bin", help="node binary for --emit-evidence (pinned vulnerable runtime)")
    ap.add_argument("--runtime-image", help="docker image for --emit-evidence")
    ap.add_argument("--pinned-key", help="publisher public key PEM for the hardened probe runs")
    args = ap.parse_args()

    if args.report:
        rows = report_rows()
        width = max(len(row["name"]) for row in rows)
        failed = False
        for row in rows:
            print("%-*s  %-8s  %s" % (width, row["name"], row["status"], row["detail"]))
            if row["status"] == "VULNERABLE":
                failed = True
        print("Decoder-path inventory: %s" % ("VULNERABLE rows found" if failed else "no vulnerable decoder in this process"))
        return 1 if failed else 0

    if args.make_artifact:
        directory = Path(args.make_artifact)
        directory.mkdir(parents=True, exist_ok=True)
        import uuid
        nonce = args.nonce or uuid.uuid4().hex
        for variant in ("genuine", "attacker"):
            doc = payload_doc(variant, nonce)
            digests = artifact_digests(doc)
            suffix = "" if variant == "genuine" else ".attacker"
            (directory / ("update_body" + suffix + ".br")).write_bytes(digests["bytes"])
            (directory / ("update_body" + suffix + ".json")).write_bytes(digests["plain_bytes"])
            print("%s: %s brotli sha256=%s (encoder %s)"
                  % (variant, len(digests["bytes"]), digests["sha256"], digests["encoder_backend"]))
        print("nonce: %s" % nonce)
        return 0

    if args.check_artifact:
        data = Path(args.check_artifact).read_bytes()
        body, backend = decompress(data)
        doc = json.loads(body.decode("utf-8"))
        print(json.dumps({"decoder": backend, "marker": doc.get("artifact"),
                          "variant": doc.get("variant"), "nonce": doc.get("nonce"),
                          "bytes": len(data), "decoded": len(body)}, indent=2))
        return 0

    if args.emit_evidence:
        runtimes = [""]
        if args.runtime_bin:
            runtimes.append(args.runtime_bin)
        if args.runtime_image:
            runtimes.append("docker:" + args.runtime_image)
        evidence = emit_evidence(args.emit_evidence, runtimes, pinned_key=args.pinned_key)
        print(json.dumps({"wrote": str(args.emit_evidence), "runs": len(evidence["decode_runs"])}, indent=2))
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
