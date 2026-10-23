"""Local checks using synthetic keys, loopback HTTPS, and a packaged client."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch
import zipapp

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "server")]
import kirimochi
from mock_registry import Registry


def run(responses, extra=(), overrides=None, command="install"):
    output, errors = io.StringIO(), io.StringIO()
    with patch.dict(os.environ), patch.object(kirimochi, "ConnectHTTPSConnection") as connection:
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            os.environ.pop(name, None)
        os.environ.update(overrides or {})
        with patch.object(kirimochi, "fetch", side_effect=responses):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                code = kirimochi.main([command, "--url", "https://registry.example", *extra])
        context = connection.call_args.args[2]
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    return code, output.getvalue() + errors.getvalue()


def update_responses(registry, variant, artifact="br", encoding="identity"):
    body = registry.update_bodies[variant]["br" if artifact == "br" else "plain"]
    return [(200, {}, registry.update_feed_bytes), (200, {"content-encoding": encoding}, body)]


def decoder_available():
    registry = Registry()
    try:
        kirimochi.decode_brotli(registry.update_bodies["genuine"]["br"])
    except kirimochi.DecoderUnavailable:
        return False
    finally:
        registry.tmp.cleanup()
    return True


def check():
    registry = Registry()
    try:
        headers = {"x-kirimochi-signature": registry.signature}
        responses = [(200, headers, registry.manifest_bytes),
                     (200, {}, registry.public_key), (200, {}, registry.empty)]

        code, output = run(responses)
        assert code == 0 and "OBSERVED:" in output and "unpinned verification key" in output
        assert "cannot detect forged" not in output
        assert "no --connect override" in output
        assert "SSL_CERT_FILE unset" in output and "SSL_CERT_DIR unset" in output

        code, output = run(responses, ["demo-lib", "--connect", "127.0.0.1:9445"],
                           {"SSL_CERT_FILE": "unused-root.pem", "SSL_CERT_DIR": "unused-certs"})
        assert code == 0 and "127.0.0.1:9445 (--connect; registry hostname DNS bypassed)" in output
        assert "SSL_CERT_FILE set" in output and "SSL_CERT_DIR set" in output

        code, output = run([(200, headers, registry.manifest_bytes + b" "), *responses[1:]])
        assert code == 3 and "Signature: FAIL" in output
        code, output = run([*responses[:2], (200, {}, b"changed payload")])
        assert code == 3 and "checksum mismatch" in output

        wrong_name = registry.manifest_bytes.replace(b"demo-lib", b"other-lib")
        code, output = run([(200, headers, wrong_name)])
        assert code == 3 and "manifest package name does not match demo-lib" in output

        error = ssl.SSLCertVerificationError("synthetic certificate rejection")
        error.verify_message = "synthetic hostname mismatch"
        code, output = run(error)
        assert code == 2 and "REJECTED:" in output and error.verify_message in output
        code, output = run(ssl.SSLError("synthetic protocol failure"))
        assert code == 3 and "INCONCLUSIVE: TLS error" in output

        with contextlib.redirect_stderr(io.StringIO()):
            try:
                kirimochi.parse_args(["install", "other-lib"])
            except SystemExit as error:
                assert error.code == 2
            else:
                raise AssertionError("unexpected package name accepted")

        with tempfile.TemporaryDirectory(prefix="kirimochi-pin-") as td:
            pinned = Path(td) / "publisher.pem"
            pinned.write_bytes(registry.public_key)

            # --- pinned key: manifest integrity before payload transport ---
            code, output = run([(200, headers, registry.manifest_bytes), (200, {}, registry.empty)],
                               ["--pinned-key", str(pinned)])
            assert code == 0 and "OBSERVED:" in output and "pinned publisher key" in output
            assert "unpinned verification key" not in output
            # Only ONE fetch response is supplied here: if the payload were
            # fetched before the signature check, the run would run out of
            # responses and report INCONCLUSIVE instead of the rejection.
            code, output = run([(200, headers, registry.manifest_bytes + b" ")],
                               ["--pinned-key", str(pinned)])
            assert code == 2 and "REJECTED:" in output and "pinned publisher key" in output

            # --- update stage: legacy decodes the attacker body, hardened
            # rejects it before any decoder call (the divergence of this stage) ---
            decoder = decoder_available()
            with patch.object(kirimochi, "decode_brotli", wraps=kirimochi.decode_brotli) as spy:
                code, output = run(update_responses(registry, "attacker"),
                                   ["--policy", "legacy"], command="update")
                legacy_calls = spy.call_count
            if decoder:
                assert code == 0 and "Decision: DECODED" in output and "variant=attacker" in output
                assert legacy_calls == 1
            else:
                assert code == 3 and "no Brotli decoder" in output

            with patch.object(kirimochi, "decode_brotli", wraps=kirimochi.decode_brotli) as spy:
                code, output = run(update_responses(registry, "attacker"),
                                   ["--policy", "hardened", "--pinned-key", str(pinned)],
                                   command="update")
                hardened_calls = spy.call_count
            assert code == 2 and "REJECTED:" in output and "SIG_REJECTED" in output
            assert hardened_calls == 0, "the hardened policy must not reach the decoder"
            print("Divergence assertion (Pair B, kirimochi): same attacker body -> "
                  "legacy decode_calls=%d vs hardened decode_calls=0 (SIG_REJECTED)." % legacy_calls)

            # Positive control: the genuine signed body passes the hardened policy.
            if decoder:
                code, output = run(update_responses(registry, "genuine"),
                                   ["--policy", "hardened", "--pinned-key", str(pinned)],
                                   command="update")
                assert code == 0 and "Decision: DECODED" in output and "variant=genuine" in output

            # Negative control: the plain body succeeds in BOTH policies.
            for policy, extra in (("legacy", []), ("hardened", ["--pinned-key", str(pinned)])):
                code, output = run(update_responses(registry, "genuine", artifact="plain"),
                                   ["--policy", policy, "--artifact", "plain", *extra],
                                   command="update")
                assert code == 0 and "Decision: ACCEPTED" in output, output

            # Pair C: Content-Encoding: br is refused before the body is decoded.
            code, output = run(update_responses(registry, "genuine", encoding="br"),
                               ["--policy", "hardened", "--pinned-key", str(pinned)],
                               command="update")
            assert code == 2 and "ENCODING_REJECTED" in output and "REJECTED:" in output

            # Fail closed: hardened without a pinned key refuses to proceed.
            code, output = run(update_responses(registry, "attacker"),
                               ["--policy", "hardened"], command="update")
            assert code == 2 and "SIG_REJECTED" in output
    finally:
        registry.tmp.cleanup()
    print("Kirimochi local checks passed.")


def check_https(pyz=None):
    with tempfile.TemporaryDirectory(prefix="kirimochi-check-") as directory:
        work = Path(directory)
        scratch = work / "scratch"
        scratch.mkdir()
        env = os.environ.copy()
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            env.pop(name, None)
        env["TMPDIR"] = str(scratch)

        public = work / "public"
        server_script = ROOT / "server" / "mock_registry.py"
        missing_tls = subprocess.run([sys.executable, "-B", str(server_script)],
                                     env=env, capture_output=True, text=True, timeout=20)
        assert missing_tls.returncode == 2 and "--cert and --key are required" in missing_tls.stderr
        # One artifact-signing key, created before any request, shared by the
        # export and the running registry: the client pins its public half the
        # way a real build bakes the publisher key in.
        artifact_key = work / "artifact-signing.key.pem"
        openssl = shutil.which("openssl")
        subprocess.run([openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                        "-out", str(artifact_key)], check=True, capture_output=True, timeout=20)
        subprocess.run([sys.executable, "-B", str(server_script), "--export", str(public),
                        "--signing-key", str(artifact_key)],
                       env=env, check=True, capture_output=True, text=True, timeout=20)
        assert {p.name for p in public.iterdir()} == {
            "manifest.json", "manifest.sig.b64", "public_key.pem", "package.tar.gz",
            "update_feed.json", "update_body.br", "update_body.json",
            "update_body.attacker.br", "update_body.attacker.json"}
        assert not any(scratch.iterdir()), "registry signing key was not cleaned up"
        manifest = (public / "manifest.json").read_bytes()
        signature = (public / "manifest.sig.b64").read_text().strip()
        public_key = (public / "public_key.pem").read_bytes()
        metadata = json.loads(manifest)
        assert metadata["name"] == "demo-lib"
        assert metadata["tarball_sha256"] == hashlib.sha256((public / "package.tar.gz").read_bytes()).hexdigest()
        assert kirimochi.verify_with_openssl(manifest, signature, public_key)[0] is True

        # This CA and leaf are fresh test fixtures for a reserved hostname only.
        config = work / "tls.cnf"
        config.write_text("""[req]
distinguished_name=dn
[dn]
[root]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:registry.example
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
""")
        openssl = shutil.which("openssl")
        commands = [
            ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
             "-subj", "/CN=Kirimochi synthetic test CA", "-config", "tls.cnf", "-extensions", "root",
             "-keyout", "root.key", "-out", "root.pem"],
            ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=registry.example",
             "-config", "tls.cnf", "-keyout", "leaf.key", "-out", "leaf.csr"],
            ["x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key",
             "-set_serial", "2", "-days", "1", "-sha256", "-extfile", "tls.cnf",
             "-extensions", "leaf", "-out", "leaf.pem"],
        ]
        for command in commands:
            subprocess.run([openssl, *command], cwd=work, check=True, capture_output=True, timeout=20)

        if pyz is None:
            staging = work / "src"
            staging.mkdir()
            for name in ("__main__.py", "kirimochi.py"):
                shutil.copyfile(ROOT / "src" / name, staging / name)
            shutil.copyfile(ROOT.parents[1] / "LICENSE", staging / "LICENSE")
            pyz = work / "kirimochi.pyz"
            zipapp.create_archive(staging, target=pyz, interpreter="/usr/bin/env python3")
        pyz = Path(pyz).resolve()
        def launch(*extra):
            server = subprocess.Popen(
                [sys.executable, "-B", str(server_script), "--port", "0",
                 "--cert", str(work / "leaf.pem"), "--key", str(work / "leaf.key"),
                 "--signing-key", str(artifact_key), *extra],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ready = queue.Queue()
            threading.Thread(target=lambda: ready.put(server.stdout.readline()), daemon=True).start()
            line = ready.get(timeout=20).strip()
            assert line.startswith("Kirimochi mock registry running on https://127.0.0.1:"), line or server.stderr.read()
            return server, int(line.rsplit(":", 1)[1])

        def client(port, args, trust_root=True, hostname="registry.example"):
            client_env = env.copy()
            if trust_root:
                client_env["SSL_CERT_FILE"] = str(work / "root.pem")
            return subprocess.run(
                [sys.executable, "-B", str(pyz), *args,
                 "--url", "https://%s:%d" % (hostname, port),
                 "--connect", "127.0.0.1:%d" % port],
                env=client_env, capture_output=True, text=True, timeout=20)

        server, port = launch()
        try:
            cases = [("registry.example", False, 2, "REJECTED:"),
                     ("registry.example", True, 0, "OBSERVED:"),
                     ("wrong.example", True, 2, "REJECTED:")]
            for hostname, trust_root, expected_code, expected_output in cases:
                result = client(port, ["install", "demo-lib"], trust_root=trust_root, hostname=hostname)
                assert result.returncode == expected_code, result.stdout + result.stderr
                assert expected_output in result.stdout, result.stdout
                if hostname == "wrong.example":
                    assert "mismatch" in result.stdout.lower(), result.stdout
                print("HTTPS zipapp: %s, test root %s -> exit %d" %
                      (hostname, "set" if trust_root else "unset", result.returncode))

            # Update stage over real TLS, genuine registry: the legacy client
            # downloads and decompresses the body; the hardened client verifies
            # digest + pinned-key signature before it would decode anything.
            result = client(port, ["update", "demo-lib", "--policy", "legacy"])
            assert result.returncode == 0 and "Decision: DECODED" in result.stdout, result.stdout
            result = client(port, ["update", "demo-lib", "--policy", "hardened",
                                   "--pinned-key", str(public / "public_key.pem")])
            assert result.returncode == 0 and "Decision: DECODED" in result.stdout, result.stdout
            result = client(port, ["update", "demo-lib", "--policy", "hardened", "--artifact", "plain",
                                   "--pinned-key", str(public / "public_key.pem")])
            assert result.returncode == 0 and "Decision: ACCEPTED" in result.stdout, result.stdout
        finally:
            server.terminate()
            server.wait(timeout=5)

        # Poisoned registry: the attacker body is served where the signed body
        # is expected. The legacy client decodes it (the decoder path is
        # reached with attacker-supplied bytes); the hardened client refuses it
        # before any decoder call.
        server, port = launch("--poison-update")
        try:
            result = client(port, ["update", "demo-lib", "--policy", "legacy"])
            assert result.returncode == 0 and "variant=attacker" in result.stdout, result.stdout
            result = client(port, ["update", "demo-lib", "--policy", "hardened",
                                   "--pinned-key", str(public / "public_key.pem")])
            assert result.returncode == 2 and "REJECTED:" in result.stdout, result.stdout
            assert "SIG_REJECTED" in result.stdout, result.stdout
            result = client(port, ["update", "demo-lib", "--policy", "hardened"])
            assert result.returncode == 2 and "SIG_REJECTED" in result.stdout, result.stdout
            print("HTTPS zipapp update stage: legacy decodes the attacker body; "
                  "hardened -> exit 2 (SIG_REJECTED) without a decode.")
        finally:
            server.terminate()
            server.wait(timeout=5)
        print("Public export and HTTPS zipapp checks passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pyz", type=Path, help="test an existing zipapp instead of building one")
    args = parser.parse_args()
    check()
    check_https(args.pyz)
