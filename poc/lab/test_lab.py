#!/usr/bin/env python3
"""Regression checks for served-chain labels, SNI routing and DNS transport.

Run: python3 poc/lab/test_lab.py
Only temporary files and loopback sockets are used. No system trust is changed.
All TLS keys and CAs are synthetic. No real CA recovery or signing code is run.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
from http.client import HTTPResponse
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "poc/vendor"))
from dnslib import DNSRecord, RCODE
from dnslib.server import DNSServer, DNSLogger


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


http = load("lab_http", "poc/lab/http/lab_http.py")
dns = load("lab_dns", "poc/lab/dns/lab_dns.py")
material = load("check_material", "poc/lab/certs/check_material.py")
DOMAIN = "v.lab.example.test"


def test_certificate(name, key, issuer=None, issuer_key=None, *, ca=False, sans=()):
    """Issue a short-lived certificate using only freshly generated test keys."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    signer = issuer_key or key
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False))
    if not ca:
        builder = (builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
    return builder.sign(signer, hashes.SHA256())


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="yip-regression-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.dir = Path(cls.tmp.name)
        root_key = ec.generate_private_key(ec.SECP256R1())
        cls.root_ca = test_certificate("temporary test root", root_key, ca=True)
        cls.known_key = ec.generate_private_key(ec.SECP256R1())
        cls.known_ca = test_certificate("temporary known issuer", cls.known_key,
                                        cls.root_ca, root_key, ca=True)
        cls.control_key = ec.generate_private_key(ec.SECP256R1())
        cls.control_ca = test_certificate("temporary control issuer", cls.control_key,
                                          cls.root_ca, root_key, ca=True)
        (cls.dir / "roots.pem").write_bytes(cls.root_ca.public_bytes(serialization.Encoding.PEM))
        metadata = cls.dir / "known-issuers.json"
        metadata.write_text(json.dumps([{"pem": cls.known_ca.public_bytes(serialization.Encoding.PEM).decode()}]))
        # This mock is test-only; the server's metadata path is fixed in production.
        metadata_patch = patch.object(http, "CA_METADATA", metadata)
        metadata_patch.start()
        cls.addClassCleanup(metadata_patch.stop)
        cls.control = cls.write_leaf("control", cls.control_ca, cls.control_key, ["*." + DOMAIN])
        cls.forged = cls.write_leaf("forged", cls.known_ca, cls.known_key,
                                    [name + "." + DOMAIN for name in ("login", "pay", "pkg")])

    @classmethod
    def write_leaf(cls, name, issuer, issuer_key, sans):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = test_certificate(name, key, issuer, issuer_key, sans=sans)
        chain, private = cls.dir / (name + ".pem"), cls.dir / (name + ".key.pem")
        chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + issuer.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        return str(chain), str(private)

    def configure(self, mixed=False, assertion=False):
        cert, key = self.control if mixed else self.forged
        http.ARGS = argparse.Namespace(cert=cert, key=key,
            forged_cert=self.forged[0] if mixed else None,
            forged_key=self.forged[1] if mixed else None,
            forged_sni=",".join(name + "." + DOMAIN for name in ("login", "pay", "pkg")),
            cert_is_forged=assertion, role="fake", log=None)
        return http.build_tls_context()

    def request(self, context, hostname, trust=None, path="/tls-probe", method="GET"):
        server = http.ThreadingHTTPServer(("127.0.0.1", 0), http.Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            if trust is None:
                trust = ssl.create_default_context(cafile=str(self.dir / "roots.pem"))
            with socket.create_connection(server.server_address, timeout=3) as raw:
                with trust.wrap_socket(raw, server_hostname=hostname) as tls:
                    peer_sha256 = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    tls.sendall((method + " " + path + " HTTP/1.1\r\nHost: " + hostname +
                                 "\r\nConnection: close\r\n\r\n").encode())
                    response = HTTPResponse(tls, method=method)
                    response.begin()
                    if path != "/tls-probe":
                        return response.status, dict(response.getheaders()), response.read()
                    self.assertEqual(response.status, 200)
                    result = json.loads(response.read())
                    self.assertEqual(result["leaf_sha256"], peer_sha256)
                    return result
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_forged_base_chain_is_detected_without_a_flag(self):
        result = self.request(self.configure(), "login." + DOMAIN)
        self.assertEqual(result["tls"], "forged")
        expected = hashlib.sha256(self.known_ca.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self.assertEqual(result["issuer_spki_sha256"], expected)

    def test_sni_selects_the_actual_chain_for_all_demo_hosts(self):
        context = self.configure(mixed=True)
        for name in ("login", "pay", "pkg"):
            with self.subTest(name=name):
                self.assertEqual(self.request(context, name + "." + DOMAIN)["tls"], "forged")
        self.assertEqual(self.request(context, "random-probe." + DOMAIN)["tls"], "other")

    def test_claiming_a_control_chain_is_forged_is_rejected(self):
        self.configure(mixed=True)
        http.ARGS.cert_is_forged = True
        with self.assertRaisesRegex(ValueError, "does not match"):
            http.build_tls_context()

    def test_omitting_issuer_preserves_the_leaf_classification(self):
        cert = x509.load_pem_x509_certificates(Path(self.forged[0]).read_bytes())[0]
        path = self.dir / "omitted-issuer.pem"
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(http.certificate_info(path), http.certificate_info(self.forged[0]))
        self.configure()
        trust = ssl.create_default_context(cafile=str(self.dir / "roots.pem"))
        trust.load_verify_locations(cadata=self.known_ca.public_bytes(serialization.Encoding.PEM).decode())
        result = self.request(http.make_context(path, self.forged[1]), "login." + DOMAIN, trust)
        self.assertEqual(result["tls"], "forged")

    def test_issuer_name_and_appended_ca_are_not_signature_evidence(self):
        cert = test_certificate("wrong signer", self.control_key, self.known_ca, self.control_key,
                                sans=["login." + DOMAIN])
        path = self.dir / "wrong-signer.pem"
        pem = cert.public_bytes(serialization.Encoding.PEM)
        path.write_bytes(pem)
        self.assertEqual(http.certificate_info(path)["tls"], "other")
        path.write_bytes(pem + self.known_ca.public_bytes(serialization.Encoding.PEM))
        with self.assertRaisesRegex(ValueError, "invalid signature"):
            http.certificate_info(path)
        path.write_bytes(Path(self.forged[0]).read_bytes() + self.control_ca.public_bytes(serialization.Encoding.PEM))
        with self.assertRaises(ValueError):
            http.certificate_info(path)

    def test_material_check_reads_the_served_fullchain(self):
        directory = self.dir / "material"
        directory.mkdir()
        chain = Path(self.forged[0]).read_bytes()
        certs = x509.load_pem_x509_certificates(chain)
        root = self.root_ca.public_bytes(serialization.Encoding.PEM)
        root_path = directory / "root.pem"
        root_path.write_bytes(root)
        roots = {"test root": self.root_ca}
        # Valid split files must not hide a broken fullchain.pem.
        (directory / "leaf.crt.pem").write_bytes(certs[0].public_bytes(serialization.Encoding.PEM))
        (directory / "intermediate.pem").write_bytes(certs[1].public_bytes(serialization.Encoding.PEM))
        path = directory / "fullchain.pem"
        path.write_bytes(chain)
        self.assertEqual(material.verify_demo_chain(directory, {}), certs[0])
        root_path.unlink()
        path.write_bytes(chain + root)
        self.assertEqual(material.verify_demo_chain(directory, {}), certs[0])
        path.write_bytes(chain)
        self.assertEqual(material.verify_demo_chain(directory, roots), certs[0])
        with self.assertRaisesRegex(ValueError, "no root.pem or known issuer"):
            material.verify_demo_chain(directory, {})
        root_path.write_bytes(root)
        for broken in (b"", certs[0].public_bytes(serialization.Encoding.PEM),
                       certs[0].public_bytes(serialization.Encoding.PEM) + self.control_ca.public_bytes(serialization.Encoding.PEM)):
            with self.subTest(length=len(broken)):
                path.write_bytes(broken)
                with self.assertRaises((ValueError, InvalidSignature)):
                    material.verify_demo_chain(directory, roots)

    def test_tls_rejects_wrong_hostname_and_untrusted_issuer(self):
        context = self.configure()
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request(context, "wrong-host." + DOMAIN)
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request(context, "login." + DOMAIN, ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))

    def test_registry_public_routes_and_missing_fixture(self):
        directory = self.dir / "registry"
        subprocess.run([sys.executable, str(ROOT / "demo/fake-pkg/server/mock_registry.py"),
                        "--export", str(directory)], check=True, capture_output=True)
        filenames = ("manifest.json", "manifest.sig.b64", "public_key.pem", "package.tar.gz")
        self.assertEqual({p.name for p in directory.iterdir()}, set(filenames))
        context = self.configure(mixed=True)
        responses = {}
        with patch.object(http, "REGISTRY", http.load_registry(directory)):
            for path, ctype in http.REGISTRY_TYPES.items():
                status, headers, body = self.request(context, "pkg." + DOMAIN, path=path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], ctype)
                self.assertEqual(body, (directory / path[1:]).read_bytes())
                responses[path] = headers, body
            headers, manifest = responses["/manifest.json"]
            public = serialization.load_pem_public_key(responses["/public_key.pem"][1])
            public.verify(base64.b64decode(headers["X-Kirimochi-Signature"], validate=True),
                          manifest, ec.ECDSA(hashes.SHA256()))
            self.assertEqual(json.loads(manifest)["tarball_sha256"],
                             hashlib.sha256(responses["/package.tar.gz"][1]).hexdigest())
            status, headers, body = self.request(context, "pkg." + DOMAIN, path="/manifest.json", method="HEAD")
            self.assertEqual((status, body), (200, b""))
            self.assertEqual(int(headers["Content-Length"]), len(manifest))
            for path in ("/manifest.sig.b64", "/../public_key.pem"):
                self.assertEqual(self.request(context, "pkg." + DOMAIN, path=path)[0], 404)
        for path in http.REGISTRY_TYPES:
            self.assertEqual(self.request(context, "pkg." + DOMAIN, path=path)[0], 503)
        for name in filenames:
            with self.subTest(missing=name):
                path = directory / name
                saved = path.read_bytes()
                path.unlink()
                with self.assertRaises(OSError):
                    http.load_registry(directory)
                path.write_bytes(saved)
        for name, broken in (("manifest.sig.b64", b"invalid\r\nheader"),
                             ("manifest.sig.b64", b""), ("manifest.json", b""), ("public_key.pem", b"")):
            with self.subTest(invalid=name, empty=not broken):
                path = directory / name
                saved = path.read_bytes()
                path.write_bytes(broken)
                with self.assertRaises(ValueError):
                    http.load_registry(directory)
                path.write_bytes(saved)

    def test_dns_udp_tcp_referral_and_scope(self):
        cfg = {"zone": "lab.example.test", "child": "v", "provider_ns": "ns.example.test",
               "true_ip": "192.0.2.10", "fake_ip": "198.51.100.66", "ttl": 0}
        resolver = dns.LabResolver(cfg, "provider")
        servers = []
        try:
            logger = DNSLogger(log="-request,-reply,-truncated,-error")
            tcp = DNSServer(resolver, address="127.0.0.1", port=0, tcp=True, logger=logger)
            port = tcp.server.server_address[1]
            servers = [tcp, DNSServer(resolver, address="127.0.0.1", port=port, logger=logger)]
            for server in servers:
                server.start_thread()
            for use_tcp in (False, True):
                query = DNSRecord.question("test.v.lab.example.test")
                query.header.ad = 1
                result = DNSRecord.parse(query.send("127.0.0.1", port, tcp=use_tcp, timeout=3))
                self.assertEqual(result.header.rcode, RCODE.NOERROR)
                self.assertEqual((result.header.ra, result.header.ad, result.header.aa), (0, 0, 0))
                self.assertEqual(str(result.ar[0].rdata), cfg["fake_ip"])
                refused = DNSRecord.parse(DNSRecord.question("unrelated.example").send(
                    "127.0.0.1", port, tcp=use_tcp, timeout=3))
                self.assertEqual(refused.header.rcode, RCODE.REFUSED)
                self.assertEqual(refused.header.aa, 0)
        finally:
            for server in servers:
                server.stop()
                server.server.server_close()


if __name__ == "__main__":
    unittest.main()
