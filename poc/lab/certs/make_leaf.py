#!/usr/bin/env python3
"""Build a lab leaf certificate signed by the recovered eMudhra CA key.

The private key is written outside the repository (secrets/ by default) with
owner-only permissions.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parent.parent.parent

DEFAULT_SANS = [
    "login.v.lab.yes-its-a-problem.iamwonderingif.com",
    "pay.v.lab.yes-its-a-problem.iamwonderingif.com",
    "pkg.v.lab.yes-its-a-problem.iamwonderingif.com",
]


def load_root_cert(path, name):
    with open(path, encoding="utf-8") as f:
        roots = json.load(f)
    for item in roots:
        if item.get("name") == name and item.get("pem"):
            return x509.load_pem_x509_certificate(item["pem"].encode("ascii"))
    raise SystemExit("root not found: %s" % name)


def recover_ca_key(cert_path, key_path):
    """Recover the tiny P-384 scalar from the public CA certificate."""
    recover = WORKSPACE / "poc/lab/certs/recover_keys.py"
    if not recover.exists():
        raise SystemExit("CA key missing and recovery script not found: %s" % recover)
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory() as td:
        tmp_cert = Path(td) / "ca.crt.pem"
        shutil.copyfile(cert_path, tmp_cert)
        subprocess.run([sys.executable, str(recover), str(tmp_cert)], check=True)
        tmp_key = tmp_cert.with_name("ca.key.pem")
        if not tmp_key.exists():
            raise SystemExit("recovery did not write %s" % tmp_key)
        data = tmp_key.read_bytes()
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    print("recovered CA key ->", key_path)


def build_leaf(ca_cert, leaf_key, sans, days):
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab leaf")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--san", action="append", help="DNS SAN; repeatable")
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--ca-cert", default=str(WORKSPACE / "poc/lab/certs/EM-DV-TLS-CA-G3B.aaa.crt.pem"))
    ap.add_argument("--ca-key", default=str(WORKSPACE / "secrets/artifacts/keys/EM-DV-TLS-CA-G3B.key.pem"))
    ap.add_argument("--roots", default=str(WORKSPACE / "artifacts/roots.json"))
    ap.add_argument("--root-name", default="AAA Certificate Services")
    ap.add_argument("--out", default=str(WORKSPACE / "secrets/demo-cert"))
    a = ap.parse_args()

    ca_cert = x509.load_pem_x509_certificate(Path(a.ca_cert).read_bytes())
    key_path = Path(a.ca_key)
    if not key_path.exists():
        recover_ca_key(Path(a.ca_cert), key_path)
    ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    root = load_root_cert(a.roots, a.root_name)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = build_leaf(ca_cert, leaf_key, a.san or DEFAULT_SANS, a.days)
    leaf = builder.sign(private_key=ca_key, algorithm=hashes.SHA384())

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    (out / "leaf.key.pem").write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    os.chmod(out / "leaf.key.pem", 0o600)
    (out / "leaf.crt.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (out / "intermediate.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (out / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (out / "fullchain.pem").write_bytes(
        leaf.public_bytes(serialization.Encoding.PEM) +
        ca_cert.public_bytes(serialization.Encoding.PEM))
    print("wrote", out)
    print("serial:", f"{leaf.serial_number:x}")
    print("sha256:", hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest())


if __name__ == "__main__":
    main()
