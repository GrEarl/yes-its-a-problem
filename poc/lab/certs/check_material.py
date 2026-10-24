#!/usr/bin/env python3
"""Check the recovered eMudhra intermediates and the two demo chains.

Reads only public artifacts and secrets/ (private keys). Writes nothing.
"""
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
ARTIFACTS = ROOT / "artifacts"
KEYS = ROOT / "secrets" / "artifacts" / "keys"
DEMO = ROOT / "secrets"


def public_der(key_or_cert):
    if hasattr(key_or_cert, "public_key"):
        key = key_or_cert.public_key()
    else:
        key = key_or_cert
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def sha256(cert):
    return cert.fingerprint(hashes.SHA256()).hex().upper()


def verify_demo_chain(directory, roots):
    """Verify the fullchain file supplied to the server, against its lab root."""
    certs = x509.load_pem_x509_certificates((directory / "fullchain.pem").read_bytes())
    if len(certs) < 2:
        raise ValueError("fullchain.pem must contain a leaf and intermediate")
    root_path = directory / "root.pem"
    if root_path.is_file():
        root = x509.load_pem_x509_certificate(root_path.read_bytes())
    elif certs[-1].subject == certs[-1].issuer:
        # Some demo chains include their self-signed root in fullchain.pem.
        root = certs[-1]
    else:
        root = next((candidate for candidate in roots.values()
                     if certs[-1].issuer == candidate.subject), None)
        if root is None:
            raise ValueError("fullchain.pem has no root.pem or known issuer for its final certificate")
    for child, issuer in zip(certs, certs[1:] + [root]):
        child.verify_directly_issued_by(issuer)
    return certs[0]


def main():
    entries = json.loads((ARTIFACTS / "impacted-intermediates.json").read_text())
    roots = {r["subject"]: x509.load_pem_x509_certificate(r["pem"].encode())
             for r in json.loads((ARTIFACTS / "roots.json").read_text())}
    by_name = {}
    for entry in entries:
        by_name.setdefault(entry["name"], []).append(entry)

    failures = []
    print("public intermediate entries: %d" % len(entries))
    print("unique intermediates: %d" % len(by_name))
    for name in sorted(by_name):
        variants = by_name[name]
        key_path = KEYS / (name.replace(" - ", "-").replace(" ", "-") + ".key.pem")
        if not key_path.exists():
            failures.append("missing key: %s" % key_path)
            continue
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        for entry in variants:
            cert = x509.load_pem_x509_certificate(entry["pem"].encode())
            if public_der(cert) != public_der(key):
                failures.append("key mismatch: %s / %s" % (name, entry["issuer"]))
            root = roots.get(entry["issuer"])
            if root is None:
                failures.append("missing root: %s" % entry["issuer"])
            else:
                try:
                    cert.verify_directly_issued_by(root)
                except Exception as exc:
                    failures.append("bad issuer signature: %s / %s: %s" %
                                    (name, entry["issuer"], exc))
        print("  %-22s %d cert(s) checked" % (name, len(variants)))

    for label in ("demo-cert", "demo-cert-emsign"):
        d = DEMO / label
        try:
            leaf = verify_demo_chain(d, roots)
        except Exception as exc:
            failures.append("%s: %s" % (label, exc))
            print("  %-22s FAILED: %s" % (label, exc))
        else:
            print("  %-22s chain OK (%s)" % (label, sha256(leaf)[:16]))

    if failures:
        print("\nFAIL")
        for failure in failures:
            print(" -", failure)
        return 1
    print("\nOK: %d public certs, %d recovered keys, 2 demo chains" %
          (len(entries), len(by_name)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
