#!/usr/bin/env python3
"""Check the recovered eMudhra intermediates and the two demo chains.

Reads only public artifacts and secrets/ (private keys). Writes nothing.
"""
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

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


def verify_signature(child, issuer):
    alg = child.signature_hash_algorithm
    pub = issuer.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), alg)
    else:
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(alg))


def sha256(cert):
    return cert.fingerprint(hashes.SHA256()).hex().upper()


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
                    verify_signature(cert, root)
                except Exception as exc:
                    failures.append("bad issuer signature: %s / %s: %s" %
                                    (name, entry["issuer"], exc))
        print("  %-22s %d cert(s), key %s" %
              (name, len(variants), "OK" if key_path.exists() else "MISSING"))

    for label in ("demo-cert", "demo-cert-emsign"):
        d = DEMO / label
        try:
            if (d / "leaf.crt.pem").exists():
                leaf = x509.load_pem_x509_certificate((d / "leaf.crt.pem").read_bytes())
                inter = x509.load_pem_x509_certificate((d / "intermediate.pem").read_bytes())
                root = x509.load_pem_x509_certificate((d / "root.pem").read_bytes())
            else:
                pem = (d / "fullchain.pem").read_text()
                certs = [x509.load_pem_x509_certificate(
                    (block + "-----END CERTIFICATE-----\n").encode())
                    for block in pem.split("-----END CERTIFICATE-----") if block.strip()]
                leaf, inter, root = certs[0], certs[1], certs[-1]
            if leaf.issuer != inter.subject or inter.issuer != root.subject:
                raise ValueError("subject/issuer mismatch")
            verify_signature(leaf, inter)
            verify_signature(inter, root)
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
