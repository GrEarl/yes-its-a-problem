#!/usr/bin/env python3
"""Recover the 8 compromised eMudhra P-384 intermediate private keys.

The keys were generated with a broken procedure: the 384-bit private scalars
are actually tiny integers (< 256).  They are recovered by brute-force:
compute 1*G, 2*G, ... until the public point matches.

Usage:
    python3 recover_keys.py <cert.pem> [<cert.pem> ...]
Writes <name>.key.pem next to each input certificate.
"""
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def recover_key(cert):
    """Return the key matching the documented P-384 range; never print it."""
    public = cert.public_key()
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP384R1):
        raise ValueError("expected a P-384 certificate")
    target = public.public_numbers()
    for scalar in range(1, 256):
        key = ec.derive_private_key(scalar, ec.SECP384R1())
        if key.public_key().public_numbers() == target:
            return key
    raise ValueError("no matching key in the documented range")


def recover(cert_path):
    cert_path = Path(cert_path)
    key = recover_key(x509.load_pem_x509_certificate(cert_path.read_bytes()))
    out = cert_path.with_name(cert_path.name.removesuffix(".pem").removesuffix(".crt") + ".key.pem")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    print("recovered key ->", out)
    return out


if __name__ == "__main__":
    for f in sys.argv[1:]:
        recover(f)
