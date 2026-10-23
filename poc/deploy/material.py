"""Read-only validation of supplied TLS leaf material; never generates keys."""
import datetime as dt
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[2]
CHILD = "v.lab.yes-its-a-problem.iamwonderingif.com"
FORGED_NAMES = {label + "." + CHILD for label in ("login", "pay", "pkg")}


def safe_read(path, private=False):
    path = Path(path).expanduser().resolve(strict=True)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.getuid()):
        raise ValueError("input must be a regular file owned by this user or root: " + str(path))
    if st.st_mode & (0o077 if private else 0o022):
        raise ValueError("unsafe permissions (key: 0600; cert: not group/world writable): " + str(path))
    if st.st_size > 128 * 1024:
        raise ValueError("input file is unexpectedly large: " + str(path))
    for parent in path.parents:
        if parent.stat().st_mode & 0o022 and not parent.stat().st_mode & stat.S_ISVTX:
            raise ValueError("input has a writable parent directory: " + str(parent))
    return path.read_bytes()


def spki(value):
    key = value.public_key() if hasattr(value, "public_key") else value
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def validate_leaf(cert_path, key_path, kind, *, now=None, trust=True):
    """Return validated bytes and a public summary. Keys never enter the summary.

    ``trust=False`` is for synthetic unit tests only. Deployment always uses the
    default: system trust for the normal leaf, published lab issuers for forged.
    """
    cert_bytes, key_bytes = safe_read(cert_path), safe_read(key_path, private=True)
    if b"PRIVATE KEY" in cert_bytes:
        raise ValueError("fullchain must contain public certificates only")
    certs = x509.load_pem_x509_certificates(cert_bytes)
    if len(certs) < 2:
        raise ValueError("fullchain must contain a leaf followed by its intermediate")
    cert_bytes = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    leaf = certs[0]
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("CA certificates and CA private keys are forbidden deployment inputs")
    key = serialization.load_pem_private_key(key_bytes, password=None)
    if spki(leaf) != spki(key):
        raise ValueError("leaf certificate and private key do not match")
    published = json.loads((ROOT / "artifacts/impacted-intermediates.json").read_text())
    ca_certs = certs[1:] + [x509.load_pem_x509_certificate(item["pem"].encode()) for item in published]
    if any(spki(key) == spki(ca) for ca in ca_certs):
        raise ValueError("leaf input reuses a CA private key; refusing transfer")
    # The PEM loader may ignore trailing blocks. Transfer only the parsed leaf
    # key, never the original file (which might concatenate another private key).
    key_bytes = key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = set(sans.get_values_for_type(x509.DNSName))
    if len(sans) != len(names):
        raise ValueError("only unique DNS SANs are accepted")
    allowed = {"*." + CHILD, CHILD} if kind == "normal" else FORGED_NAMES
    required = {"*." + CHILD} if kind == "normal" else FORGED_NAMES
    if not required <= names or not names <= allowed:
        raise ValueError("SANs must match the owned lab names for " + kind)
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise ValueError("leaf is not valid for TLS server authentication")
    except x509.ExtensionNotFound:
        pass
    now = now or dt.datetime.now(dt.timezone.utc)
    for cert in certs:
        # cryptography 41 (Ubuntu 24.04) predates the timezone-aware properties.
        before = getattr(cert, "not_valid_before_utc", None)
        after = getattr(cert, "not_valid_after_utc", None)
        before = before or cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        after = after or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
        if not before <= now < after:
            raise ValueError("certificate chain contains an expired or not-yet-valid certificate")
    for child, issuer in zip(certs, certs[1:]):
        child.verify_directly_issued_by(issuer)
    if trust and kind == "normal":
        with tempfile.TemporaryDirectory(prefix="yip-cert-check-") as directory:
            leaf_file, chain_file = Path(directory) / "leaf.pem", Path(directory) / "chain.pem"
            leaf_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            chain_file.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs[1:]))
            result = subprocess.run(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname",
                                     "probe." + CHILD, "-untrusted", str(chain_file), str(leaf_file)],
                                    capture_output=True, text=True)
            if result.returncode:
                raise ValueError("normal chain failed system trust verification: " + result.stderr.strip())
    if trust and kind == "forged":
        issuers = [x509.load_pem_x509_certificate(item["pem"].encode()) for item in published]
        if not any(spki(certs[1]) == spki(issuer) and certs[1].subject == issuer.subject for issuer in issuers):
            raise ValueError("forged leaf issuer is not a published lab intermediate")
    expiry = getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after.replace(tzinfo=dt.timezone.utc)
    return cert_bytes, key_bytes, {"kind": kind, "sans": sorted(names),
                                  "expires": expiry.isoformat(),
                                  "days_left": (expiry - now).days,
                                  "leaf_sha256": leaf.fingerprint(hashes.SHA256()).hex()}
