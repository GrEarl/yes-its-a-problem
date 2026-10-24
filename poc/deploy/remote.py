"""Root helper sent over SSH by deploy.py. Reads one JSON request on stdin.

No archive extraction, repository copy, shell interpolation, or key generation.
Only the fixed public file allowlist and validated leaf inputs are accepted.
"""
import base64
import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

APP = Path("/opt/yip")
ETC = Path("/etc/yip")
STATE = Path("/var/lib/yip")
CHALLENGE_NAME = "_acme-challenge.v.lab.yes-its-a-problem.iamwonderingif.com"
PUBLIC_FILES = (
    "LICENSE",
    "poc/lab/dns/lab_dns.py", "poc/lab/http/lab_http.py",
    "artifacts/impacted-intermediates.json",
    "poc/vendor/dnslib/__init__.py", "poc/vendor/dnslib/bimap.py",
    "poc/vendor/dnslib/bit.py", "poc/vendor/dnslib/buffer.py",
    "poc/vendor/dnslib/dns.py", "poc/vendor/dnslib/label.py",
    "poc/vendor/dnslib/lex.py", "poc/vendor/dnslib/ranges.py",
    "poc/vendor/dnslib/server.py", "poc/vendor/dnslib-0.9.26.dist-info/LICENSE",
    "poc/deploy/public-registry/manifest.json", "poc/deploy/public-registry/manifest.sig.b64",
    "poc/deploy/public-registry/public_key.pem", "poc/deploy/public-registry/package.tar.gz",
)
CERT_FILES = {"normal-fullchain.pem", "normal-key.pem", "forged-fullchain.pem", "forged-key.pem"}


def run(*args):
    subprocess.run(args, check=True)


def decode_files(files, allowed):
    if not isinstance(files, dict) or not set(files) <= set(allowed):
        raise ValueError("payload contains a file outside the transfer allowlist")
    decoded = {}
    for name, data in files.items():
        decoded[name] = base64.b64decode(data, validate=True)
        if len(decoded[name]) > 2_000_000:
            raise ValueError("oversized input")
    return decoded


def atomic_write(path, data, mode=0o640, gid=0):
    """Replace only changed content; a reader sees either complete version."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("refusing an unexpected destination symlink: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_bytes() != data:
        fd, temporary = tempfile.mkstemp(prefix=".yip-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temporary, mode)
            os.chown(temporary, 0, gid)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    os.chmod(path, mode)
    os.chown(path, 0, gid)


def check_platform():
    release = dict(line.rstrip().split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                   if "=" in line)
    if release.get("ID", "").strip('"') != "ubuntu" or release.get("VERSION_ID", "").strip('"') != "24.04":
        raise ValueError("this installer supports fresh Ubuntu 24.04 LTS hosts")


def prepare():
    check_platform()
    run("apt-get", "update", "-qq")
    run("apt-get", "install", "-y", "--no-install-recommends", "python3", "python3-cryptography", "openssl")
    try:
        pwd.getpwnam("yip")
    except KeyError:
        run("useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--no-create-home",
            "--shell", "/usr/sbin/nologin", "yip")
    gid = grp.getgrnam("yip").gr_gid
    for directory in (APP, ETC, STATE):
        if directory.is_symlink():
            raise ValueError("refusing managed-directory symlink: " + str(directory))
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o750)
        os.chown(directory, 0, gid)
    if not (STATE / "challenges.json").exists():
        atomic_write(STATE / "challenges.json", b"{}\n", gid=gid)
    return gid


def validate_pair(cert_bytes, key_bytes):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    certs = x509.load_pem_x509_certificates(cert_bytes)
    if len(certs) < 2 or b"PRIVATE KEY" in cert_bytes:
        raise ValueError("expected a public fullchain")
    if certs[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("refusing CA private-key input")
    key = serialization.load_pem_private_key(key_bytes, password=None)
    def public(k):
        return k.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    if public(certs[0]) != public(key):
        raise ValueError("certificate/key mismatch")
    if any(public(key) == public(ca) for ca in certs[1:]):
        raise ValueError("leaf input reuses a CA private key")
    for child, issuer in zip(certs, certs[1:]):
        child.verify_directly_issued_by(issuer)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())


def install_certs(files, role, gid):
    if role not in ("fake", "true"):
        raise ValueError("provider must not receive leaf private keys")
    allowed = CERT_FILES if role == "fake" else {"normal-fullchain.pem", "normal-key.pem"}
    certs = decode_files(files, allowed)
    current = ETC / "current"
    # Renewals replace the normal leaf only; keep the previously supplied fake leaf.
    if role == "fake" and "forged-fullchain.pem" not in certs and current.is_symlink():
        for name in ("forged-fullchain.pem", "forged-key.pem"):
            certs[name] = (current / name).read_bytes()
    if set(certs) != allowed:
        raise ValueError("incomplete leaf certificate pairs")
    for kind in (("normal", "forged") if role == "fake" else ("normal",)):
        certs[kind + "-key.pem"] = validate_pair(certs[kind + "-fullchain.pem"], certs[kind + "-key.pem"])
    digest = hashlib.sha256(b"".join(name.encode() + certs[name] for name in sorted(certs))).hexdigest()[:24]
    version = ETC / ("certs-" + digest)
    if version.is_symlink():
        raise ValueError("refusing certificate-directory symlink")
    version.mkdir(exist_ok=True, mode=0o750)
    os.chown(version, 0, gid)
    for name, data in certs.items():
        atomic_write(version / name, data, gid=gid)
    previous = current.resolve() if current.is_symlink() else None
    if current.exists() and not current.is_symlink():
        raise ValueError("/etc/yip/current must be the managed certificate symlink")
    link = ETC / ".current-new"
    link.unlink(missing_ok=True)
    link.symlink_to(version.name)
    os.replace(link, current)
    return previous, version


def challenge(values, gid):
    if not isinstance(values, dict) or not set(values) <= {CHALLENGE_NAME}:
        raise ValueError("unexpected DNS challenge name")
    for tokens in values.values():
        if not isinstance(tokens, list) or len(tokens) > 4 or any(
                not isinstance(t, str) or not 1 <= len(t) <= 256 or
                any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in t)
                for t in tokens):
            raise ValueError("invalid DNS challenge value")
    atomic_write(STATE / "challenges.json", (json.dumps(values, sort_keys=True) + "\n").encode(), gid=gid)


def main():
    if os.geteuid() != 0:
        raise ValueError("use root or passwordless sudo for this installer")
    request = json.load(sys.stdin)
    action, role = request["action"], request["role"]
    if role not in ("provider", "fake", "true"):
        raise ValueError("invalid role")
    if action == "install":
        # Validate all names before package installation or filesystem changes.
        files = decode_files(request["files"], PUBLIC_FILES)
        units = request["units"]
        if not set(units) <= {"yip-dns.service", "yip-http.service"}:
            raise ValueError("unexpected service name")
        gid = prepare()
        for name, data in files.items():
            atomic_write(APP / name, data, mode=0o644, gid=gid)
        previous = version = None
        if request.get("certs"):
            previous, version = install_certs(request["certs"], role, gid)
        for name, text in units.items():
            atomic_write(Path("/etc/systemd/system") / name, text.encode(), mode=0o644)
        run("systemctl", "daemon-reload")
        for name in units:
            run("systemctl", "enable", name)
            run("systemctl", "restart", name)
            run("systemctl", "is-active", "--quiet", name)
    elif action == "challenge":
        challenge(request["values"], grp.getgrnam("yip").gr_gid)
    elif action == "certs":
        previous, version = install_certs(request["certs"], role, grp.getgrnam("yip").gr_gid)
        if previous != version:
            try:
                run("systemctl", "restart", "yip-http.service")
                run("systemctl", "is-active", "--quiet", "yip-http.service")
            except subprocess.CalledProcessError:
                if previous:
                    rollback = ETC / ".rollback"
                    rollback.unlink(missing_ok=True)
                    rollback.symlink_to(previous.name)
                    os.replace(rollback, ETC / "current")
                    run("systemctl", "restart", "yip-http.service")
                raise
    else:
        raise ValueError("unknown action")
    print(json.dumps({"ok": True, "action": action, "role": role}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("remote operation failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
