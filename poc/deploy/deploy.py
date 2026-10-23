#!/usr/bin/env python3
"""Small, explicit controller for three owned Ubuntu VPSs.

preflight and plan are offline. apply, ssh-check, acme, renew and the internal
hook command make network connections. No command changes Cloudflare or GitHub.
"""
import argparse
import base64
import fcntl
import ipaddress
import json
import os
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "poc/vendor"))
from dnslib import DNSRecord, QTYPE, RCODE
from material import CHILD, FORGED_NAMES, validate_leaf
from remote import PUBLIC_FILES

SITE = "yes-its-a-problem.iamwonderingif.com"
LAB = "lab." + SITE
PROVIDER_NS = "ns1." + SITE
CHILD_NS = "ns-child." + SITE
ROLES = ("provider", "fake", "true")
SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]
ACME_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
ACME_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


def load_config(path):
    cfg = json.loads(Path(path).read_text())
    expected = {"hosts", "child_ns", "acme_email", "state_dir", "forged_fullchain", "forged_key"}
    if set(cfg) != expected or set(cfg["hosts"]) != set(ROLES):
        raise ValueError("config keys must match config.example.json")
    seen_ip, seen_ssh = set(), set()
    for role, host in cfg["hosts"].items():
        if set(host) != {"ipv4", "ssh"}:
            raise ValueError("each host requires ipv4 and ssh fields")
        if host["ipv4"] is not None:
            ip = ipaddress.IPv4Address(host["ipv4"])
            if not ip.is_global or ip.is_multicast or ip.is_reserved or str(ip) in seen_ip:
                raise ValueError("use three distinct public IPv4 unicast addresses")
            seen_ip.add(str(ip))
        if host["ssh"] is not None:
            if not isinstance(host["ssh"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", host["ssh"]):
                raise ValueError("ssh must be a plain SSH config alias, without user@ or options")
            if host["ssh"] in seen_ssh:
                raise ValueError("one separate VPS and distinct SSH alias are required per role")
            seen_ssh.add(host["ssh"])
    errors = child_ns_errors(cfg)
    if errors:
        raise ValueError(errors[0])
    email = cfg["acme_email"]
    if email is not None and (not isinstance(email, str) or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)):
        raise ValueError("invalid ACME contact email")
    for field in ("state_dir", "forged_fullchain", "forged_key"):
        if cfg[field] is not None and (not isinstance(cfg[field], str) or not Path(cfg[field]).is_absolute()):
            raise ValueError(field + " must be an absolute local path or null")
    if bool(cfg["forged_fullchain"]) != bool(cfg["forged_key"]):
        raise ValueError("forged_fullchain and forged_key must be supplied together")
    private_state(cfg)
    return cfg


def state_dir(cfg):
    return Path(cfg["state_dir"] or ROOT / "secrets/deploy-state")


def private_state(cfg, create=False):
    path = state_dir(cfg)
    resolved = path.resolve()
    secrets = ROOT / "secrets"
    for candidate in (path.absolute(), resolved):
        if (candidate == ROOT or ROOT in candidate.parents) and secrets not in candidate.parents:
            raise ValueError("state_dir inside the repository must be beneath ignored secrets/")
    if path.is_symlink():
        raise ValueError("state_dir must not be a symlink")
    in_secrets = secrets in resolved.parents
    if not in_secrets and not path.exists():
        raise ValueError("external state_dir must already exist with owner-only access (0700)")
    if path.exists():
        info = path.stat()
        if not path.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("state_dir must be owned by this user with mode 0700")
    for parent in resolved.parents:
        if parent.exists() and parent.stat().st_mode & 0o022 and not parent.stat().st_mode & stat.S_ISVTX:
            raise ValueError("state_dir has a writable parent directory: " + str(parent))
    if create:
        previous = os.umask(0o077)
        try:
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        finally:
            os.umask(previous)
    return path


def normal_paths(cfg):
    live = state_dir(cfg) / "acme/live/yip-normal"
    return live / "fullchain.pem", live / "privkey.pem"


def dns_contract():
    """Require the reviewed contract; never silently substitute the older fixture."""
    source = (ROOT / "poc/lab/dns/lab_dns.py").read_text()
    return '"--child-ns"' in source or "'--child-ns'" in source


LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"


def in_zone(name, zone):
    return name == zone or name.endswith("." + zone)


def child_ns_name(cfg):
    """The configured external child-NS name, normalized like the DNS lab."""
    return str(cfg["child_ns"]["name"]).strip().rstrip(".").lower()


def child_ns_addresses(cfg):
    """(true_ip, fake_ip) of the child-NS contract; None means unassigned."""
    return cfg["child_ns"]["true_ip"], cfg["child_ns"]["fake_ip"]


def child_ns_errors(cfg):
    """Validate the external child-NS block; also used for the preflight rows.

    The deployment topology delegates the child zone to an NS name OUTSIDE the
    provider zone: an ordinary record inside the managed parent zone.  Its
    parent-side A record points at the true VPS; the lab referral contradicts it
    with an ADDITIONAL A at the fake VPS, which is fixture data only.
    """
    block = cfg.get("child_ns")
    if not isinstance(block, dict) or set(block) != {"name", "true_ip", "fake_ip"}:
        return ["child_ns requires exactly the name, true_ip and fake_ip fields"]
    if not isinstance(block.get("name"), str) or not re.fullmatch(
            LABEL + r"(?:\." + LABEL + r")+", block["name"].strip().rstrip(".")):
        return ["child_ns.name must be a plain DNS hostname"]
    name = child_ns_name(cfg)
    errors = []
    if not in_zone(name, SITE) or name == SITE:
        errors.append("child_ns.name must be an ordinary name inside the managed parent zone " + SITE)
    if in_zone(name, LAB):
        errors.append("child_ns.name must sit outside the delegated provider zone " + LAB +
                      " (external child-NS contract; the legacy in-zone fixture is not this topology)")
    if in_zone(name, CHILD):
        errors.append("child_ns.name must sit outside the delegated child zone " + CHILD)
    if name == PROVIDER_NS:
        errors.append("child_ns.name must differ from the provider NS name " + PROVIDER_NS)
    addresses = {}
    for field in ("true_ip", "fake_ip"):
        value = block.get(field)
        if value is None:
            continue
        try:
            ip = ipaddress.IPv4Address(value)
        except (ValueError, TypeError):
            errors.append("child_ns." + field + " must be null or a public IPv4 unicast address")
            continue
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            errors.append("child_ns." + field + " must be null or a public IPv4 unicast address")
            continue
        addresses[field] = str(ip)
    if addresses.get("true_ip") and addresses.get("true_ip") == addresses.get("fake_ip"):
        errors.append("child_ns true_ip and fake_ip must differ: the referral ADDITIONAL contradicts the parent-side A record")
    for field, role in (("true_ip", "true"), ("fake_ip", "fake")):
        value, host = addresses.get(field), cfg["hosts"][role]["ipv4"]
        if bool(value) != bool(host):
            errors.append("child_ns." + field + " and hosts." + role + ".ipv4 must be assigned together")
        elif value and host and value != str(host):
            errors.append("child_ns." + field + " must match hosts." + role + ".ipv4 (" + str(host) + ")")
    return errors


def child_ns_plan(cfg):
    """Dry-run documentation of the reviewed external child-NS contract.

    The parent-side A record is a real Cloudflare record and keeps pointing at
    the true VPS.  The contradictory ADDITIONAL A is fixture data emitted by the
    lab referral only; it is never a Cloudflare record.
    """
    name, (true_ip, fake_ip) = child_ns_name(cfg), child_ns_addresses(cfg)
    return {
        "name": name,
        "parent_side_a": {"type": "A", "name": name, "content": true_ip, "cloudflare_record": True},
        "referral_additional": {"type": "ADDITIONAL", "name": name, "content": fake_ip,
                                "cloudflare_record": False,
                                "note": "contradictory lab fixture only; never publish this record"},
    }


def check(cfg):
    rows = []
    def result(scope, status, description):
        rows.append({"scope": scope, "status": status, "description": description})
    for relative in PUBLIC_FILES:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            result("local", "BLOCKED", "missing or symlinked allowlisted source: " + relative)
            continue
        if path.suffix == ".py":
            try:
                compile(path.read_bytes(), str(path), "exec")
            except (SyntaxError, ValueError) as exc:
                result("local", "BLOCKED",
                       "allowlisted Python source does not parse: " + relative + " (" + str(exc) + ")")
    if not any(r["scope"] == "local" for r in rows):
        result("local", "PASS", "public source allowlist exists; Python sources parse")
    result("dns", "PASS" if dns_contract() else "BLOCKED",
           "DNS --child-ns contract present" if dns_contract() else
           "lab_dns.py lacks --child-ns; the external child-NS deployment is not supported. Do not deploy the older in-zone fixture as this topology.")
    name = child_ns_name(cfg)
    errors = child_ns_errors(cfg)
    result("dns", "BLOCKED" if errors else "PASS",
           "; ".join(errors) if errors else
           "child NS " + name + " is an ordinary " + SITE + " record outside the delegated provider zone")
    true_ip, fake_ip = child_ns_addresses(cfg)
    result("dns", "PASS" if true_ip else "PENDING",
           "child NS true address " + str(true_ip) + ": parent-side A record target (true VPS)" if true_ip else
           "child NS true address: parent-side A record target (true VPS) is an unassigned VPS input")
    result("dns", "PASS" if fake_ip else "PENDING",
           "child NS fake address " + str(fake_ip) + ": contradictory referral ADDITIONAL fixture only, never a Cloudflare record"
           if fake_ip else
           "child NS fake address: the contradictory referral ADDITIONAL fixture (never a Cloudflare record) is an unassigned VPS input")
    status, description = child_ns_plan_status(cfg)
    result("dns", status, description)
    http_source = (ROOT / "poc/lab/http/lab_http.py").read_text()
    result("https", "PASS" if "--registry-dir" in http_source else "BLOCKED",
           "HTTP --registry-dir contract present" if "--registry-dir" in http_source else
           "lab_http.py lacks --registry-dir; package demo routes are not deployable")
    for role in ROLES:
        host = cfg["hosts"][role]
        result("dns", "PASS" if all(host.values()) else "PENDING", role + " public IPv4 and SSH alias")
    result("acme", "PASS" if cfg["acme_email"] else "PENDING", "ACME contact email")
    result("acme", "PASS" if shutil.which("certbot") else "PENDING", "local Certbot executable")
    for kind, paths in (("normal", normal_paths(cfg)),
                        ("forged", (cfg["forged_fullchain"], cfg["forged_key"]))):
        if not all(paths) or not all(Path(p).is_file() for p in paths):
            result("https", "PENDING", kind + " leaf fullchain and matching key input")
        else:
            try:
                _, _, info = validate_leaf(*paths, kind)
                result("https", "PASS", kind + " input validated: " + json.dumps(info))
            except Exception as exc:
                result("https", "BLOCKED", kind + " input: " + str(exc))
    result("external", "PENDING", "SSH host keys/sudo/Ubuntu version/bound IPs/distinct machines/ports: run ssh-check after VPS provisioning")
    result("external", "PENDING", "Cloudflare delegation, CAA/DNSSEC state, public UDP+TCP 53, ACME issuance, HTTPS, Pages and release acceptance have not been tested here")
    return rows


def require(cfg, stage):
    scopes = {"local", "dns"} | ({"https"} if stage == "https" else set())
    failures = [r for r in check(cfg) if r["scope"] in scopes and r["status"] != "PASS"]
    if failures:
        raise ValueError("not ready for " + stage + ":\n" + "\n".join(r["description"] for r in failures))


def cloudflare_records(cfg):
    """The only records the owner may create.  The child-NS A row keeps pointing
    at the TRUE VPS; the contradictory referral ADDITIONAL is fixture data and
    never appears here (see child_ns_plan)."""
    hosts = cfg["hosts"]
    true_ip, _ = child_ns_addresses(cfg)
    return [
        {"type": "CNAME", "name": SITE, "content": "grearl.github.io", "proxied": False},
        {"type": "A", "name": PROVIDER_NS, "content": hosts["provider"]["ipv4"], "proxied": False},
        {"type": "A", "name": child_ns_name(cfg), "content": true_ip, "proxied": False},
        {"type": "NS", "name": LAB, "content": PROVIDER_NS},
    ]


def child_ns_plan_status(cfg):
    """Guard the plan rows against publishing the contradictory ADDITIONAL."""
    name, plan_rows = child_ns_name(cfg), cloudflare_records(cfg)
    true_ip, fake_ip = child_ns_addresses(cfg)
    child_rows = [r for r in plan_rows if str(r["name"]).lower() == name]
    if fake_ip and any(str(r.get("content")) == fake_ip for r in plan_rows):
        return "BLOCKED", "the contradictory ADDITIONAL address must never appear as a Cloudflare record"
    if len(child_rows) != 1 or child_rows[0]["type"] != "A":
        return "BLOCKED", "the Cloudflare plan needs exactly one A record for the child NS name " + name
    if true_ip and child_rows[0]["content"] != true_ip:
        return "BLOCKED", "the parent-side child NS A record must point at the true VPS"
    return "PASS", ("Cloudflare plan keeps the child NS A at the true VPS and never publishes the "
                    "contradictory ADDITIONAL (referral fixture data only)")


def units(cfg, role, stage):
    ip = cfg["hosts"][role]["ipv4"]
    if not ip or role not in ROLES:
        raise ValueError("cannot render units without a concrete host address")
    template = (HERE / "service.template").read_text()
    # Coupling: the DNS lab must accept these exact flags; dns_contract() checks
    # the --child-ns part and child_ns_name() supplies the configured external
    # name before any unit or apply stage renders.
    dns = ["/usr/bin/python3", "/opt/yip/poc/lab/dns/lab_dns.py", "--role", role,
           "--bind", ip, "--port", "53", "--zone", LAB, "--child", "v",
           "--provider-ns", PROVIDER_NS, "--child-ns", child_ns_name(cfg),
           "--provider-ip", cfg["hosts"]["provider"]["ipv4"],
           "--true-ip", cfg["hosts"]["true"]["ipv4"], "--fake-ip", cfg["hosts"]["fake"]["ipv4"],
           "--ttl", "0"]
    if role != "provider":
        dns += ["--challenge-file", "/var/lib/yip/challenges.json"]
    rendered = {"yip-dns.service": template.format(role=role, kind="DNS", command=shlex.join(dns))}
    if stage == "https" and role != "provider":
        http = ["/usr/bin/python3", "/opt/yip/poc/lab/http/lab_http.py", "--role", role,
                "--bind", ip, "--port", "443", "--cert", "/etc/yip/current/normal-fullchain.pem",
                "--key", "/etc/yip/current/normal-key.pem", "--registry-dir", "/opt/yip/poc/deploy/public-registry"]
        if role == "fake":
            http += ["--forged-cert", "/etc/yip/current/forged-fullchain.pem", "--forged-key",
                     "/etc/yip/current/forged-key.pem", "--forged-sni", ",".join(sorted(FORGED_NAMES))]
        rendered["yip-http.service"] = template.format(role=role, kind="HTTPS", command=shlex.join(http))
    return rendered


def encode(data):
    return base64.b64encode(data).decode("ascii")


def leaf_payload(cfg, include_forged):
    payload = {}
    inputs = [("normal", normal_paths(cfg))]
    if include_forged:
        inputs.append(("forged", (cfg["forged_fullchain"], cfg["forged_key"])))
    for kind, paths in inputs:
        cert, key, _ = validate_leaf(*paths, kind)
        payload[kind + "-fullchain.pem"] = encode(cert)
        payload[kind + "-key.pem"] = encode(key)
    return payload


def install_payload(cfg, role, stage):
    files = PUBLIC_FILES
    if role == "provider":
        files = [f for f in files if f == "LICENSE" or f.startswith("poc/vendor/") or f == "poc/lab/dns/lab_dns.py"]
    return {"action": "install", "role": role,
            "files": {f: encode((ROOT / f).read_bytes()) for f in files},
            "units": units(cfg, role, stage),
            "certs": leaf_payload(cfg, role == "fake") if stage == "https" and role != "provider" else {}}


def remote(cfg, role, request):
    alias = cfg["hosts"][role]["ssh"]
    command = "sudo -n /usr/bin/python3 -c " + shlex.quote((HERE / "remote.py").read_text())
    subprocess.run(["ssh", *SSH_OPTIONS, alias, command], input=json.dumps(request).encode(), check=True)


def ssh_check(cfg, stage):
    require(cfg, "dns")
    identities = set()
    for role in ROLES:
        # Bind tests are read-only and omit ports already owned by our active service.
        script = """
import json, pathlib, socket, subprocess
host = json.loads(__import__('sys').argv[1])
release = dict(line.split('=', 1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
assert release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04', 'Ubuntu 24.04 LTS required'
ip = host['ipv4']
addresses = json.loads(subprocess.check_output(['ip','-j','address','show']))
assert any(a.get('local') == ip for iface in addresses for a in iface.get('addr_info', [])), 'public IPv4 is not assigned to this host'
for port, kind, service in [(53,socket.SOCK_DGRAM,'yip-dns.service'),(53,socket.SOCK_STREAM,'yip-dns.service')] + ([(443,socket.SOCK_STREAM,'yip-http.service')] if host['https'] else []):
    if subprocess.run(['systemctl','is-active','--quiet',service]).returncode == 0:
        continue
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind((ip,port))
print(json.dumps({'machine_id': pathlib.Path('/etc/machine-id').read_text().strip(), 'bound_ip': ip}))
"""
        host = {"ipv4": cfg["hosts"][role]["ipv4"], "https": stage == "https" and role != "provider"}
        command = "sudo -n /usr/bin/python3 -c " + shlex.quote(script) + " " + shlex.quote(json.dumps(host))
        result = subprocess.run(["ssh", *SSH_OPTIONS, cfg["hosts"][role]["ssh"], command],
                                capture_output=True, text=True, check=True)
        identity = json.loads(result.stdout)["machine_id"]
        if not identity or identity in identities:
            raise ValueError("SSH aliases must point to three distinct OS instances")
        identities.add(identity)
        print("PASS " + role + ": SSH, sudo, Ubuntu, bind address and required listeners")


def query_txt(ip, name, tcp=False):
    response = DNSRecord.parse(DNSRecord.question(name, "TXT").send(ip, 53, tcp=tcp, timeout=5))
    if response.header.rcode != RCODE.NOERROR:
        return set()
    return {b"".join(rr.rdata.data).decode("ascii") for rr in response.rr if rr.rtype == QTYPE.TXT}


def hook(cfg, action):
    domain = os.environ.get("CERTBOT_IDENTIFIER") or os.environ.get("CERTBOT_DOMAIN", "")
    token = os.environ.get("CERTBOT_VALIDATION", "")
    if domain.removeprefix("*.") != CHILD or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", token):
        raise ValueError("unexpected Certbot challenge environment")
    state = private_state(cfg, create=True)
    path = state / "challenge-state.json"
    with (state / "challenge.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        values = json.loads(path.read_text()) if path.exists() else {}
        name = "_acme-challenge." + CHILD
        tokens = set(values.get(name, []))
        if action == "auth":
            tokens.add(token)
        else:
            tokens.discard(token)
        values = {name: sorted(tokens)} if tokens else {}
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(values))
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        # Both endpoints must be updated, including cleanup after partial failure.
        errors = []
        for role in ("true", "fake"):
            try:
                remote(cfg, role, {"action": "challenge", "role": role, "values": values})
            except subprocess.CalledProcessError as exc:
                errors.append(str(exc))
        if errors:
            raise ValueError("challenge distribution failed: " + "; ".join(errors))
        if action == "auth":
            targets = [(cfg["hosts"][r]["ipv4"], tcp) for r in ("true", "fake") for tcp in (False, True)]
            targets += [(ip, False) for ip in ("1.1.1.1", "8.8.8.8")]
            deadline = time.monotonic() + 120
            while True:
                try:
                    if all(token in query_txt(ip, name, tcp) for ip, tcp in targets):
                        break
                except (OSError, ValueError):
                    pass
                if time.monotonic() >= deadline:
                    raise ValueError("TXT not visible from both authorities and both public resolvers within 120s")
                time.sleep(2)


def certbot_base(cfg, staging=False):
    executable = shutil.which("certbot")
    if not executable:
        raise ValueError("install Certbot on this controller first")
    base = private_state(cfg, create=True) / ("acme-staging" if staging else "acme")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return [executable, "--config-dir", str(base), "--work-dir", str(base / "work"),
            "--logs-dir", str(base / "logs")]


def acme(cfg, config_path, staging):
    require(cfg, "dns")
    if not cfg["acme_email"]:
        raise ValueError("acme_email is required")
    command = certbot_base(cfg, staging) + ["certonly", "--manual", "--preferred-challenges", "dns",
               "--non-interactive", "--agree-tos", "--email", cfg["acme_email"], "--cert-name", "yip-normal",
               "--server", ACME_STAGING_DIRECTORY if staging else ACME_DIRECTORY, "-d", "*." + CHILD]
    for action, flag in (("auth", "--manual-auth-hook"), ("cleanup", "--manual-cleanup-hook")):
        command += [flag, shlex.join([sys.executable, str(HERE / "deploy.py"), "--config",
                                     str(config_path), "hook", action])]
    subprocess.run(command, check=True)
    print("Staging certificate only; it will not be deployed." if staging else
          "Normal certificate issued. Run preflight --require https before apply --stage https.")


def renew(cfg, dry_run):
    require(cfg, "dns")
    command = certbot_base(cfg) + ["renew", "--cert-name", "yip-normal", "--non-interactive",
                                  "--server", ACME_STAGING_DIRECTORY if dry_run else ACME_DIRECTORY]
    if dry_run:
        command += ["--dry-run"]
    result = subprocess.run(command)
    if not dry_run:
        # Re-sync even when renewal is not due: retries a previous partial SSH failure.
        certs = leaf_payload(cfg, False)
        errors = []
        for role in ("true", "fake"):
            try:
                remote(cfg, role, {"action": "certs", "role": role, "certs": certs})
            except subprocess.CalledProcessError as exc:
                errors.append(str(exc))
        if errors:
            raise ValueError("normal certificate sync failed; next renew retries: " + "; ".join(errors))
    if result.returncode:
        raise ValueError("Certbot renewal failed; inspect the private local ACME logs")


def schedule(cfg, config_path):
    """Render local scheduler files; never register or start a scheduled job."""
    require(cfg, "https")
    if not shutil.which("certbot"):
        raise ValueError("install Certbot before rendering a renewal schedule")
    directory = private_state(cfg, create=True) / "schedule"
    directory.mkdir(exist_ok=True, mode=0o700)
    command = [sys.executable, str(HERE / "deploy.py"), "--config", str(config_path), "renew"]
    executable_path = ":".join(dict.fromkeys([str(Path(shutil.which("certbot")).parent),
                                             str(Path(sys.executable).parent), "/usr/bin", "/bin"]))
    systemd_command = shlex.join(command).replace("%", "%%").replace("$", "$$")
    service = ("[Unit]\nDescription=Renew and distribute the owned lab wildcard leaf\n"
               "[Service]\nType=oneshot\nUMask=0077\n"
               "Environment=PATH=" + executable_path + "\nExecStart=" + systemd_command + "\n")
    timer = ("[Unit]\nDescription=Check lab wildcard renewal twice daily\n[Timer]\n"
             "OnCalendar=*-*-* 03,15:10:00\nRandomizedDelaySec=1h\nPersistent=true\n"
             "[Install]\nWantedBy=timers.target\n")
    plist = {"Label": "com.yip.renew", "ProgramArguments": command,
             "EnvironmentVariables": {"PATH": executable_path}, "StartInterval": 43200,
             "RunAtLoad": True, "StandardOutPath": str(directory / "renew.stdout.log"),
             "StandardErrorPath": str(directory / "renew.stderr.log")}
    outputs = {"yip-renew.service": service.encode(), "yip-renew.timer": timer.encode(),
               "com.yip.renew.plist": plistlib.dumps(plist)}
    for name, data in outputs.items():
        path = directory / name
        path.write_bytes(data)
        os.chmod(path, 0o600)
    print("Scheduler files rendered only; not enabled: " + str(directory))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=HERE / "config.example.json")
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight", help="offline checks; no VPS required")
    preflight.add_argument("--require", choices=("dns", "https"))
    for name in ("plan", "apply", "ssh-check"):
        p = sub.add_parser(name)
        p.add_argument("--stage", choices=("dns", "https"), default="dns")
    issue = sub.add_parser("acme", help="request a normal owned-domain wildcard certificate")
    issue.add_argument("--staging", action="store_true")
    renewal = sub.add_parser("renew")
    renewal.add_argument("--dry-run", action="store_true")
    sub.add_parser("schedule", help="render local macOS/Linux renewal scheduler files; do not install them")
    internal = sub.add_parser("hook", help=argparse.SUPPRESS)
    internal.add_argument("action", choices=("auth", "cleanup"))
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.command == "preflight":
        rows = check(cfg)
        for row in rows:
            print(row["status"] + " [" + row["scope"] + "] " + row["description"])
        print("Offline report only: no VPS, DNS, CA, GitHub, or Cloudflare was contacted.")
        if args.require:
            require(cfg, args.require)
        return 1 if any(r["status"] == "BLOCKED" for r in rows) else 0
    if args.command == "plan":
        print(json.dumps({"cloudflare_records_to_review": cloudflare_records(cfg),
                          "child_ns_contract": child_ns_plan(cfg),
                          "null_means_unassigned": True, "public_transfer_allowlist": PUBLIC_FILES}, indent=2))
        require(cfg, args.stage)
        for role in ROLES:
            for name, content in units(cfg, role, args.stage).items():
                print("\n# " + role + "/" + name + "\n" + content)
    elif args.command == "ssh-check":
        ssh_check(cfg, args.stage)
    elif args.command == "apply":
        require(cfg, args.stage)
        ssh_check(cfg, args.stage)
        for role in ("true", "fake", "provider"):
            if args.stage == "https" and role == "provider":
                continue
            remote(cfg, role, install_payload(cfg, role, args.stage))
    elif args.command == "acme":
        acme(cfg, args.config.resolve(), args.staging)
    elif args.command == "renew":
        renew(cfg, args.dry_run)
    elif args.command == "schedule":
        schedule(cfg, args.config.resolve())
    elif args.command == "hook":
        hook(cfg, args.action)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
