#!/usr/bin/env python3
"""
probe_matrix.py -- ADDITIONAL/bailiwick acceptance matrix + resolver probe harness.

For every (resolver, response pattern) cell the harness:

  1. starts the lab_dns fixture authority set (provider role with the pattern,
     a third-party authority for the unrelated name, and for pattern p3 a true
     and a fake child endpoint plus a logging UDP sink),
  2. configures the candidate resolver to use the fixtures as its forward /
     stub / authority for the lab zones (no other nameserver is reachable from
     the lab; stray recursion is redirected at a local sink),
  3. PRIMES the resolver first -- the trigger query walks the crafted response
     (fresh random trigger and third-party names per cell) -- and only then
     issues independent follow-up queries for the third-party name within TTL
     (prime-then-probe ordering; a path-validation query uses a DIFFERENT
     random name so it can never mask a cached acceptance),
  4. records which endpoint answered (distinct marker addresses per endpoint)
     to separate USE-FOR-RESOLUTION from RE-RESOLVE-REAL.

Four outcomes per cell (plus INCONCLUSIVE/ERROR):
  REJECT                   the unrelated A is not persisted as an answerable
                           record and did not steer resolution,
  USE-FOR-RESOLUTION-ONLY  the unrelated A steered this resolution (the fake
                           endpoint answered or was queried) but a later
                           independent query does not return it,
  RE-RESOLVE-REAL          the unrelated A was ignored: the NS name was
                           re-resolved and the real endpoint answered,
  CACHE-AND-ANSWER         a later independent query for the third-party name
                           returns the unrelated A (with cache-decaying TTL).

Everything runs against loopback (host mode) or an isolated, egress-blocked
user-defined docker network (docker mode).  No query ever leaves the lab.

Modes:
  --mode shape    fixture-only response-shape checks (loopback, offline);
                  used by test_local.sh scenario 3.
  --mode matrix   the full resolver matrix (default).

Machine-readable output: results/<label>.json (evidence per cell).
Human summary:          results/<label>.md.
"""
import argparse
import copy
import json
import os
import random
import signal
import socket
import string
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "vendor"))

from dnslib import DNSRecord, QTYPE, RCODE  # noqa: E402

RCODE_NAME = {getattr(RCODE, n): n for n in
              ("NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED")}

PATTERN_INFO = {
    "p1": {"shape": "authoritative answer + unrelated A in ADDITIONAL",
           "trigger": "in-zone", "load_bearing": False},
    "p2": {"shape": "referral + unrelated A in ADDITIONAL (third-party owner)",
           "trigger": "child", "load_bearing": False},
    "p3": {"shape": "external-NS delegation glue (ADDITIONAL A for the NS name)",
           "trigger": "child", "load_bearing": True},
    "p4": {"shape": "answer section containing unrelated owner records",
           "trigger": "in-zone", "load_bearing": False},
    "p5": {"shape": "forged successful answer with unsolicited RRs in ANSWER "
                    "(CVE-2025-40778 axis)",
           "trigger": "child", "load_bearing": False},
}


# ------------------------- query helpers -------------------------

def norm(name):
    return str(name).rstrip(".").lower()


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def dns_query(server, port, name, qtype="A", timeout=6, tcp=False, rd=True):
    req = DNSRecord.question(name, qtype)
    req.header.rd = 1 if rd else 0
    t0 = time.time()
    try:
        raw = req.send(server, port, timeout=timeout, tcp=tcp)
        reply = DNSRecord.parse(raw)
    except Exception as exc:
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                "elapsed": round(time.time() - t0, 3)}
    out = {"ok": True, "elapsed": round(time.time() - t0, 3),
           "rcode": RCODE_NAME.get(reply.header.rcode, str(reply.header.rcode)),
           "aa": bool(reply.header.aa), "ra": bool(reply.header.ra),
           "rd": bool(reply.header.rd), "tc": bool(reply.header.tc),
           "answer": [], "authority": [], "additional": []}
    for section, key in ((reply.rr, "answer"), (reply.auth, "authority"), (reply.ar, "additional")):
        for rr in section:
            out[key].append({"owner": norm(rr.rname), "type": QTYPE[rr.rtype],
                             "ttl": rr.ttl, "data": str(rr.rdata)})
    return out


def section_text(records):
    return "; ".join("%s %s %s ttl=%s" % (r["owner"], r["type"], r["data"], r["ttl"])
                     for r in records) or "-"


def answer_ips(result, owner, rtype="A"):
    if not result.get("ok"):
        return []
    return [r["data"] for r in result["answer"]
            if r["type"] == rtype and r["owner"] == norm(owner)]


def result_ttls(result, owner, rtype="A"):
    if not result.get("ok"):
        return []
    return [r["ttl"] for r in result["answer"]
            if r["type"] == rtype and r["owner"] == norm(owner)]


# ------------------------- lab namespace -------------------------

class Lab:
    """Names and addresses of one matrix run (all .invalid = never public)."""

    def __init__(self, seed=None, runner="host"):
        self.seed = seed or "".join(random.choice(string.ascii_lowercase + string.digits)
                                    for _ in range(8))
        r = self.seed
        self.zone = "z%s.lab.invalid" % r
        self.child = "c%s" % r[:4]
        self.child_zone = "%s.%s" % (self.child, self.zone)
        self.tp_zone = "t%s.invalid" % r
        self.target = "n%s.%s" % (r[:4], self.tp_zone)
        self.trigger_inzone = "w.%s" % self.zone
        self.trigger_child = "w.%s" % self.child_zone
        self.baseline_name = "b%s.%s" % (r[:4], self.tp_zone)
        # task-15: second unrelated tree served by the SAME provider server
        # (shared-hosting topology) + typed injection values for p5
        self.zone2 = "y%s.cust.invalid" % r
        self.poison_aaaa = "2001:db8::66"
        self.poison_ns = "ns-inject.lab.invalid"
        self.ttl = 300
        self.runner = runner
        if runner == "docker":
            self.provider_ip = "10.77.0.10"
            self.tp_ip = "10.77.0.11"
            self.true_ns_ip = "10.77.0.20"
            self.fake_ns_ip = "10.77.0.66"
            self.drop_ip = "10.77.0.254"
        else:
            self.provider_ip = "127.0.0.1"
            self.tp_ip = "127.0.0.1"
            self.provider_port = free_port()
            self.tp_port = free_port()
            self.true_ns_ip = "127.0.0.8"
            self.fake_ns_ip = "127.0.0.9"
            self.drop_ip = "127.0.0.9"
        self.true_tp_addr = self.true_ns_ip
        self.true_marker = "192.0.2.10"
        self.fake_marker = "198.51.100.66"

    def poison_for(self, pattern, variant):
        if pattern == "p3":
            return self.drop_ip if variant.get("ns_target") == "unreachable" else self.fake_ns_ip
        return self.fake_ns_ip

    def trigger_for(self, pattern):
        return self.trigger_inzone if PATTERN_INFO[pattern]["trigger"] == "in-zone" else self.trigger_child

    def describe(self):
        return {"seed": self.seed, "runner": self.runner, "zone": self.zone,
                "child_zone": self.child_zone, "tp_zone": self.tp_zone,
                "third_party_name": self.target, "ttl": self.ttl,
                "true_third_party_address": self.true_tp_addr,
                "poison_address": self.fake_ns_ip, "true_marker": self.true_marker,
                "fake_marker": self.fake_marker}


# ------------------ fixture processes (host mode) ------------------

class LocalFixtures:
    def __init__(self, lab, workdir):
        self.lab = lab
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.procs = {}
        self.logs = {}

    def _spawn(self, name, args, log):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(HERE.parent.parent / "vendor")
        fh = open(log, "ab")
        proc = subprocess.Popen(args, stdout=fh, stderr=fh, env=env)
        self.procs[name] = proc
        self.logs[name] = Path(log)

    def start_provider(self, pattern, variant, tag, target=None, ptype="A"):
        self.stop("provider")
        lab = self.lab
        poison = lab.poison_for(pattern, variant)
        target = target or lab.target
        args = [sys.executable, str(HERE / "lab_dns.py"),
                "--role", "provider", "--bind", "127.0.0.1",
                "--port", str(lab.provider_port),
                "--zone", lab.zone, "--child", lab.child,
                "--provider-ns", "ns1." + lab.zone,
                "--true-ip", lab.true_tp_addr, "--fake-ip", poison,
                "--provider-ip", "127.0.0.1", "--ttl", str(lab.ttl),
                "--pattern", pattern,
                "--third-party", target, "--third-party-ip", poison,
                "--third-party-type", ptype, "--third-party-aaaa", lab.poison_aaaa,
                "--third-party-ns", lab.poison_ns, "--zone2", lab.zone2,
                "--log", str(self.workdir / (tag + "-provider.jsonl"))]
        if pattern == "p3":
            args += ["--child-ns", target, "--referral-owner", "name"]
        self._spawn("provider", args, self.workdir / (tag + "-provider.out"))
        self.logs["provider"] = self.workdir / (tag + "-provider.jsonl")

    def start_static(self, tag):
        lab = self.lab
        self._spawn("tp", [sys.executable, str(HERE / "lab_dns.py"),
                           "--role", "thirdparty", "--bind", "127.0.0.1",
                           "--port", str(lab.tp_port), "--zone", lab.tp_zone,
                           "--provider-ns", "ns1." + lab.tp_zone,
                           "--true-ip", lab.true_tp_addr, "--fake-ip", lab.fake_ns_ip,
                           "--ttl", str(lab.ttl),
                           "--log", str(self.workdir / (tag + "-tp.jsonl"))],
                    self.workdir / (tag + "-tp.out"))
        self.logs["tp"] = self.workdir / (tag + "-tp.jsonl")

    def ready(self, name, timeout=15):
        proc = self.procs.get(name)
        if not proc:
            return False
        port = self.lab.provider_port if name == "provider" else self.lab.tp_port
        probe = "ready-probe." + (self.lab.zone if name == "provider" else self.lab.tp_zone)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                return False
            res = dns_query("127.0.0.1", port, probe, timeout=0.5)
            if res.get("ok"):
                return True
            time.sleep(0.2)
        return False

    def query_count(self, name, since):
        path = self.logs.get(name)
        if not path or not path.exists():
            return 0
        n = 0
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    if json.loads(line).get("ts", 0) >= since:
                        n += 1
                except Exception:
                    pass
        except Exception:
            pass
        return n

    def stop(self, name):
        proc = self.procs.pop(name, None)
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

    def stop_all(self):
        for name in list(self.procs):
            self.stop(name)


# ---------------------- docker driver ----------------------

class Docker:
    def __init__(self, network="lab-dns-matrix", subnet="10.77.0.0/24"):
        self.network = network
        self.subnet = subnet

    def run(self, args, timeout=180):
        return subprocess.run(["docker"] + args, capture_output=True, text=True, timeout=timeout)

    def available(self):
        try:
            r = self.run(["version", "--format", "{{.Server.Version}}"], timeout=20)
        except Exception as exc:
            return False, str(exc)
        return (r.returncode == 0), (r.stdout.strip() or r.stderr.strip())

    def ensure_network(self):
        r = self.run(["network", "inspect", self.network])
        if r.returncode == 0:
            return
        r = self.run(["network", "create", "--subnet", self.subnet,
                      "--internal", "--label", "lab-matrix=1", self.network])
        if r.returncode != 0:
            raise RuntimeError("docker network create failed: " + r.stderr.strip())

    def build(self, tag, directory, build_args=None, timeout=900):
        args = ["build", "-t", tag]
        for k, v in (build_args or {}).items():
            args += ["--build-arg", k + "=" + v]
        args.append(str(directory))
        return self.run(args, timeout=timeout)

    def image(self, ref):
        return self.run(["image", "inspect", ref]).returncode == 0

    def rm(self, name):
        self.run(["rm", "-f", name], timeout=60)

    def start(self, name, args, ip=None, copies=None, entrypoint=None):
        """create -> docker cp -> start (bind mounts do not work on this colima VM)."""
        self.rm(name)
        cmd = ["create", "--name", name, "--network", self.network,
               "--label", "lab-matrix=1"]
        if ip:
            cmd += ["--ip", ip]
        if entrypoint:
            cmd += ["--entrypoint", entrypoint]
        cmd += args
        r = self.run(cmd)
        if r.returncode != 0:
            raise RuntimeError("docker create " + name + " failed: " + r.stderr.strip())
        for src, dst in (copies or []):
            try:
                os.chmod(src, 0o644)
            except Exception:
                pass
            r = self.run(["cp", src, name + ":" + dst])
            if r.returncode != 0:
                raise RuntimeError("docker cp %s -> %s failed: %s" % (src, dst, r.stderr.strip()))
        r = self.run(["start", name])
        if r.returncode != 0:
            raise RuntimeError("docker start " + name + " failed: " + r.stderr.strip())
        return name

    def logs(self, name):
        r = self.run(["logs", name], timeout=30)
        return (r.stdout or "") + (r.stderr or "")

    def exec_cat(self, name, path):
        r = self.run(["exec", name, "cat", path], timeout=30)
        return r.stdout if r.returncode == 0 else ""

    def running(self, name):
        r = self.run(["inspect", "-f", "{{.State.Running}}", name], timeout=20)
        return r.returncode == 0 and r.stdout.strip() == "true"

    def version_of(self, name, argv):
        r = self.run(["exec", name] + argv, timeout=60)
        text = (r.stdout or r.stderr).strip()
        return text.splitlines()[0][:200] if text else "?"

    def version_run(self, argv):
        r = self.run(argv, timeout=120)
        text = (r.stdout or r.stderr).strip()
        return text.splitlines()[0][:200] if text else "?"


class DockerFixtures:
    """Long-lived fixture containers (tp / true-ns / fake-ns / drop) + per-cell provider."""

    def __init__(self, docker, lab, fixture_image):
        self.docker = docker
        self.lab = lab
        self.image = fixture_image
        self.provider_log = "/tmp/provider.jsonl"

    def start_static(self):
        lab, d = self.lab, self.docker
        d.start("labmx-tp", [self.image, "/lab/lab_dns.py",
                             "--role", "thirdparty", "--bind", "0.0.0.0", "--port", "53",
                             "--zone", lab.tp_zone, "--provider-ns", "ns1." + lab.tp_zone,
                             "--true-ip", lab.true_tp_addr, "--fake-ip", lab.fake_ns_ip,
                             "--ttl", str(lab.ttl), "--log", "/tmp/q.jsonl"],
                ip=lab.tp_ip, entrypoint="python3")
        d.start("labmx-true", [self.image, "/lab/lab_dns.py",
                               "--role", "true", "--bind", "0.0.0.0", "--port", "53",
                               "--zone", lab.zone, "--child", lab.child,
                               "--provider-ns", "ns1." + lab.zone,
                               "--true-ip", lab.true_marker, "--fake-ip", lab.fake_marker,
                               "--ttl", str(lab.ttl), "--log", "/tmp/q.jsonl"],
                ip=lab.true_ns_ip, entrypoint="python3")
        d.start("labmx-fake", [self.image, "/lab/lab_dns.py",
                               "--role", "fake", "--bind", "0.0.0.0", "--port", "53",
                               "--zone", lab.zone, "--child", lab.child,
                               "--provider-ns", "ns1." + lab.zone,
                               "--true-ip", lab.true_marker, "--fake-ip", lab.fake_marker,
                               "--ttl", str(lab.ttl), "--log", "/tmp/q.jsonl"],
                ip=lab.fake_ns_ip, entrypoint="python3")
        d.start("labmx-drop", [self.image, "/lab/udp_sink.py",
                               "--bind", "0.0.0.0", "--port", "53", "--log", "/tmp/q.jsonl"],
                ip=lab.drop_ip, entrypoint="python3")
        time.sleep(2.0)

    def start_provider(self, pattern, variant, target=None, ptype="A"):
        lab, d = self.lab, self.docker
        poison = lab.poison_for(pattern, variant)
        target = target or lab.target
        args = [self.image, "/lab/lab_dns.py",
                "--role", "provider", "--bind", "0.0.0.0", "--port", "53",
                "--zone", lab.zone, "--child", lab.child,
                "--provider-ns", "ns1." + lab.zone,
                "--true-ip", lab.true_tp_addr, "--fake-ip", poison,
                "--ttl", str(lab.ttl), "--pattern", pattern,
                "--third-party", target, "--third-party-ip", poison,
                "--third-party-type", ptype, "--third-party-aaaa", lab.poison_aaaa,
                "--third-party-ns", lab.poison_ns, "--zone2", lab.zone2,
                "--log", self.provider_log]
        if pattern == "p3":
            args += ["--child-ns", target, "--referral-owner", "name"]
        d.start("labmx-provider", args, ip=lab.provider_ip, entrypoint="python3")
        time.sleep(0.8)

    def counts(self, since):
        d = self.docker
        out = {}
        for name, cname in (("provider", "labmx-provider"), ("thirdparty", "labmx-tp"),
                            ("true_ns", "labmx-true"), ("fake_ns", "labmx-fake"),
                            ("drop", "labmx-drop")):
            path = self.provider_log if name == "provider" else "/tmp/q.jsonl"
            text = d.exec_cat(cname, path)
            n = 0
            for line in text.splitlines():
                try:
                    if json.loads(line).get("ts", 0) >= since:
                        n += 1
                except Exception:
                    pass
            out[name] = n
        return out

    def stop_all(self):
        for name in ("labmx-provider", "labmx-tp", "labmx-true", "labmx-fake",
                     "labmx-drop", "labmx-resolver"):
            self.docker.rm(name)


# ------------------------ resolver configs ------------------------

def root_hints(path, sink_ip):
    text = (". 3600000  NS  a.root.lab.invalid.\n"
            "a.root.lab.invalid. 3600000 A " + sink_ip + "\n")
    Path(path).write_text(text, encoding="utf-8")
    return text


def unbound_conf(lab, mode, provider, tp, sink_ip, iface, harden_unverified_glue,
                 hints_path, do_localhost):
    # CRITICAL (recon finding): unbound ships local-zone "invalid." static per RFC 6761,
    # which shadows stub/forward zones under *.invalid unless overridden.
    stub = "stub-zone" if mode == "stub" else "forward-zone"
    addr_key = "stub-addr" if mode == "stub" else "forward-addr"
    lines = [
        "server:",
        "    verbosity: 1",
        "    num-threads: 1",
        "    interface: " + iface,
        "    access-control: 0.0.0.0/0 allow",
        "    do-ip6: no",
        "    do-udp: yes",
        "    do-tcp: yes",
        "    username: \"\"",
        "    chroot: \"\"",
        "    pidfile: \"\"",
        "    use-syslog: no",
        "    logfile: \"\"",
        "    module-config: \"iterator\"",
        "    harden-unverified-glue: " + harden_unverified_glue,
        "    harden-glue: yes",
        "    aggressive-nsec: no",
        "    qname-minimisation: no",
        "    local-zone: \"invalid.\" transparent",
        "    root-hints: \"" + hints_path + "\"",
        "    cache-min-ttl: 0",
        "    cache-max-ttl: 86400",
        "    prefetch: no",
        "    minimal-responses: no",
        "    hide-identity: yes",
        "    hide-version: yes",
    ]
    if do_localhost:
        lines.append("    do-not-query-localhost: no")
    prime = ["    stub-prime: no"] if mode == "stub" else []
    lines += [stub + ":",
              "    name: \"" + lab.zone + "\"",
              "    " + addr_key + ": " + provider] + prime
    lines += [stub + ":",
              "    name: \"" + lab.tp_zone + "\"",
              "    " + addr_key + ": " + tp] + prime
    if getattr(lab, "zone2", None):
        # task-15: tree-B (shared-hosting second tree) served by the same provider
        lines += [stub + ":",
                  "    name: \"" + lab.zone2 + "\"",
                  "    " + addr_key + ": " + provider] + prime
    return "\n".join(lines) + "\n"


def bind_conf(lab, provider, tp, sink_ip, hints_path):
    # named.conf authority mode: static-stub zones to the fixed fixture servers
    return "\n".join([
        "options {",
        "    directory \"/var/cache/bind\";",
        "    listen-on { any; };",
        "    listen-on-v6 { none; };",
        "    recursion yes;",
        "    allow-recursion { any; };",
        "    allow-query { any; };",
        "    allow-query-cache { any; };",
        "    dnssec-validation no;",
        "    empty-zones-enable no;",
        "    managed-keys-directory \"/var/cache/bind\";",
        "};",
        "zone \"" + lab.zone + "\" { type static-stub; server-addresses { " + provider + "; }; };",
        "zone \"" + lab.tp_zone + "\" { type static-stub; server-addresses { " + tp + "; }; };",
        "zone \"" + getattr(lab, "zone2", lab.zone + "2") + "\" { type static-stub; server-addresses { "
        + provider + "; }; };",
        "zone \".\" { type hint; file \"" + hints_path + "\"; };",
    ]) + "\n"


def bind_conf_fallback(lab, provider, tp, sink_ip, hints_path):
    # recon-verified shape: stub zone for the provider zone + forward zone for the
    # third-party zone (used only if static-stub refuses to start)
    return "\n".join([
        "options {",
        "    directory \"/var/cache/bind\";",
        "    listen-on { any; };",
        "    listen-on-v6 { none; };",
        "    recursion yes;",
        "    allow-recursion { any; };",
        "    allow-query { any; };",
        "    dnssec-validation no;",
        "    empty-zones-enable no;",
        "};",
        "zone \"" + lab.zone + "\" { type stub; masters { " + provider + "; }; file \"stub-lab-zone\"; };",
        "zone \"" + lab.tp_zone + "\" { type forward; forward only; forwarders { " + tp + "; }; };",
        "zone \"" + getattr(lab, "zone2", lab.zone + "2") + "\" { type forward; forward only; forwarders { "
        + provider + "; }; };",
        "zone \".\" { type hint; file \"" + hints_path + "\"; };",
    ]) + "\n"


def dnsmasq_conf(lab, provider, tp):
    return "\n".join([
        "# lab dnsmasq: forward the two lab zones to the two fixture servers",
        "no-resolv",
        "no-hosts",
        "bind-interfaces",
        "listen-address=0.0.0.0",
        "server=/" + lab.zone + "/" + provider,
        "server=/" + lab.tp_zone + "/" + tp,
        "server=/" + getattr(lab, "zone2", lab.zone + "2") + "/" + provider,
    ]) + "\n"


def kresd_conf(lab, provider, tp):
    # Knot Resolver v5 Lua (recon: policy.suffix second argument must be a table)
    return "\n".join([
        "net.listen('0.0.0.0', 53, { kind = 'dns' })",
        "cache.size = 100 * MB",
        "policy.add(policy.suffix(policy.STUB('" + provider + "'), { todname('" + lab.zone + "') }))",
        "policy.add(policy.suffix(policy.STUB('" + tp + "'), { todname('" + lab.tp_zone + "') }))",
        "policy.add(policy.suffix(policy.STUB('" + provider + "'), { todname('" + getattr(lab, "zone2", lab.zone + "2") + "') }))",
    ]) + "\n"


def pdns_conf(lab, provider, tp, hints_path):
    # PowerDNS Recursor 5.x YAML-style config (recon: forward_zones = list of structs)
    return "\n".join([
        "incoming:",
        "  listen:",
        "    - 0.0.0.0:53",
        "  allow_from:",
        "    - 0.0.0.0/0",
        "recursor:",
        "  daemon: false",
        "  socket_dir: /var/run/pdns-recursor",
        "  forward_zones:",
        "    - zone: " + lab.zone,
        "      forwarders:",
        "        - " + provider,
        "    - zone: " + lab.tp_zone,
        "      forwarders:",
        "        - " + tp,
        "    - zone: " + getattr(lab, "zone2", lab.zone + "2"),
        "      forwarders:",
        "        - " + provider,
        "dnssec:",
        "  validation: \"off\"",
    ]) + "\n"


def pdns_conf_classic(lab, provider, tp):
    # PowerDNS Recursor 4.x classic config (comma-separated forward-zones form)
    return "\n".join([
        "daemon=no",
        "local-address=0.0.0.0",
        "local-port=53",
        "allow-from=0.0.0.0/0,::/0",
        "dnssec=off",
        "quiet=no",
        "webserver=no",
        "socket-dir=/var/run/pdns-recursor",
        "forward-zones=" + lab.zone + "=" + provider + "," + lab.tp_zone + "=" + tp +
        "," + getattr(lab, "zone2", lab.zone + "2") + "=" + provider,
    ]) + "\n"


def coredns_conf(lab, provider, tp):
    # CoreDNS: forwarder only (P2/P3 referral shapes are N/A for forwarders)
    return "\n".join([
        lab.zone + ":53 {",
        "    errors",
        "    forward . " + provider,
        "}",
        lab.tp_zone + ":53 {",
        "    errors",
        "    forward . " + tp,
        "}",
        ".:53 {",
        "    errors",
        "    forward . 127.0.0.1:9",
        "}",
    ]) + "\n"


def maradns_conf(lab, provider, tp):
    # MaraDNS Deadwood (dwood3rc): upstream_servers per zone suffix
    return "\n".join([
        "bind_address = \"0.0.0.0\"",
        "chroot_dir = \"/etc/maradns\"",
        "recursive_acl = \"0.0.0.0/0\"",
        "maxprocs = 8",
        "filter_rfc1918 = 0",
        "upstream_servers = {}",
        "upstream_servers[\"" + lab.zone + "\"] = \"" + provider + "\"",
        "upstream_servers[\"" + lab.tp_zone + "\"] = \"" + tp + "\"",
    ]) + "\n"


# ------------------------- resolver rows -------------------------

RESOLVER_IMAGES = {
    "unbound": ("lab-dns/r-unbound", "unbound"),
    "dnsmasq": ("lab-dns/r-dnsmasq", "dnsmasq"),
    "kresd": ("lab-dns/r-kresd", "knot-resolver"),
    "pdns": ("lab-dns/r-pdns", "pdns-recursor"),
}

DOCKER_ROWS = [
    {"name": "bind9-pre", "image": "lab-recon/bind9:9.18.38", "kind": "bind",
     "mount": "/etc/bind/named.conf", "entrypoint": None, "start": [],
     "version_run": ["run", "--rm", "--entrypoint", "named", "lab-recon/bind9:9.18.38", "-v"],
     "modes": ["authority"], "p3_harden": ["default"],
     "note": "BIND 9.18.38 ESV (built from ISC tarball): BEFORE the 2025-10 strict-glue change"},
    {"name": "bind9-post", "image": "lab-recon/bind9:9.18.41", "kind": "bind",
     "mount": "/etc/bind/named.conf", "entrypoint": None, "start": [],
     "version_run": ["run", "--rm", "--entrypoint", "named", "lab-recon/bind9:9.18.41", "-v"],
     "modes": ["authority"], "p3_harden": ["default"],
     "note": "BIND 9.18.41 ESV (built from ISC tarball): AFTER the 2025-10 strict-glue change"},
    {"name": "unbound", "image": "lab-recon/unbound", "kind": "unbound",
     "mount": "/etc/unbound/unbound.conf", "entrypoint": "unbound",
     "start": ["-d", "-c", "/etc/unbound/unbound.conf"],
     "version_run": ["run", "--rm", "--entrypoint", "unbound", "lab-recon/unbound", "-V"],
     "modes": ["stub", "forward"], "p3_harden": ["yes", "no"],
     "note": "Unbound 1.22 (alpine); P3 run with harden-unverified-glue yes and no"},
    {"name": "dnsmasq", "image": "lab-recon/dnsmasq", "kind": "dnsmasq",
     "mount": "/etc/dnsmasq.conf", "entrypoint": "dnsmasq",
     "start": ["-k", "--conf-file=/etc/dnsmasq.conf"],
     "version_run": ["run", "--rm", "--entrypoint", "dnsmasq", "lab-recon/dnsmasq", "-v"],
     "modes": ["forward"], "p3_harden": ["default"], "forwarder_only": True,
     "note": "dnsmasq 2.90 is a forwarder: P2/P3 referral shapes are N/A (run, not counted)"},
    {"name": "knot-resolver", "image": "lab-recon/knot", "kind": "kresd",
     "mount": "/etc/knot-resolver/kresd.conf", "entrypoint": "sh",
     "start": ["-c", "mkdir -p /var/lib/knot-resolver && exec kresd -n -c "
               "/etc/knot-resolver/kresd.conf /var/lib/knot-resolver"],
     "version_run": ["run", "--rm", "--entrypoint", "kresd", "lab-recon/knot", "-V"],
     "modes": ["stub"], "p3_harden": ["default"],
     "note": "Knot Resolver 5.7.4 (kresd v5 Lua, policy.STUB)"},
    {"name": "pdns-recursor", "image": "lab-recon/pdns", "kind": "pdns",
     "mount": "/etc/pdns/recursor.conf", "entrypoint": "sh",
     "start": ["-c", "mkdir -p /var/run/pdns-recursor && chown recursor /var/run/pdns-recursor; "
               "exec pdns_recursor --daemon=no --config-dir=/etc/pdns"],
     "version_run": ["run", "--rm", "--entrypoint", "pdns_recursor", "lab-recon/pdns", "--version"],
     "modes": ["forward"], "p3_harden": ["default"],
     "note": "PowerDNS Recursor 5.1.3 (forward_zones); no documented glue policy"},
    {"name": "pdns-recursor-4.9", "image": "lab-recon/pdns-old", "kind": "pdns-classic",
     "mount": "/etc/pdns/recursor.conf", "entrypoint": "sh",
     "start": ["-c", "mkdir -p /var/run/pdns-recursor && chown recursor /var/run/pdns-recursor; "
               "exec pdns_recursor --daemon=no --config-dir=/etc/pdns"],
     "version_run": ["run", "--rm", "--entrypoint", "pdns_recursor", "lab-recon/pdns-old", "--version"],
     "modes": ["forward"], "p3_harden": ["default"],
     "note": "PowerDNS Recursor 4.9.5 (classic comma-separated forward-zones)"},
    {"name": "bind9-9.20.15", "image": "lab-recon/bind9:9.20.15", "kind": "bind",
     "mount": "/etc/bind/named.conf", "entrypoint": None, "start": [],
     "version_run": ["run", "--rm", "--entrypoint", "named", "lab-recon/bind9:9.20.15", "-v"],
     "modes": ["authority"], "p3_harden": ["default"],
     "note": "BIND 9.20.15 (built from ISC tarball): post-boundary stable branch"},
    {"name": "coredns", "image": "coredns/coredns", "kind": "coredns",
     "mount": "/Corefile", "entrypoint": "/coredns",
     "start": ["-conf", "/Corefile"],
     "version_run": ["run", "--rm", "--entrypoint", "/coredns", "coredns/coredns", "--version"],
     "modes": ["forward"], "p3_harden": ["default"], "forwarder_only": True,
     "note": "CoreDNS is a forwarder: P2/P3 referral shapes are N/A (run, not counted)"},
    {"name": "maradns", "image": "lab-recon/maradns", "kind": "maradns",
     "mount": "/etc/maradns/dwood3rc", "entrypoint": "Deadwood",
     "start": ["-f", "/etc/maradns/dwood3rc"],
     "version_run": ["run", "--rm", "--entrypoint", "Deadwood", "lab-recon/maradns", "--version"],
     "modes": ["forward"], "p3_harden": ["default"], "forwarder_only": True,
     "note": "MaraDNS Deadwood is a forwarder: P2/P3 N/A (run, not counted)"},
]


P5_KIND_FILTER = None
P5_TYPE_FILTER = None


def variants_for(row, pattern):
    if pattern == "p5":
        out = [{"owner_kind": "out-of-zone", "ns_target": "n/a",
                "harden_unverified_glue": "default", "unsolicited_type": "A"}]
        for kind in ("different-zone", "same-server-diff-tree"):
            for rtype in ("A", "AAAA", "NS"):
                out.append({"owner_kind": kind, "ns_target": "n/a",
                            "harden_unverified_glue": "default", "unsolicited_type": rtype})
        if P5_KIND_FILTER:
            out = [v for v in out if v.get("owner_kind") in P5_KIND_FILTER]
        if P5_TYPE_FILTER:
            out = [v for v in out if v.get("unsolicited_type", "A") in P5_TYPE_FILTER]
        return out
    if pattern != "p3":
        return [{"ns_target": "n/a", "harden_unverified_glue": "default"}]
    out = []
    for harden in row.get("p3_harden", ["default"]):
        for target in ("reachable", "unreachable"):
            out.append({"ns_target": target, "harden_unverified_glue": harden})
    return out


def cell_id(resolver, mode, pattern, variant):
    parts = [resolver, mode, pattern]
    if pattern == "p5":
        parts.append("owner-" + variant.get("owner_kind", "out-of-zone"))
        if variant.get("unsolicited_type", "A") != "A":
            parts.append("type-" + variant["unsolicited_type"])
    if pattern == "p3":
        parts.append("ns-" + variant["ns_target"])
        if variant.get("harden_unverified_glue") not in (None, "default"):
            parts.append("harden-" + variant["harden_unverified_glue"])
    return "-".join(parts)


# ------------------------- probe execution -------------------------

def build_plan(lab, pattern, server, port, trigger=None, target=None, probe_qtype="A"):
    """Prime-then-probe ordering: the trigger query primes the crafted response
    FIRST; the probed third-party name is queried only afterwards and was never
    queried before, so a cached acceptance can surface.  The path-validation
    query uses a different random name so it cannot mask the probe."""
    target = target or lab.target
    trigger = trigger or lab.trigger_for(pattern)
    return {
        "server": server, "port": port,
        "queries": [
            {"key": "baseline", "name": lab.baseline_name, "qtype": "A", "rd": True, "timeout": 6,
             "retry_until": {"answer_contains": lab.true_tp_addr, "deadline_s": 30, "interval_s": 1}},
            {"key": "trigger", "name": trigger, "qtype": "A", "rd": True,
             "timeout": 15},
            {"key": "probe1", "name": target, "qtype": probe_qtype, "rd": True, "timeout": 8},
            {"sleep": 3},
            {"key": "probe2", "name": target, "qtype": probe_qtype, "rd": True, "timeout": 8},
            {"key": "probe3", "name": target, "qtype": probe_qtype, "rd": False, "timeout": 6},
        ],
    }


def execute_plan(plan, docker=None):
    payload = json.dumps(plan)
    if docker is None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(HERE.parent.parent / "vendor")
        r = subprocess.run([sys.executable, str(HERE / "probe_client.py")],
                           input=payload, capture_output=True, text=True, timeout=180, env=env)
    else:
        r = subprocess.run(["docker", "exec", "-i", "labmx-probe",
                            "python3", "/lab/probe_client.py"],
                           input=payload, capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        return {"error": "probe_client failed: " + (r.stderr or r.stdout)[-500:]}
    try:
        return json.loads(r.stdout)
    except Exception as exc:
        return {"error": "bad probe_client output: %s: %s" % (exc, r.stdout[-500:])}


# ------------------------- verdicts -------------------------

def judge(lab, pattern, variant, plan_out, counts, target=None, endpoint_logs=False,
          probe_type="A", poison_value=None):
    poison = poison_value if poison_value is not None else lab.poison_for(pattern, variant)
    target = norm(target or lab.target)
    results = plan_out.get("results", {})
    probes = [results.get("probe1"), results.get("probe2"), results.get("probe3")]
    # only the recursive probes (probe1/probe2) decide the cache axis; the rd=0
    # probe is supplementary (resolvers may REFUSE non-recursive queries even
    # for cached names, which is no evidence either way)
    rd_probes = [p for p in probes if p and p.get("rd")]
    notes = []
    ttl_evidence = []
    cache = "INCONCLUSIVE"
    poison_seen = False
    true_seen = False
    for idx, p in enumerate(probes, start=1):
        if not p or not p.get("ok"):
            continue
        ips = [r for r in p["answer"] if r["owner"] == target and r["type"] == probe_type]
        ttl_evidence.append({"probe": "probe%d" % idx, "rd": p.get("rd"),
                             "answers": ips, "rcode": p.get("rcode")})
        for r in ips:
            if norm(r["data"]) == norm(poison):
                poison_seen = True
            elif probe_type == "A" and r["data"] == lab.true_tp_addr:
                true_seen = True
    if poison_seen:
        cache = "CACHE-AND-ANSWER"
    elif true_seen:
        cache = "REJECT"
        notes.append("third-party name still resolves to the true address")
    elif rd_probes and all((p.get("ok") and p.get("rcode") in ("NXDOMAIN", "NOERROR"))
                           for p in rd_probes):
        cache = "REJECT"
        notes.append("third-party name does not return the unrelated A")

    trigger = results.get("trigger") or {}
    trig_answers = [r["data"] for r in trigger.get("answer", []) if r["type"] == "A"]
    counts = counts or {}
    used_poison = (lab.fake_marker in trig_answers or counts.get("fake_ns", 0) > 0
                   or counts.get("drop", 0) > 0)
    used_real = (lab.true_marker in trig_answers or counts.get("true_ns", 0) > 0)
    if not PATTERN_INFO[pattern]["load_bearing"]:
        # p1/p2/p4: the third-party name is not part of the resolution chain,
        # so there is nothing to use; the endpoint counts still show which
        # endpoint answered the trigger.
        use = "N/A"
    elif used_poison:
        use = "USE-FOR-RESOLUTION"
    elif used_real:
        use = "RE-RESOLVE-REAL"
    elif endpoint_logs and not used_poison:
        use = "NOT-USED-NO-FOLLOW"
        notes.append("trigger resolution failed but endpoint logs are conclusive: "
                     "no query reached the poison endpoint")
    elif trigger.get("rcode") in ("SERVFAIL",) or not trigger.get("ok"):
        use = "UNKNOWN"
        notes.append("trigger resolution failed; glue use not observable (host mode has "
                     "no endpoint logs)")
    else:
        use = "NOT-USED-NO-FOLLOW"

    if cache == "CACHE-AND-ANSWER":
        verdict = "CACHE-AND-ANSWER"
    elif use == "USE-FOR-RESOLUTION":
        verdict = "USE-FOR-RESOLUTION-ONLY"
    elif use == "RE-RESOLVE-REAL":
        verdict = "RE-RESOLVE-REAL"
    elif cache == "REJECT":
        verdict = "REJECT"
    else:
        verdict = "INCONCLUSIVE"
    return {"cache_verdict": cache, "use_verdict": use, "verdict": verdict,
            "ttl_evidence": ttl_evidence, "notes": notes}


# ------------------------- config assembly -------------------------

def config_candidates(kind, lab, mode, provider, tp, sink_ip, iface, hints_path,
                      harden_unverified_glue, do_localhost):
    """Return (config_text, note) candidates, richest first."""
    out = []
    if kind == "unbound":
        out.append((unbound_conf(lab, mode, provider, tp, sink_ip, iface,
                                 harden_unverified_glue, hints_path, do_localhost), "full"))
        out.append((unbound_conf(lab, mode, provider, tp, sink_ip, iface, harden_unverified_glue,
                                 hints_path, do_localhost).replace("    qname-minimisation: no\n", ""),
                    "reduced"))
    elif kind == "bind":
        out.append((bind_conf(lab, provider, tp, sink_ip, hints_path), "static-stub"))
        out.append((bind_conf_fallback(lab, provider, tp, sink_ip, hints_path), "stub+forward"))
    elif kind == "dnsmasq":
        out.append((dnsmasq_conf(lab, provider, tp), "forward"))
    elif kind == "kresd":
        out.append((kresd_conf(lab, provider, tp), "stub-policy"))
    elif kind == "pdns":
        out.append((pdns_conf(lab, provider, tp, hints_path), "forward-zones-yaml"))
    elif kind == "pdns-classic":
        out.append((pdns_conf_classic(lab, provider, tp), "forward-zones-classic"))
    elif kind == "coredns":
        out.append((coredns_conf(lab, provider, tp), "forward"))
    elif kind == "maradns":
        out.append((maradns_conf(lab, provider, tp), "forward"))
    else:
        raise ValueError("unknown resolver kind " + kind)
    return out


# ------------------------- cell execution -------------------------

def run_cell(ctx, row, mode, pattern, variant):
    lab = ctx.lab
    cid = cell_id(row["name"], mode, pattern, variant)
    rnd = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    trigger_name = "w%s.%s" % (rnd, lab.zone if PATTERN_INFO[pattern]["trigger"] == "in-zone"
                               else lab.child_zone)
    if pattern == "p5" and variant.get("owner_kind") == "different-zone":
        # unsolicited owner inside the provider's zone tree but in a DIFFERENT
        # zone than the queried child zone
        target_name = "b%s.%s" % (rnd, lab.zone)
    elif pattern == "p5" and variant.get("owner_kind") == "same-server-diff-tree":
        # task-15: unsolicited owner in ANOTHER TREE served by the same server
        # (shared-hosting cross-tenant axis)
        target_name = "b%s.%s" % (rnd, lab.zone2)
    else:
        target_name = "n%s.%s" % (rnd, lab.tp_zone)
    probe_type = (variant.get("unsolicited_type") or "A").upper()
    if probe_type == "AAAA":
        poison_value = lab.poison_aaaa
    elif probe_type == "NS":
        poison_value = lab.poison_ns
    else:
        poison_value = lab.poison_for(pattern, variant)
    cell = {
        "id": cid, "resolver": row["name"], "runner": row["runner"],
        "resolver_version": ctx.versions.get(row["name"], "?"), "mode": mode,
        "pattern": pattern, "pattern_shape": PATTERN_INFO[pattern]["shape"],
        "variant": dict(variant),
        "counted": not (row.get("forwarder_only") and pattern in ("p2", "p3")),
        "trigger_name": trigger_name, "third_party_name": target_name,
        "poison_address": poison_value,
        "true_third_party_address": lab.true_tp_addr,
        "config_note": "", "errors": [],
    }
    if not cell["counted"]:
        cell["notes"] = ["forwarder row: referral shapes are N/A (run for evidence, not counted)"]
    else:
        cell["notes"] = []
    t0 = time.time()
    provider_t0 = t0
    candidates = ctx.configs_for(row, lab, mode, variant)
    for config_text, note in candidates:
        cell["config"] = config_text
        cell["config_note"] = note
        try:
            if row["runner"] == "host":
                ctx.fixtures.start_provider(pattern, variant, cid, target=target_name,
                                              ptype=probe_type)
                provider_t0 = time.time()
                server, port = ctx.start_host_resolver(row, mode, variant, config_text, cid)
            else:
                ctx.fixtures.start_provider(pattern, variant, target=target_name,
                                              ptype=probe_type)
                provider_t0 = time.time()
                server, port = ctx.start_docker_resolver(row, config_text, cid), 53
        except Exception as exc:
            cell["errors"].append("resolver start failed (%s): %s" % (note, exc))
            continue
        plan = build_plan(lab, pattern, server, port, trigger=trigger_name, target=target_name,
                          probe_qtype=probe_type)
        plan_out = execute_plan(plan, docker=ctx.docker if row["runner"] == "docker" else None)
        if "error" in plan_out:
            cell["errors"].append(plan_out["error"])
            ctx.stop_resolver(row)
            continue
        results = plan_out.get("results", {})
        baseline = results.get("baseline") or {}
        if not (baseline.get("ok") and any(r["data"] == lab.true_tp_addr
                                           for r in baseline.get("answer", []))):
            cell["errors"].append("baseline failed with config %s: %s"
                                  % (note, json.dumps(baseline)[:300]))
            if row["runner"] == "docker":
                cell.setdefault("resolver_log_tail", ctx.docker.logs("labmx-resolver")[-1500:])
            ctx.stop_resolver(row)
            continue
        counts = ctx.counts(provider_t0)
        cell["baseline"] = baseline
        cell["trigger"] = results.get("trigger")
        cell["probes"] = [results.get("probe1"), results.get("probe2"), results.get("probe3")]
        cell["endpoint_queries"] = counts
        cell.update(judge(lab, pattern, variant, plan_out, counts, target=target_name,
                          endpoint_logs=(row["runner"] == "docker"),
                          probe_type=probe_type, poison_value=poison_value))
        ctx.stop_resolver(row)
        return cell
    cell["verdict"] = "ERROR" if cell["errors"] else "INCONCLUSIVE"
    cell.setdefault("cache_verdict", "INCONCLUSIVE")
    cell.setdefault("use_verdict", "UNKNOWN")
    cell.setdefault("ttl_evidence", [])
    ctx.stop_resolver(row)
    return cell


class Context:
    def __init__(self, lab, docker, fixtures, workdir, versions, rows_by_name):
        self.lab = lab
        self.docker = docker
        self.fixtures = fixtures
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.versions = versions
        self.rows_by_name = rows_by_name
        self.hints_host = str(self.workdir / "lab-hints")
        root_hints(self.hints_host, lab.drop_ip if lab.runner == "docker" else "127.0.0.9")
        self._host_proc = None
        self._host_port = free_port()

    def configs_for(self, row, lab, mode, variant):
        harden = variant.get("harden_unverified_glue", "default")
        harden = "no" if harden == "default" else harden
        if row["runner"] == "host":
            self._host_port = free_port()
            iface = "127.0.0.1@" + str(self._host_port)
            provider, tp = "127.0.0.1@" + str(lab.provider_port), "127.0.0.1@" + str(lab.tp_port)
            hints = self.hints_host
            sink = "127.0.0.9"
            do_localhost = True
        else:
            iface = "0.0.0.0@53"
            provider, tp = lab.provider_ip, lab.tp_ip
            hints = "/lab-hints"
            sink = lab.drop_ip
            do_localhost = False
        return config_candidates(row["kind"], lab, mode, provider, tp, sink, iface, hints,
                                 harden, do_localhost)

    def start_host_resolver(self, row, mode, variant, config_text, cid):
        conf = self.workdir / (cid + ".conf")
        conf.write_text(config_text, encoding="utf-8")
        log = open(self.workdir / (cid + ".out"), "ab")
        env = dict(os.environ)
        self._host_proc = subprocess.Popen([row["binary"], "-d", "-c", str(conf)],
                                           stdout=log, stderr=log, env=env)
        time.sleep(1.0)
        if self._host_proc.poll() is not None:
            raise RuntimeError("unbound exited: " + (self.workdir / (cid + ".out")).read_text()[-400:])
        return "127.0.0.1", int(config_text.split("interface: 127.0.0.1@")[1].split("\n")[0])

    def start_docker_resolver(self, row, config_text, cid):
        conf = self.workdir / (cid + ".conf")
        conf.write_text(config_text, encoding="utf-8")
        copies = [(str(conf), row["mount"])]
        if row["kind"] in ("bind", "unbound"):
            copies.append((self.hints_host, "/lab-hints"))
        self.docker.rm("labmx-resolver")
        self.docker.start("labmx-resolver", [row["image"]] + row.get("start", []),
                          ip="10.77.0.50", copies=copies,
                          entrypoint=row.get("entrypoint") or None)
        time.sleep(1.2)
        if not self.docker.running("labmx-resolver"):
            tail = self.docker.logs("labmx-resolver")[-600:]
            raise RuntimeError("resolver container exited: " + tail)
        return "10.77.0.50"

    def stop_resolver(self, row):
        if row["runner"] == "host":
            proc = self._host_proc
            self._host_proc = None
            if proc and proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        else:
            self.docker.rm("labmx-resolver")

    def counts(self, since):
        if isinstance(self.fixtures, LocalFixtures):
            return {"provider": self.fixtures.query_count("provider", since),
                    "thirdparty": self.fixtures.query_count("tp", since),
                    "true_ns": 0, "fake_ns": 0, "drop": 0}
        return self.fixtures.counts(since)


# ------------------------- shape checks (offline) -------------------------

def check_shape(lab, fixtures, pattern, tag=None):
    variant = {"ns_target": "n/a", "harden_unverified_glue": "default"}
    poison = lab.poison_for(pattern, variant)
    out = {"pattern": pattern, "shape": PATTERN_INFO[pattern]["shape"], "checks": [], "ok": True}

    def check(what, cond, detail=""):
        out["checks"].append({"what": what, "ok": bool(cond), "detail": detail})
        if not cond:
            out["ok"] = False

    fixtures.start_provider(pattern, variant, tag or ("shape-" + pattern), target=lab.target,
                            ptype=getattr(lab, "third_party_type", "A"))
    if not fixtures.ready("provider", timeout=15):
        check("fixture starts", False, "provider fixture did not start")
        return out
    if not fixtures.ready("tp", timeout=15):
        check("third-party fixture starts", False, "third-party fixture did not start")
        return out
    trig = lab.trigger_for(pattern)
    res = dns_query("127.0.0.1", lab.provider_port, trig)
    out["trigger_response"] = res
    check("trigger answers NOERROR", res.get("ok") and res.get("rcode") == "NOERROR",
          json.dumps(res)[:300])
    if not res.get("ok"):
        return out
    ans = [(r["owner"], r["type"], r["data"], r["ttl"]) for r in res["answer"]]
    auth = [(r["owner"], r["type"], r["data"], r["ttl"]) for r in res["authority"]]
    add = [(r["owner"], r["type"], r["data"], r["ttl"]) for r in res["additional"]]
    child_ns = "ns.true." + lab.zone
    if pattern == "p1":
        check("answer section: A for trigger", ("A", lab.true_tp_addr) in
              [(r["type"], r["data"]) for r in res["answer"]] and res["aa"] is True, str(ans))
        check("ADDITIONAL: unrelated A for third-party name",
              [(r["owner"], r["type"], r["data"]) for r in res["additional"]] ==
              [(lab.target, "A", poison)], str(add))
        check("ADDITIONAL TTL = %d" % lab.ttl,
              [r["ttl"] for r in res["additional"]] == [lab.ttl], str(add))
    elif pattern == "p2":
        check("referral (aa=0, one NS in AUTHORITY)",
              res["aa"] is False and
              [(r["owner"], r["type"], norm(r["data"])) for r in res["authority"]] ==
              [(lab.child_zone, "NS", norm(child_ns))], str(auth))
        check("ADDITIONAL: unrelated A for third-party name",
              [(r["owner"], r["type"], r["data"]) for r in res["additional"]] ==
              [(lab.target, "A", poison)], str(add))
    elif pattern == "p3":
        check("referral (aa=0, external NS in AUTHORITY; owner = queried name)",
              res["aa"] is False and
              [(r["owner"], r["type"], norm(r["data"])) for r in res["authority"]] ==
              [(norm(trig), "NS", norm(lab.target))], str(auth))
        check("ADDITIONAL: delegation glue A for the NS name",
              [(r["owner"], r["type"], r["data"]) for r in res["additional"]] ==
              [(lab.target, "A", poison)], str(add))
        refused = dns_query("127.0.0.1", lab.provider_port, lab.target)
        check("provider holds no data for the external NS name (REFUSED)",
              refused.get("ok") and refused.get("rcode") == "REFUSED", json.dumps(refused)[:300])
        tp = dns_query("127.0.0.1", lab.tp_port, lab.target)
        check("third-party authority serves the true address",
              tp.get("ok") and answer_ips(tp, lab.target) == [lab.true_tp_addr],
              json.dumps(tp)[:300])
    elif pattern == "p4":
        check("answer section: A for trigger + unrelated owner record",
              res["aa"] is True and
              [(r["owner"], r["type"], r["data"]) for r in res["answer"]] ==
              [(norm(trig), "A", lab.true_tp_addr), (lab.target, "A", poison)], str(ans))
        check("no ADDITIONAL records", res["additional"] == [], str(add))
        check("unrelated owner TTL = %d" % lab.ttl,
              [r["ttl"] for r in res["answer"] if r["owner"] == norm(lab.target)] == [lab.ttl],
              str(ans))
    elif pattern == "p5":
        # task-14 / CVE-2025-40778 axis: forged successful answer with an
        # unsolicited RR in the ANSWER section (owner chosen by the harness:
        # outside the answering server's zone, in a different zone, or in
        # another tree served by the same server; type A/AAAA/NS)
        ptype = getattr(lab, "third_party_type", "A")
        pvalue = poison
        if ptype == "AAAA":
            pvalue = getattr(lab, "poison_aaaa", pvalue)
        elif ptype == "NS":
            pvalue = getattr(lab, "poison_ns", pvalue)
        unsol = [r for r in res["answer"] if r["owner"] == norm(lab.target)]
        shape_ok = ([(r["owner"], r["type"]) for r in res["answer"]] ==
                    [(norm(trig), "A"), (norm(lab.target), ptype)]) and len(unsol) == 1 \
            and norm(unsol[0]["data"]) == norm(pvalue)
        check("forged successful answer (aa=1) with unsolicited %s owner in ANSWER" % ptype,
              res["aa"] is True and shape_ok, str(ans))
        check("unsolicited owner TTL = %d" % lab.ttl,
              [r["ttl"] for r in unsol] == [lab.ttl], str(ans))
    return out


def run_shape(args):
    lab = Lab(seed=args.seed, runner="host")
    workdir = Path(args.out_dir) / (args.label + ".shape")
    fixtures = LocalFixtures(lab, workdir)
    results = []
    try:
        fixtures.start_static("shape")
        for pattern in args.patterns:
            if pattern == "p5":
                for kind, tgt, rtype in (
                        ("out-of-zone", lab.target, "A"),
                        ("different-zone", "b" + lab.seed[:4] + "." + lab.zone, "A"),
                        ("same-server-diff-tree-A", "b" + lab.seed[:4] + "." + lab.zone2, "A"),
                        ("same-server-diff-tree-AAAA", "b" + lab.seed[:4] + "." + lab.zone2, "AAAA"),
                        ("same-server-diff-tree-NS", "b" + lab.seed[:4] + "." + lab.zone2, "NS")):
                    lab2 = copy.copy(lab)
                    lab2.target = tgt
                    lab2.third_party_type = rtype
                    res = check_shape(lab2, fixtures, pattern, tag="shape-p5-" + kind)
                    res["owner_kind"] = kind
                    results.append(res)
            else:
                results.append(check_shape(lab, fixtures, pattern))
    finally:
        fixtures.stop_all()
    ok = all(r["ok"] for r in results)
    print(json.dumps({"mode": "shape", "lab": lab.describe(), "patterns": results,
                      "ok": ok}, indent=2))
    print("shape check:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ------------------------- writers -------------------------

def write_json(path, payload):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")


SHORT = {"CACHE-AND-ANSWER": "ACCEPT(cache)", "USE-FOR-RESOLUTION-ONLY": "USE",
         "RE-RESOLVE-REAL": "RE-RESOLVE-REAL", "REJECT": "REJECT",
         "INCONCLUSIVE": "INCONCL", "ERROR": "ERROR", None: "-"}


def write_md(path, payload):
    lines = []
    lines.append("# ADDITIONAL/bailiwick acceptance matrix -- " + payload["label"])
    lines.append("")
    lines.append("Generated " + payload["generated_at"] +
                 " by probe_matrix.py (lab-only: loopback + isolated docker")
    lines.append("network; no query left the lab).  Machine-readable evidence: "
                 + payload["label"] + ".json.")
    lines.append("")
    lines.append("## Lab namespace")
    lines.append("")
    labs = ([('lab', payload['lab'])] if payload.get('lab') else
            [('host', payload.get('lab_host', {})), ('docker', payload.get('lab_docker', {}))])
    for tag, lab in labs:
        for key, val in lab.items():
            lines.append("- %s.%s: %s" % (tag, key, val))
    lines.append("")
    lines.append("## Verdicts")
    lines.append("")
    lines.append("| verdict | meaning |")
    lines.append("| --- | --- |")
    lines.append("| ACCEPT (CACHE-AND-ANSWER) | an independent later query for the third-party name returns the unrelated A (cached AND answerable) |")
    lines.append("| USE-FOR-RESOLUTION-ONLY | the unrelated A steered the trigger resolution (fake endpoint answered/was queried) but is not returned as an answer later |")
    lines.append("| RE-RESOLVE-REAL | the unrelated A was ignored: the NS name was re-resolved and the real endpoint answered the trigger |")
    lines.append("| REJECT | neither: the unrelated A is not persisted and did not steer resolution |")
    lines.append("| N/A | pattern not applicable to this resolver (forwarder: no referral path) |")
    lines.append("| INCONCLUSIVE/ERROR | the run produced no usable evidence (see cell evidence) |")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| resolver | version | mode | P1 | P2 | P3 glue-reachable | P3 glue-unreachable | P4 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    rows = {}
    for cell in payload["cells"]:
        key = (cell["resolver"], cell["mode"])
        rows.setdefault(key, {"version": cell["resolver_version"], "cells": []})["cells"].append(cell)
    for (res, mode), info in rows.items():
        cols = {}
        for cell in info["cells"]:
            label = ("N/A" if not cell.get("counted")
                     else SHORT.get(cell.get("verdict"), str(cell.get("verdict"))))
            if cell["pattern"] == "p3":
                extra = cell["variant"].get("harden_unverified_glue")
                if extra not in (None, "default"):
                    label += " (harden-%s)" % extra
                cols.setdefault("p3", {}).setdefault(cell["variant"].get("ns_target"), []).append(label)
            else:
                cols[cell["pattern"]] = label

        def p3col(ns):
            vals = cols.get("p3", {}).get(ns)
            return " / ".join(vals) if vals else "-"
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |"
                     % (res, info["version"], mode, cols.get("p1", "-"), cols.get("p2", "-"),
                        p3col("reachable"), p3col("unreachable"), cols.get("p4", "-")))
    lines.append("")
    if payload.get("failures"):
        lines.append("## Setup failures")
        lines.append("")
        for f in payload["failures"]:
            lines.append("- " + f)
        lines.append("")
    lines.append("## Per-cell evidence")
    lines.append("")
    for cell in payload["cells"]:
        lines.append("### %s -- verdict %s" % (cell["id"], cell.get("verdict")))
        lines.append("")
        lines.append("- resolver: %s (%s) via %s, config variant %s, counted=%s"
                     % (cell["resolver"], cell["resolver_version"], cell["mode"],
                        cell.get("config_note"), cell.get("counted")))
        lines.append("- trigger %s; third-party name %s; poison address %s"
                     % (cell["trigger_name"], cell["third_party_name"], cell["poison_address"]))
        trig = cell.get("trigger") or {}
        if trig.get("ok"):
            lines.append("- trigger response: rcode=%s aa=%s answer=[%s] authority=[%s] additional=[%s]"
                         % (trig.get("rcode"), trig.get("aa"), section_text(trig.get("answer", [])),
                            section_text(trig.get("authority", [])), section_text(trig.get("additional", []))))
        else:
            lines.append("- trigger response: " + json.dumps(trig)[:300])
        base = cell.get("baseline") or {}
        if base.get("ok"):
            lines.append("- baseline (before priming): rcode=%s answer=[%s]"
                         % (base.get("rcode"), section_text(base.get("answer", []))))
        for idx, probe in enumerate(cell.get("probes") or [], start=1):
            if not probe:
                lines.append("- probe%d: (missing)" % idx)
                continue
            if probe.get("ok"):
                lines.append("- probe%d (rd=%s): rcode=%s answer=[%s]"
                             % (idx, probe.get("rd"), probe.get("rcode"),
                                section_text(probe.get("answer", []))))
            else:
                lines.append("- probe%d: %s" % (idx, json.dumps(probe)[:200]))
        lines.append("- TTL evidence: " + json.dumps(cell.get("ttl_evidence", [])))
        lines.append("- endpoint query counts since priming: " + json.dumps(cell.get("endpoint_queries", {})))
        lines.append("- cache dimension: %s; use dimension: %s"
                     % (cell.get("cache_verdict"), cell.get("use_verdict")))
        if cell.get("notes"):
            lines.append("- notes: " + "; ".join(cell["notes"]))
        if cell.get("errors"):
            lines.append("- errors: " + "; ".join(cell["errors"]))
        if cell.get("resolver_log_tail"):
            lines.append("- resolver log tail: " +
                         cell["resolver_log_tail"].replace("\n", " | ")[:400])
        lines.append("")
    if payload.get("method_notes"):
        lines.append("## Method notes / limitations")
        lines.append("")
        for n in payload["method_notes"]:
            lines.append("- " + n)
        lines.append("")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines), encoding="utf-8")


# ------------------------- matrix runner -------------------------

HOST_ROW = {"name": "unbound-local", "runner": "host", "kind": "unbound",
            "binary": "/opt/homebrew/sbin/unbound", "modes": ["stub", "forward"],
            "p3_harden": ["yes", "no"],
            "note": "host Unbound on loopback; endpoint follow-up (use dimension) not "
                    "observable without privileged port 53"}


def select_rows(wanted, failures):
    rows = []
    want = set(wanted)
    if not want:
        failures.append("no resolvers selected")
    if want & {"all", "host", "unbound-local"}:
        if Path(HOST_ROW["binary"]).exists():
            rows.append(dict(HOST_ROW))
        else:
            failures.append("unbound-local: binary %s not found" % HOST_ROW["binary"])
    if want & {"all", "docker"} or (want & {r["name"] for r in DOCKER_ROWS}):
        for row in DOCKER_ROWS:
            if want & {"all", "docker"} or row["name"] in want:
                rows.append(dict(row, runner="docker"))
    return rows


def ensure_docker_images(docker, rows, failures):
    """Build the fixture/probe image (always: the lab code is baked in, so a
    stale image would silently serve stale patterns); verify resolver images."""
    r = docker.run(["build", "-f", str(HERE / "docker" / "Dockerfile.fixture"),
                    "-t", "lab-mx/fixture", str(HERE.parent.parent)], timeout=900)
    if r.returncode != 0:
        failures.append("fixture image build failed: " + r.stderr.strip()[:400])
        return
    for row in rows:
        if row["runner"] == "docker" and not docker.image(row["image"]):
            failures.append("resolver %s: image %s unavailable (build/pull it first); cells skipped"
                            % (row["name"], row["image"]))


def docker_version(docker, row):
    try:
        return docker.version_run(row["version_run"])
    except Exception as exc:
        return "version unavailable: %s" % exc


def run_matrix(args):
    failures = []
    cells = []
    rows = select_rows(args.resolvers, failures)
    versions = {}
    vendor = HERE.parent.parent / "vendor"
    lab_host = Lab(seed=args.seed, runner="host")
    lab_docker = Lab(seed=args.seed, runner="docker")
    workdir = Path(args.out_dir) / (args.label + ".run")
    workdir.mkdir(parents=True, exist_ok=True)

    host_rows = [r for r in rows if r["runner"] == "host"]
    docker_rows = [r for r in rows if r["runner"] == "docker"]
    prio = {"bind9-pre": 0, "bind9-post": 1, "bind9-9.20.15": 2, "unbound": 3,
            "pdns-recursor": 4, "pdns-recursor-4.9": 5, "dnsmasq": 6,
            "knot-resolver": 7, "coredns": 8, "maradns": 9}
    docker_rows.sort(key=lambda r: prio.get(r["name"], 99))

    # ---- host phase (loopback) ----
    if host_rows:
        fixtures = LocalFixtures(lab_host, workdir)
        fixtures.start_static("static")
        if not fixtures.ready("tp", timeout=8):
            failures.append("host fixtures failed to start")
        for row in host_rows:
            try:
                versions[row["name"]] = subprocess.run([row["binary"], "-V"],
                                                       capture_output=True, text=True,
                                                       timeout=30).stdout.splitlines()[0][:200]
            except Exception as exc:
                versions[row["name"]] = "version unavailable: %s" % exc
        ctx = Context(lab_host, None, fixtures, workdir, versions, {})
        try:
            for row in host_rows:
                for mode in row["modes"]:
                    for pattern in args.patterns:
                        for variant in variants_for(row, pattern):
                            cell = run_cell(ctx, row, mode, pattern, variant)
                            cells.append(cell)
                            print("[%d] %s -> %s" % (len(cells), cell["id"],
                                                     cell.get("verdict")), flush=True)
        finally:
            fixtures.stop_all()

    # ---- docker phase (isolated network) ----
    if docker_rows:
        docker = Docker()
        ok, info = docker.available()
        if not ok:
            failures.append("docker daemon unavailable: " + str(info)[:300])
            for row in docker_rows:
                for mode in row["modes"]:
                    for pattern in args.patterns:
                        for variant in variants_for(row, pattern):
                            cells.append({"id": cell_id(row["name"], mode, pattern, variant),
                                          "resolver": row["name"], "runner": "docker",
                                          "resolver_version": "?", "mode": mode,
                                          "pattern": pattern, "variant": dict(variant),
                                          "pattern_shape": PATTERN_INFO[pattern]["shape"],
                                          "counted": True, "verdict": "ERROR",
                                          "cache_verdict": "INCONCLUSIVE",
                                          "use_verdict": "UNKNOWN", "ttl_evidence": [],
                                          "trigger_name": lab_docker.trigger_for(pattern),
                                          "third_party_name": lab_docker.target,
                                          "poison_address": lab_docker.poison_for(pattern, variant),
                                          "true_third_party_address": lab_docker.true_tp_addr,
                                          "notes": [], "errors": ["docker daemon unavailable"],
                                          "endpoint_queries": {}})
        else:
            versions["docker"] = "server " + str(info)[:60]
            try:
                docker.ensure_network()
                ensure_docker_images(docker, docker_rows, failures)
                available = [r for r in docker_rows if docker.image(r["image"])]
                for row in docker_rows:
                    if not docker.image(row["image"]):
                        failures.append("resolver %s: image %s unavailable; cells skipped"
                                        % (row["name"], row["image"]))
                if docker.image("technitium/dns-server"):
                    failures.append("technitium/dns-server: NOT RUN -- configuration requires an "
                                    "interactive web-API bootstrap (admin userCreate + "
                                    "settings/setForwarders) that this harness cannot automate; "
                                    "image is present for future runs")
                else:
                    failures.append("technitium/dns-server: image not available in this lab VM; row NOT RUN")
                for row in available:
                    versions[row["name"]] = docker_version(docker, row)
                fixtures = DockerFixtures(docker, lab_docker, "lab-mx/fixture")
                fixtures.start_static()
                docker.start("labmx-probe", ["lab-mx/fixture", "3600"], entrypoint="sleep")
                ctx = Context(lab_docker, docker, fixtures, workdir, versions, {})
                try:
                    for row in available:
                        for mode in row["modes"]:
                            for pattern in args.patterns:
                                for variant in variants_for(row, pattern):
                                    cell = run_cell(ctx, row, mode, pattern, variant)
                                    cells.append(cell)
                                    print("[%d] %s -> %s" % (len(cells), cell["id"],
                                                             cell.get("verdict")), flush=True)
                finally:
                    fixtures.stop_all()
                    docker.rm("labmx-probe")
                    if not args.keep:
                        docker.run(["network", "rm", docker.network], timeout=60)
            except Exception as exc:
                failures.append("docker phase aborted: %s: %s" % (type(exc).__name__, exc))

    payload = {
        "label": args.label,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "poc/lab/dns/probe_matrix.py",
        "host": {"uname": " ".join(os.uname()) if hasattr(os, "uname") else sys.platform,
                 "python": sys.version.split()[0]},
        "lab_host": lab_host.describe(), "lab_docker": lab_docker.describe(),
        "resolvers": [{"name": r["name"], "runner": r["runner"], "mode": ",".join(r["modes"]),
                       "version": versions.get(r["name"], "?"), "note": r.get("note", "")}
                      for r in rows],
        "cells": cells, "failures": failures,
        "method_notes": METHOD_NOTES,
        "summary": {"cells": len(cells),
                    "verdicts": {v: sum(1 for c in cells if c.get("verdict") == v)
                                 for v in ("CACHE-AND-ANSWER", "USE-FOR-RESOLUTION-ONLY",
                                           "REJECT", "INCONCLUSIVE", "ERROR")}},
    }
    write_json(Path(args.out_dir) / (args.label + ".json"), payload)
    write_md(Path(args.out_dir) / (args.label + ".md"), payload)
    base = args.out_dir + "/" + args.label
    print("wrote %s.json and %s.md" % (base, base))
    return 0


METHOD_NOTES = [
    "Each cell uses a fresh provider fixture and a fresh resolver instance; the third-party, "
    "true-NS, fake-NS and drop fixtures are shared and their query logs are filtered by timestamp.",
    "CACHE-AND-ANSWER requires an independent later query for the third-party name to return the "
    "unrelated A; TTL decay between probe1/probe2 is recorded as cache evidence.",
    "USE-FOR-RESOLUTION is observed via which endpoint answered the trigger (distinct marker "
    "addresses: true NS returns 192.0.2.10, fake NS returns 198.51.100.66) and via endpoint "
    "query logs (the drop sink logs attempts to the unreachable glue address).",
    "Host rows: port 53 cannot be bound without privileges, so the 'use' dimension is not "
    "observable in host mode and the p3 glue target is unreachable there (fast-fail).",
    "QNAME minimisation is disabled where the implementation exposes the knob; fixture TTL is 300s.",
    "dnsmasq is a forwarder with no referral path: p2/p3 cells are run for evidence but not counted.",
    "OS stub resolvers (systemd-resolved / macOS / Windows) are not probed: they would forward to "
    "public upstreams, which the lab-only constraint forbids; such rows must be labeled as their "
    "upstream rather than as implementations of their own.",
    "All names are .invalid and freshly randomised per run (seed recorded); nothing is sent to any "
    "public resolver or external host -- docker runs on an --internal network and stray recursion "
    "is redirected to a local sink.",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["matrix", "shape"], default="matrix")
    ap.add_argument("--resolvers", default="all",
                    help="comma list of resolver names, or all/host/docker")
    ap.add_argument("--patterns", default="p1,p2,p3,p4")
    ap.add_argument("--p5-types", default=None,
                    help="comma list of unsolicited record types to run (A,AAAA,NS)")
    ap.add_argument("--p5-kinds", default=None,
                    help="comma list of p5 owner kinds to run (out-of-zone,different-zone,"
                         "same-server-diff-tree); default all")
    ap.add_argument("--label", default=None)
    ap.add_argument("--out-dir", default=str(HERE / "results"))
    ap.add_argument("--seed", default=None)
    ap.add_argument("--keep", action="store_true", help="keep docker network/containers")
    args = ap.parse_args()
    args.label = args.label or ("matrix-" + time.strftime("%Y-%m-%d"))
    global P5_KIND_FILTER, P5_TYPE_FILTER
    if args.p5_kinds:
        P5_KIND_FILTER = set(x.strip() for x in args.p5_kinds.split(",") if x.strip())
    if args.p5_types:
        P5_TYPE_FILTER = set(x.strip().upper() for x in args.p5_types.split(",") if x.strip())
    args.patterns = [p.strip() for p in args.patterns.split(",") if p.strip()]
    for p in args.patterns:
        if p not in PATTERN_INFO:
            ap.error("unknown pattern " + p)
    wanted = [x.strip() for x in args.resolvers.split(",") if x.strip()]
    if wanted == ["host"]:
        wanted = ["unbound-local"]
    args.resolvers = wanted
    if args.mode == "shape":
        return run_shape(args)
    return run_matrix(args)


if __name__ == "__main__":
    sys.exit(main())
