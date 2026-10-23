#!/usr/bin/env python3
"""
probe_iterative.py -- P3 (external-NS delegation glue) over a NON-pre-seeded,
fully iterative resolution path.

Why: in probe_matrix.py the third-party zone owning the forged NS name is
pre-seeded (stub/forward/static-stub), so the NS-name resolution is
stub-mediated.  The public case walks the ITERATIVE path.  This suite removes
all zone seeding: the resolver reaches every zone through normal iteration
from a lab-owned fake root (root-hints -> role root fixture with a --delegate
table).  The forged ADDITIONAL points at an NS name in a zone that is not
pre-seeded anywhere; it is resolvable only via that iteration chain (or the
glue target is unreachable and the fallback is recorded).

Two config variants per resolver:
  seeded     the provider zone is stub/forward-seeded (fast path to the
             poisoned referral), the NS-target zone is NOT seeded,
  iterative  nothing is seeded at all; the whole chain is walked from the
             fake root.

Outcomes per cell (same axes as probe_matrix.py):
  cache dimension  CACHE-AND-ANSWER / REJECT      (prime-then-probe, fresh
                                                   names, TTL evidence),
  use dimension    USE-FOR-RESOLUTION / RE-RESOLVE-REAL / NOT-USED-NO-FOLLOW
                   (endpoint markers + endpoint query logs incl. the drop
                   sink for the unreachable-glue variant).

Lab-only: everything runs on an egress-blocked docker network; stray
recursion lands on the fake root or the logging sink.  No query leaves the lab.
"""
import argparse
import json
import os
import random
import string
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import probe_matrix as pm  # noqa: E402

NET = "lab-dns-iter"
SUBNET = "10.78.0.0/24"
ROOT_IP = "10.78.0.253"
PROVIDER_IP = "10.78.0.10"
TP_IP = "10.78.0.11"
TRUE_NS_IP = "10.78.0.20"
FAKE_NS_IP = "10.78.0.66"
DROP_IP = "10.78.0.254"
RESOLVER_IP = "10.78.0.50"
TRUE_MARKER = "192.0.2.10"
FAKE_MARKER = "198.51.100.66"
TTL = 300

ROWS = [
    {"name": "bind9-pre", "image": "lab-recon/bind9:9.18.38", "kind": "bind",
     "mount": "/etc/bind/named.conf", "entrypoint": None, "start": [],
     "version_run": ["run", "--rm", "--entrypoint", "named", "lab-recon/bind9:9.18.38", "-v"],
     "variants": ["seeded", "iterative"]},
    {"name": "bind9-post", "image": "lab-recon/bind9:9.18.41", "kind": "bind",
     "mount": "/etc/bind/named.conf", "entrypoint": None, "start": [],
     "version_run": ["run", "--rm", "--entrypoint", "named", "lab-recon/bind9:9.18.41", "-v"],
     "variants": ["seeded", "iterative"]},
    {"name": "bind9-9.20.15", "image": "lab-recon/bind9:9.20.15", "kind": "bind",
     "mount": "/etc/bind/named.conf", "entrypoint": None, "start": [],
     "version_run": ["run", "--rm", "--entrypoint", "named", "lab-recon/bind9:9.20.15", "-v"],
     "variants": ["seeded", "iterative"]},
    {"name": "unbound", "image": "lab-recon/unbound", "kind": "unbound",
     "mount": "/etc/unbound/unbound.conf", "entrypoint": "unbound",
     "start": ["-d", "-c", "/etc/unbound/unbound.conf"],
     "version_run": ["run", "--rm", "--entrypoint", "unbound", "lab-recon/unbound", "-V"],
     "variants": ["seeded", "iterative"]},
    {"name": "pdns-recursor", "image": "lab-recon/pdns", "kind": "pdns",
     "mount": "/etc/pdns/recursor.conf", "entrypoint": "sh",
     "start": ["-c", "mkdir -p /var/run/pdns-recursor && chown recursor /var/run/pdns-recursor; "
               "exec pdns_recursor --daemon=no --config-dir=/etc/pdns"],
     "version_run": ["run", "--rm", "--entrypoint", "pdns_recursor", "lab-recon/pdns", "--version"],
     "variants": ["seeded", "iterative"]},
    {"name": "pdns-recursor-4.9", "image": "lab-recon/pdns-old", "kind": "pdns-classic",
     "mount": "/etc/pdns/recursor.conf", "entrypoint": "sh",
     "start": ["-c", "mkdir -p /var/run/pdns-recursor && chown recursor /var/run/pdns-recursor; "
               "exec pdns_recursor --daemon=no --config-dir=/etc/pdns"],
     "version_run": ["run", "--rm", "--entrypoint", "pdns_recursor", "lab-recon/pdns-old", "--version"],
     "variants": ["seeded", "iterative"]},
]


class IterLab:
    """Iterative namespace: every zone below a lab-owned fake root; the zone
    owning the forged NS name is never pre-seeded anywhere."""

    def __init__(self, seed=None):
        self.seed = seed or "".join(random.choice(string.ascii_lowercase + string.digits)
                                    for _ in range(8))
        r = self.seed
        self.zone = "z%s.nsc" % r
        self.child = "c%s" % r[:4]
        self.child_zone = "%s.%s" % (self.child, self.zone)
        self.tp_zone = "t%s.nsx" % r
        self.target = "ns-%s.%s" % (r[:4], self.tp_zone)   # forged NS name (out of bailiwick)
        self.trigger = "w.%s" % self.child_zone
        self.baseline_name = "b%s.%s" % (r[:4], self.tp_zone)
        self.ttl = TTL
        self.provider_ip = PROVIDER_IP
        self.tp_ip = TP_IP
        self.true_ns_ip = TRUE_NS_IP
        self.fake_ns_ip = FAKE_NS_IP
        self.drop_ip = DROP_IP
        self.true_tp_addr = TRUE_NS_IP          # true A for the forged NS name
        self.true_marker = TRUE_MARKER
        self.fake_marker = FAKE_MARKER
        self.provider_log = "/tmp/provider.jsonl"
        self.delegations = [
            (self.zone, "ns1." + self.zone, PROVIDER_IP),
            (self.tp_zone, "ns1." + self.tp_zone, TP_IP),
        ]

    def poison_for(self, pattern, variant):
        return self.drop_ip if variant.get("ns_target") == "unreachable" else self.fake_ns_ip

    def describe(self):
        return {"seed": self.seed, "runner": "docker-iterative", "zone": self.zone,
                "child_zone": self.child_zone, "tp_zone_unseeded": self.tp_zone,
                "forged_ns_name": self.target, "trigger": self.trigger,
                "true_address_of_forged_ns": self.true_tp_addr, "ttl": self.ttl,
                "root": ROOT_IP, "note": "NS-target zone is not pre-seeded in any resolver config"}


# ------------------------- resolver configs -------------------------

def root_hints(path):
    text = (". 3600000  NS  a.root.lab.invalid.\n"
            "a.root.lab.invalid. 3600000 A " + ROOT_IP + "\n")
    Path(path).write_text(text, encoding="utf-8")
    os.chmod(path, 0o644)
    return text


def unbound_conf(lab, variant):
    lines = [
        "server:",
        "    verbosity: 1",
        "    num-threads: 1",
        "    interface: 0.0.0.0@53",
        "    access-control: 0.0.0.0/0 allow",
        "    do-ip6: no",
        "    username: \"\"",
        "    chroot: \"\"",
        "    pidfile: \"\"",
        "    use-syslog: no",
        "    logfile: \"\"",
        "    module-config: \"iterator\"",
        "    harden-unverified-glue: no",
        "    harden-glue: yes",
        "    aggressive-nsec: no",
        "    qname-minimisation: no",
        "    root-hints: \"/lab-hints\"",
        "    cache-min-ttl: 0",
        "    prefetch: no",
        "    hide-identity: yes",
    ]
    if variant == "seeded":
        lines += [
            "stub-zone:",
            "    name: \"" + lab.zone + "\"",
            "    stub-addr: " + PROVIDER_IP,
            "    stub-prime: no",
        ]
    return "\n".join(lines) + "\n"


def bind_conf(lab, variant):
    lines = [
        "options {",
        "    directory \"/var/cache/bind\";",
        "    listen-on { any; };",
        "    listen-on-v6 { none; };",
        "    recursion yes;",
        "    allow-recursion { any; };",
        "    allow-query { any; };",
        "    dnssec-validation no;",
        "    empty-zones-enable no;",
        "    managed-keys-directory \"/var/cache/bind\";",
        "};",
    ]
    if variant == "seeded":
        lines.append("zone \"" + lab.zone + "\" { type static-stub; server-addresses { "
                     + PROVIDER_IP + "; }; };")
    lines.append("zone \".\" { type hint; file \"/lab-hints\"; };")
    return "\n".join(lines) + "\n"


def pdns_conf(lab, variant):
    lines = [
        "incoming:",
        "  listen:",
        "    - 0.0.0.0:53",
        "  allow_from:",
        "    - 0.0.0.0/0",
        "recursor:",
        "  daemon: false",
        "  socket_dir: /var/run/pdns-recursor",
        "  hint_file: /lab-hints",
    ]
    if variant == "seeded":
        lines += ["  forward_zones:",
                  "    - zone: " + lab.zone,
                  "      forwarders:",
                  "        - " + PROVIDER_IP]
    lines += ["dnssec:", "  validation: \"off\""]
    return "\n".join(lines) + "\n"


def pdns_classic_conf(lab, variant):
    # PowerDNS Recursor: hint-file is ignored in this build (root hints never
    # loaded; baseline SERVFAIL); the working root override is the empty-zone
    # forwarder form forward-zones==<root-ip>, below which pdns iterates
    # referrals normally.  dont-query must be narrowed or pdns refuses to send
    # queries to the RFC1918 lab addresses at all.
    lines = [
        "daemon=no",
        "local-address=0.0.0.0",
        "local-port=53",
        "allow-from=0.0.0.0/0,::/0",
        "dnssec=off",
        "quiet=no",
        "webserver=no",
        "dont-query=127.0.0.0/8",
        "socket-dir=/var/run/pdns-recursor",
        "forward-zones==" + ROOT_IP +
        (("," + lab.zone + "=" + PROVIDER_IP) if variant == "seeded" else ""),
    ]
    return "\n".join(lines) + "\n"


# NOTE: PowerDNS Recursor 5.x YAML 'hint_file' was ignored at run time (baseline
# SERVFAIL against built-in root hints); the classic key=value form with
# hint-file= works on both 5.1.3 and 4.9.5 (verified against 5.1.3 and 4.9.5).
BUILDERS = {"unbound": unbound_conf, "bind": bind_conf,
            "pdns": pdns_classic_conf, "pdns-classic": pdns_classic_conf}


# ------------------------- fixture + resolver control -------------------------

def start_root(docker, lab):
    args = ["lab-mx/fixture", "/lab/lab_dns.py",
            "--role", "root", "--bind", "0.0.0.0", "--port", "53",
            "--zone", ".", "--provider-ns", "a.root.lab.invalid",
            "--true-ip", ROOT_IP, "--fake-ip", lab.drop_ip,
            "--ttl", str(TTL), "--log", "/tmp/q.jsonl"]
    for zone, ns, ip in lab.delegations:
        args += ["--delegate", "%s=%s/%s" % (zone, ns, ip)]
    docker.start("labmx-root", args, ip=ROOT_IP, entrypoint="python3")


def iter_judge(lab, variant, plan_out, counts, target):
    """Cache axis as in probe_matrix; use axis treats a query that reached the
    poison endpoint (fake endpoint or drop sink) as USE-FOR-RESOLUTION."""
    out = pm.judge(lab, "p3", variant, plan_out, counts, target=target, endpoint_logs=True)
    counts = counts or {}
    results = plan_out.get("results", {})
    trig = results.get("trigger") or {}
    trig_answers = [r["data"] for r in trig.get("answer", []) if r["type"] == "A"]
    poison_endpoint_touched = counts.get("fake_ns", 0) > 0 or counts.get("drop", 0) > 0
    if out["cache_verdict"] == "CACHE-AND-ANSWER":
        out["verdict"] = "CACHE-AND-ANSWER"
        return out
    if poison_endpoint_touched or lab.fake_marker in trig_answers:
        out["use_verdict"] = "USE-FOR-RESOLUTION"
        out["verdict"] = "USE-FOR-RESOLUTION-ONLY"
        if lab.fake_marker not in trig_answers:
            out["notes"].append("poison endpoint logged the query but returned no answer "
                                "(unreachable-glue variant): steering decision observed")
    elif out["use_verdict"] == "RE-RESOLVE-REAL":
        out["verdict"] = "RE-RESOLVE-REAL"
    elif out["cache_verdict"] == "REJECT":
        out["verdict"] = "REJECT"
    else:
        out["verdict"] = "INCONCLUSIVE"
    return out


def run_cell(ctx, row, variant, ns_target):
    lab = ctx["lab"]
    docker = ctx["docker"]
    poison = lab.poison_for("p3", {"ns_target": ns_target})
    rnd = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    trigger = "w%s.%s" % (rnd, lab.child_zone)
    target = "ns-%s.%s" % (rnd, lab.tp_zone)
    cid = "%s-%s-p3-ns-%s" % (row["name"], variant, ns_target)
    cell = {"id": cid, "resolver": row["name"], "runner": "docker-iterative",
            "resolver_version": ctx["versions"].get(row["name"], "?"),
            "mode": variant, "pattern": "p3",
            "pattern_shape": "external-NS delegation glue (iterative path, NS-target zone unseeded)",
            "variant": {"ns_target": ns_target, "harden_unverified_glue": "default"},
            "counted": True, "trigger_name": trigger, "third_party_name": target,
            "poison_address": poison, "true_third_party_address": lab.true_tp_addr,
            "notes": [], "errors": []}
    t0 = time.time()
    config = BUILDERS[row["kind"]](lab, variant)
    cell["config"] = config
    try:
        docker.start("labmx-provider", ["lab-mx/fixture", "/lab/lab_dns.py",
                                        "--role", "provider", "--bind", "0.0.0.0", "--port", "53",
                                        "--zone", lab.zone, "--child", lab.child,
                                        "--provider-ns", "ns1." + lab.zone,
                                        "--true-ip", lab.true_tp_addr, "--fake-ip", poison,
                                        "--ttl", str(TTL), "--pattern", "p3",
                                        "--third-party", target, "--third-party-ip", poison,
                                        "--child-ns", target, "--referral-owner", "name",
                                        "--log", "/tmp/provider.jsonl"],
                     ip=PROVIDER_IP, entrypoint="python3")
        time.sleep(0.8)
        conf = Path(ctx["workdir"]) / (cid + ".conf")
        conf.write_text(config, encoding="utf-8")
        os.chmod(conf, 0o644)
        docker.rm("labmx-resolver")
        docker.start("labmx-resolver", [row["image"]] + row.get("start", []),
                     ip=RESOLVER_IP,
                     copies=[(str(conf), row["mount"]), (ctx["hints"], "/lab-hints")],
                     entrypoint=row.get("entrypoint") or None)
        time.sleep(1.5)
        if not docker.running("labmx-resolver"):
            raise RuntimeError("resolver container exited: " + docker.logs("labmx-resolver")[-500:])
        plan = pm.build_plan(lab, "p3", RESOLVER_IP, 53, trigger=trigger, target=target)
        out = pm.execute_plan(plan, docker=docker)
        if "error" in out:
            raise RuntimeError(out["error"])
        results = out.get("results", {})
        baseline = results.get("baseline") or {}
        if not (baseline.get("ok") and any(r["data"] == lab.true_tp_addr
                                           for r in baseline.get("answer", []))):
            raise RuntimeError("iterative baseline failed (fake-root chain broken): %s"
                               % json.dumps(baseline)[:300])
        counts = ctx["fixtures"].counts(t0)
        counts["root"] = count_log(docker, "labmx-root", t0)
        cell["baseline"] = baseline
        cell["trigger"] = results.get("trigger")
        cell["probes"] = [results.get("probe1"), results.get("probe2"), results.get("probe3")]
        cell["endpoint_queries"] = counts
        cell.update(iter_judge(lab, {"ns_target": ns_target}, out, counts, target))
    except Exception as exc:
        cell["errors"].append(str(exc)[:600])
        cell.setdefault("verdict", "ERROR")
        cell.setdefault("cache_verdict", "INCONCLUSIVE")
        cell.setdefault("use_verdict", "UNKNOWN")
        cell.setdefault("ttl_evidence", [])
    finally:
        docker.rm("labmx-resolver")
        docker.rm("labmx-provider")
    return cell


def count_log(docker, name, since):
    text = docker.exec_cat(name, "/tmp/q.jsonl")
    n = 0
    for line in text.splitlines():
        try:
            if json.loads(line).get("ts", 0) >= since:
                n += 1
        except Exception:
            pass
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rows", default="all", help="comma list of resolver names or all")
    ap.add_argument("--label", default="matrix-2026-10-27-iterative")
    ap.add_argument("--out-dir", default=str(HERE / "results"))
    ap.add_argument("--seed", default=None)
    args = ap.parse_args()

    lab = IterLab(seed=args.seed)
    docker = pm.Docker(network=NET, subnet=SUBNET)
    ok, info = docker.available()
    failures = []
    cells = []
    versions = {}
    if not ok:
        print("docker unavailable: %s" % info)
        return 2
    want = set(x.strip() for x in args.rows.split(",")) 
    rows = [r for r in ROWS if want & {"all", r["name"]}]
    docker.ensure_network()
    workdir = Path(args.out_dir) / (args.label + ".run")
    workdir.mkdir(parents=True, exist_ok=True)
    hints = str(workdir / "lab-hints")
    root_hints(hints)
    docker.start("labmx-probe", ["lab-mx/fixture", "3600"], entrypoint="sleep")
    fixtures = pm.DockerFixtures(docker, lab, "lab-mx/fixture")
    fixtures.start_static()
    start_root(docker, lab)
    ctx = {"lab": lab, "docker": docker, "fixtures": fixtures,
           "workdir": str(workdir), "hints": hints, "versions": versions}
    try:
        for row in rows:
            if not docker.image(row["image"]):
                failures.append("%s: image %s unavailable; cells skipped" % (row["name"], row["image"]))
                continue
            versions[row["name"]] = docker.version_run(row["version_run"])
            for variant in row["variants"]:
                for ns_target in ("reachable", "unreachable"):
                    cell = run_cell(ctx, row, variant, ns_target)
                    cells.append(cell)
                    print("[%d] %s -> %s" % (len(cells), cell["id"], cell.get("verdict")),
                          flush=True)
    finally:
        fixtures.stop_all()
        docker.rm("labmx-root")
        docker.rm("labmx-probe")
        docker.run(["network", "rm", NET], timeout=60)

    payload = {
        "label": args.label,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": "poc/lab/dns/probe_iterative.py",
        "suite": "P3 external-NS delegation glue over a NON-pre-seeded iterative path",
        "lab": lab.describe(),
        "resolvers": [{"name": r["name"], "runner": "docker-iterative", "mode": ",".join(r["variants"]),
                       "version": versions.get(r["name"], "?")} for r in rows],
        "cells": cells, "failures": failures,
        "summary": {"cells": len(cells),
                    "verdicts": {v: sum(1 for c in cells if c.get("verdict") == v)
                                 for v in ("CACHE-AND-ANSWER", "USE-FOR-RESOLUTION-ONLY",
                                           "RE-RESOLVE-REAL", "REJECT", "INCONCLUSIVE", "ERROR")}},
        "method_notes": [
            "The zone owning the forged NS name is NOT pre-seeded in any resolver config; it is "
            "reached only by normal iteration from the lab-owned fake root (root-hints -> role root "
            "fixture with a --delegate table).",
            "seeded variant: only the provider (trigger) zone is stub/forward-seeded; "
            "iterative variant: nothing is seeded at all.",
            "prime-then-probe ordering with fresh random trigger and forged-NS names per cell; "
            "the probed name is never queried before priming (O1 fix).",
            "USE-FOR-RESOLUTION is recorded when a query reached the poison endpoint (fake "
            "endpoint, or the logging drop sink for the unreachable-glue variant).",
            "Raw wire hex of every response is captured in the JSON evidence.",
        ],
    }
    pm.write_json(Path(args.out_dir) / (args.label + ".json"), payload)
    pm.write_md(Path(args.out_dir) / (args.label + ".md"), payload)
    print("wrote %s.json" % (args.out_dir + "/" + args.label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
