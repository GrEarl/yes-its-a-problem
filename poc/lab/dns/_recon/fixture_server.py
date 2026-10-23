#!/usr/bin/env python3
"""Minimal authoritative fixture DNS server for lab zones (dnslib-based)."""
import os, sys
sys.path.insert(0, "/vendor")
from dnslib import DNSRecord, QTYPE, RR, A, SOA, NS, RCODE
from dnslib.server import DNSServer, BaseResolver

ZONE = os.environ["ZONE"].strip(".").lower()  # e.g. alpha.test (lowercase compare)
ANSWER_IP = os.environ["ANSWER_IP"]           # A record returned for any name in zone
NS_IP = os.environ.get("NS_IP", ANSWER_IP)    # A record for ns1.<zone>
TTL = 60

class FixtureResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        name = str(qname).strip(".").lower()   # case-insensitive: resolvers may use 0x20 randomization
        reply = request.reply()
        reply.header.aa = 1
        zone = ZONE
        if name == zone or name.endswith("." + zone):
            if qtype in ("SOA", "ANY") and name == zone:
                reply.add_answer(RR(qname, QTYPE.SOA, ttl=TTL,
                    rdata=SOA("ns1." + zone, "hostmaster." + zone,
                              (2026010101, 7200, 3600, 1209600, TTL))))
            if qtype in ("NS", "ANY") and name == zone:
                reply.add_answer(RR(qname, QTYPE.NS, ttl=TTL, rdata=NS("ns1." + zone)))
            if qtype in ("A", "ANY"):
                ip = NS_IP if name == "ns1." + zone else ANSWER_IP
                reply.add_answer(RR(qname, QTYPE.A, ttl=TTL, rdata=A(ip)))
            if not reply.rr:
                reply.header.rcode = RCODE.NXDOMAIN
                reply.add_auth(RR(zone, QTYPE.SOA, ttl=TTL,
                    rdata=SOA("ns1." + zone, "hostmaster." + zone,
                              (2026010101, 7200, 3600, 1209600, TTL))))
        else:
            reply.header.rcode = RCODE.REFUSED
        return reply

if __name__ == "__main__":
    resolver = FixtureResolver()
    udp = DNSServer(resolver, port=53, address="0.0.0.0", tcp=False)
    tcp = DNSServer(resolver, port=53, address="0.0.0.0", tcp=True)
    import threading
    threading.Thread(target=tcp.start, daemon=True).start()
    print("fixture authoritative for %s -> A %s (ns1 -> %s) on 0.0.0.0:53" % (ZONE, ANSWER_IP, NS_IP), flush=True)
    udp.start()
