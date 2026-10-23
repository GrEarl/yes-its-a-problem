#!/usr/bin/env python3
"""Tiny DNS client using dnslib (no dig). Usage: query.py <server-ip> <qname> [qtype] [tcp]"""
import sys
sys.path.insert(0, "/vendor")
from dnslib import DNSRecord, QTYPE

server, qname = sys.argv[1], sys.argv[2]
qtype = sys.argv[3] if len(sys.argv) > 3 else "A"
tcp = len(sys.argv) > 4 and sys.argv[4] == "tcp"
q = DNSRecord.question(qname, qtype)
try:
    a = q.send(server, 53, tcp=tcp, timeout=5)
    r = DNSRecord.parse(a)
    print("rcode=%s aa=%s ra=%s" % (r.header.rcode, r.header.aa, r.header.ra))
    for rr in r.rr:
        print("ANSWER %s" % rr)
    for rr in r.auth:
        print("AUTH   %s" % rr)
    if not r.rr:
        print("(no answer rr)")
except Exception as e:
    print("ERROR %s" % e)
    sys.exit(1)
