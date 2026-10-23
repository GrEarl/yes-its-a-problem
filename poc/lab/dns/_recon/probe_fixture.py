#!/usr/bin/env python3
import sys
sys.path.insert(0, "/vendor")
from dnslib import DNSRecord, QTYPE, EDNS0

def send(label, q, srv):
    try:
        a = q.send(srv, 53, timeout=5)
        r = DNSRecord.parse(a)
        print("%-32s -> rcode=%s an=%d auth=%d" % (label, r.header.rcode, len(r.rr), len(r.auth)))
    except Exception as e:
        print("%-32s -> ERROR %s" % (label, e))

srv = "10.200.0.6"
send("plain RD=1", DNSRecord.question("host.beta.test"), srv)
q = DNSRecord.question("host.beta.test"); q.header.rd = 0
send("RD=0", q, srv)
q = DNSRecord.question("host.beta.test"); q.add_ar(EDNS0("host.beta.test", udp_len=1232))
send("EDNS OPT", q, srv)
q = DNSRecord.question("host.beta.test"); q.header.rd = 0
q.add_ar(EDNS0("host.beta.test", udp_len=1232))
send("EDNS OPT + RD=0", q, srv)
send("0x20 case", DNSRecord.question("HoSt.BeTa.TeSt"), srv)
send("trailing dot name", DNSRecord.question("host.beta.test."), srv)
