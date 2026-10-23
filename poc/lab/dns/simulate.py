#!/usr/bin/env python3
"""
simulate.py -- compare records from the three configured local DNS endpoints.

The true/fake ports are fixed fixtures, not destinations selected by a recursive
resolver. Success confirms their records agree with the expected configuration;
it does not demonstrate resolver behavior, cache poisoning, or tenant isolation.
"""
import argparse

from dnslib import DNSError, DNSRecord, QTYPE, RCODE

ZONE = "lab.yes-its-a-problem.iamwonderingif.com"


def norm(name):
    return str(name).rstrip(".").lower()


def query(name, port, qtype="A"):
    req = DNSRecord.question(name, qtype)
    reply = DNSRecord.parse(req.send("127.0.0.1", port, timeout=3))
    if (not reply.header.qr or reply.header.id != req.header.id or
            reply.questions != req.questions or reply.header.tc or
            reply.header.rcode != RCODE.NOERROR):
        raise ValueError("invalid or unsuccessful %s response for %s on port %s" %
                         (qtype, name, port))
    return reply


def require_a(records, name, expected):
    addresses = {str(rr.rdata) for rr in records
                 if rr.rtype == QTYPE.A and norm(rr.rname) == norm(name)}
    if addresses != {expected}:
        raise ValueError("A for %s: got %s, expected %s" %
                         (name, sorted(addresses), expected))


def compare(args):
    print("=== configured DNS fixture comparison; no recursive resolver is tested")
    referral = query(args.name, args.provider_port)
    print(referral)
    ns_records = [rr for rr in referral.auth if rr.rtype == QTYPE.NS]
    if referral.header.aa or referral.rr or len(ns_records) != 1:
        raise ValueError("expected one non-authoritative NS referral")
    child, ns_name = norm(ns_records[0].rname), norm(ns_records[0].rdata)
    if norm(args.name) != child and not norm(args.name).endswith("." + child):
        raise ValueError("referral owner does not contain the requested name")
    require_a(referral.ar, ns_name, args.fake_ip)

    ns_answer = query(ns_name, args.provider_port)
    require_a(ns_answer.rr, ns_name, args.true_ip)
    print("NS:", ns_name)
    print("direct A:", args.true_ip, "ADDITIONAL A:", args.fake_ip)

    for role, port, expected in (("true", args.true_port, args.true_ip),
                                 ("fake", args.fake_port, args.fake_ip)):
        answer = query(args.name, port)
        require_a(answer.rr, args.name, expected)
        child_answer = query(child, port, "NS")
        child_ns = {(norm(rr.rname), norm(rr.rdata)) for rr in child_answer.rr
                    if rr.rtype == QTYPE.NS}
        if not answer.header.aa or not child_answer.header.aa or child_ns != {(child, ns_name)}:
            raise ValueError("%s endpoint does not serve the delegated child authority" % role)
        print("configured %s endpoint (127.0.0.1:%s): A %s; child NS matches" %
              (role, port, expected))
    print("fixture comparison: PASS (expected records; no resolver verdict)")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--provider-port", type=int, default=15351)
    ap.add_argument("--true-port", type=int, default=15352)
    ap.add_argument("--fake-port", type=int, default=15353)
    ap.add_argument("--name", default="www." + "v." + ZONE)
    ap.add_argument("--true-ip", default="192.0.2.10")
    ap.add_argument("--fake-ip", default="198.51.100.66")
    args = ap.parse_args()

    if args.true_ip == args.fake_ip:
        ap.error("--true-ip and --fake-ip must differ")
    try:
        compare(args)
    except OSError as exc:
        raise SystemExit("INCONCLUSIVE: DNS query failed: %s" % exc) from None
    except (DNSError, ValueError) as exc:
        raise SystemExit("INCONSISTENT: %s" % exc) from None


if __name__ == "__main__":
    main()
