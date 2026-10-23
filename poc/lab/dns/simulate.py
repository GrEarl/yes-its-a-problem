#!/usr/bin/env python3
"""
simulate.py -- show what a safe and a vulnerable resolver would do with the
crafted provider response, using the three local lab servers.

safe      : ignores the malicious ADDITIONAL, resolves the sibling nameserver
            through the provider (legit A -> true IP), and asks the true NS.
vulnerable: trusts the malicious ADDITIONAL, asks the fake NS.
"""
import argparse
import socket

from dnslib import DNSRecord, QTYPE

ZONE = "lab.yes-its-a-problem.iamwonderingif.com"


def query(name, port, qtype="A", host="127.0.0.1"):
    req = DNSRecord.question(name, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(req.pack(), (host, port))
        data, _ = sock.recvfrom(8192)
    finally:
        sock.close()
    return DNSRecord.parse(data)


def first_a(record):
    for rr in record.rr:
        if rr.rtype == QTYPE.A:
            return str(rr.rdata)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider-port", type=int, default=5351)
    ap.add_argument("--true-port", type=int, default=5352)
    ap.add_argument("--fake-port", type=int, default=5353)
    ap.add_argument("--name", default="www." + "v." + ZONE)
    ap.add_argument("--fake-ip", default="198.51.100.66")
    args = ap.parse_args()

    print("=== provider referral for", args.name)
    referral = query(args.name, args.provider_port)
    print(referral)

    ns_name = None
    for rr in referral.auth:
        if rr.rtype == QTYPE.NS:
            ns_name = str(rr.rdata).rstrip(".")
            break
    glue_fake = None
    for rr in referral.ar:
        if rr.rtype == QTYPE.A:
            glue_fake = str(rr.rdata)
            break
    print("sibling NS :", ns_name)
    print("ADDITIONAL :", glue_fake)
    if not ns_name:
        raise SystemExit("no NS in referral")
    if not glue_fake:
        raise SystemExit("no ADDITIONAL A in referral")
    if glue_fake != args.fake_ip:
        raise SystemExit("unexpected ADDITIONAL A: %s (want %s)" % (glue_fake, args.fake_ip))

    # Safe resolver: ignore ADDITIONAL, resolve NS name through provider.
    ns_a = query(ns_name, args.provider_port)
    true_ip = first_a(ns_a)
    print("\n=== safe path")
    print("provider legit A for", ns_name, "->", true_ip)
    true_answer = query(args.name, args.true_port)
    print("true NS answer:", true_answer)
    print("safe answer  :", first_a(true_answer))

    # Vulnerable resolver: use the ADDITIONAL A and ask the fake NS.
    print("\n=== vulnerable path")
    print("using ADDITIONAL A:", glue_fake)
    fake_answer = query(args.name, args.fake_port)
    print("fake NS answer:", fake_answer)
    print("vulnerable answer:", first_a(fake_answer))

    safe = first_a(true_answer)
    vuln = first_a(fake_answer)
    print("\nsimulated result: safe=%s vulnerable=%s -> %s" %
          (safe, vuln, "DIFFERENT (poisoned)" if safe != vuln else "same"))


if __name__ == "__main__":
    main()
