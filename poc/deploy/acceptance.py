#!/usr/bin/env python3
"""Read-only public checks to run after deployment. Never uses --insecure.

A resolver query plus a pinned HTTPS request are separate observations. The
additional unpinned HTTPS request exercises this controller's system resolver,
which can differ from a browser's DoH resolver. No result proves all clients safe.
"""
import argparse
import datetime
import ipaddress
import json
import subprocess
import sys
import uuid
from pathlib import Path

from deploy import (CHILD, SITE, DNSRecord, QTYPE, RCODE, child_ns_addresses, child_ns_name,
                    load_config, require)


def dns(ip, name, qtype="A", tcp=False, recursive=True):
    query = DNSRecord.question(name, qtype)
    query.header.rd = int(recursive)
    reply = DNSRecord.parse(query.send(ip, 53, tcp=tcp, timeout=8))
    def rows(records):
        return [{"type": QTYPE[rr.rtype], "name": str(rr.rname).rstrip("."),
                 "value": str(rr.rdata), "ttl": rr.ttl} for rr in records]
    return {"server": ip, "name": name, "type": qtype, "tcp": tcp,
            "rcode": RCODE[reply.header.rcode], "aa": bool(reply.header.aa), "ra": bool(reply.header.ra),
            "answers": rows(reply.rr), "authority": rows(reply.auth), "additional": rows(reply.ar)}


def child_ns_contract_failures(referral, parent, cfg):
    """Judge captured observations against the reviewed lab_dns.py --child-ns contract.

    The provider delegates the child zone to an external NS name (outside the
    provider zone) and attaches an unrelated ADDITIONAL A for that name at the
    fake address.  The parent zone keeps an ordinary A record for the same name
    at the true address: that contradiction is the lab fixture, and the
    ADDITIONAL value is never a Cloudflare record.  Returns failure strings.
    """
    name = child_ns_name(cfg)
    true_ip, fake_ip = child_ns_addresses(cfg)
    if not true_ip or not fake_ip:
        return ["child NS true/fake addresses are unassigned"]
    failures = []
    if referral.get("rcode") != "NOERROR" or referral.get("aa"):
        failures.append("child zone query must return a non-authoritative NOERROR referral")
    delegated = {str(r["value"]).rstrip(".").lower() for r in referral.get("authority", [])
                 if r["type"] == "NS" and str(r["name"]).lower() == CHILD}
    if delegated != {name}:
        failures.append("referral must delegate " + CHILD + " to the external NS name " + name)
    additional = {str(r["value"]) for r in referral.get("additional", [])
                  if r["type"] == "A" and str(r["name"]).lower() == name}
    if additional != {fake_ip}:
        failures.append("referral ADDITIONAL for " + name + " must be the contradictory fake address " + str(fake_ip))
    parent_addresses = {str(r["value"]) for r in parent.get("answers", []) if r["type"] == "A"}
    if parent_addresses != {true_ip}:
        failures.append("the parent-side A record for " + name + " must keep pointing at the true address " + str(true_ip))
    return failures


def https(host, path, pin=None):
    command = ["curl", "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "10",
               "--max-time", "25", "--proto", "=https", "--write-out",
               "\n%{http_code} %{remote_ip} %{ssl_verify_result}"]
    if pin:
        command += ["--resolve", host + ":443:" + pin]
    command += ["https://" + host + path]
    result = subprocess.run(command, capture_output=True, text=True)
    observation = {"host": host, "path": path, "pinned_ip": pin, "curl_exit": result.returncode}
    if result.returncode:
        observation["error"] = result.stderr.strip()
        return observation
    body, metadata = result.stdout.rsplit("\n", 1)
    code, peer, verify = metadata.split()
    observation.update(http_status=int(code), peer_ip=peer, ssl_verify_result=int(verify))
    try:
        observation["body"] = json.loads(body)
    except ValueError:
        observation["body_prefix"] = body[:200]
    return observation


def valid_probe(response, cfg, host, token):
    body = response.get("body", {})
    role = body.get("path")
    return (response.get("http_status") == 200 and response.get("ssl_verify_result") == 0 and
            role in ("true", "fake") and body.get("host") == host and body.get("token") == token and
            response.get("peer_ip") == cfg["hosts"][role]["ipv4"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--resolver", action="append", help="recursive resolver IPv4; default: 1.1.1.1, 8.8.8.8")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cfg = load_config(args.config)
    require(cfg, "dns")
    resolvers = args.resolver or ["1.1.1.1", "8.8.8.8"]
    for resolver in resolvers:
        ipaddress.IPv4Address(resolver)
    report = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "limits": __doc__, "checks": []}
    checks, failed = report["checks"], []
    # A fresh label avoids reusing a previous browser probe's cached answer.
    for role in ("true", "fake"):
        token = uuid.uuid4().hex
        host = "direct-" + token + "." + CHILD
        response = https(host, "/probe?token=" + token, cfg["hosts"][role]["ipv4"])
        checks.append({"kind": "independent_normal_https_endpoint", "role": role, **response})
        if not valid_probe(response, cfg, host, token):
            failed.append(role + " normal HTTPS endpoint failed")
    for role in ("provider", "true", "fake"):
        for tcp in (False, True):
            refusal = dns(cfg["hosts"][role]["ipv4"], "example.net", tcp=tcp, recursive=False)
            checks.append({"kind": "no_recursion", "role": role, **refusal})
            if refusal["rcode"] != "REFUSED" or refusal["ra"]:
                failed.append(role + " must refuse queries outside its authority")
    name = child_ns_name(cfg)
    true_ip, fake_ip = child_ns_addresses(cfg)
    provider_ip = cfg["hosts"]["provider"]["ipv4"]
    # The reviewed --child-ns contract: an external NS name whose parent-side A
    # keeps the true address while the provider referral contradicts it with an
    # ADDITIONAL A at the fake address (lab fixture data, never a Cloudflare
    # record).  Referral, parent A and out-of-zone refusal are separate direct
    # observations of the provider authority and the parent zone.
    for tcp in (False, True):
        referral = dns(provider_ip, "contract-" + uuid.uuid4().hex + "." + CHILD, tcp=tcp, recursive=False)
        checks.append({"kind": "child_ns_referral_additional", **referral})
        parent_side = dns(resolvers[0], name, tcp=tcp)
        checks.append({"kind": "child_ns_parent_side_a", **parent_side})
        for problem in child_ns_contract_failures(referral, parent_side, cfg):
            failed.append(problem)
        checks.append({"kind": "child_ns_contradiction_observed", "tcp": tcp,
                       "parent_side_a": sorted(x["value"] for x in parent_side["answers"] if x["type"] == "A"),
                       "referral_additional": sorted(x["value"] for x in referral["additional"]
                                                     if x["type"] == "A" and x["name"].lower() == name),
                       "note": "contradictory ADDITIONAL is fixture data only; never a Cloudflare record"})
        refusal = dns(provider_ip, name, tcp=tcp, recursive=False)
        checks.append({"kind": "child_ns_out_of_zone_refusal", **refusal})
        if refusal["rcode"] != "REFUSED":
            failed.append("provider must refuse queries for the external child NS name " + name)
    for resolver in resolvers:
        authoritative_name = dns(resolver, name)
        checks.append({"kind": "legitimate_child_ns_address", **authoritative_name})
        ips = {x["value"] for x in authoritative_name["answers"] if x["type"] == "A"}
        if ips != {true_ip}:
            failed.append(resolver + " did not return the configured legitimate child NS A at the true address")
        token = uuid.uuid4().hex
        host = "check-" + token + "." + CHILD
        answer = dns(resolver, host)
        checks.append({"kind": "recursive_answer", **answer})
        addresses = {x["value"] for x in answer["answers"] if x["type"] == "A"}
        expected = {cfg["hosts"][r]["ipv4"] for r in ("true", "fake")}
        if not addresses or not addresses <= expected:
            failed.append(resolver + " returned an unexpected or absent probe address")
        for address in sorted(addresses & expected):
            response = https(host, "/probe?token=" + token, address)
            checks.append({"kind": "pinned_https_after_separate_dns_query", "resolver": resolver, **response})
            if not valid_probe(response, cfg, host, token):
                failed.append("pinned HTTPS probe failed for " + address)
    token = uuid.uuid4().hex
    host = "system-" + token + "." + CHILD
    response = https(host, "/probe?token=" + token)
    checks.append({"kind": "system_resolver_https_request", **response})
    if not valid_probe(response, cfg, host, token):
        failed.append("system-resolved HTTPS probe failed")
    for role in ("true", "fake"):
        response = https("login." + CHILD, "/tls-probe", cfg["hosts"][role]["ipv4"])
        checks.append({"kind": "separate_tls_observation", "role": role, **response})
        # A forged chain rejection is an observation, not an instruction to bypass it.
        if role == "fake" and response["curl_exit"] == 60:
            checks[-1]["observation"] = "client rejected certificate verification"
        elif response.get("http_status") == 200 and response.get("ssl_verify_result") == 0:
            body = response.get("body", {})
            expected = "forged" if role == "fake" else "other"
            if body.get("tls") != expected or body.get("host") != "login." + CHILD or not body.get("leaf_sha256"):
                failed.append(role + " TLS response did not identify the intended certificate")
        else:
            failed.append(role + " TLS observation was unavailable or inconclusive")
    for query in ("", "?lang=ja", "?lang=en"):
        response = https(SITE, "/" + query)
        checks.append({"kind": "pages_https", **response})
        if response.get("http_status") != 200 or response.get("ssl_verify_result") != 0:
            failed.append("Pages HTTPS failed " + query)
    report["failures"] = failed
    report["status"] = "FAIL" if failed else "PASS_WITH_RECORDED_TLS_OBSERVATIONS"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"] + ": " + str(args.output))
    return bool(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("ERROR: acceptance incomplete: " + str(exc), file=sys.stderr)
        sys.exit(1)
