#!/usr/bin/env python3
"""
probe_client.py -- in-lab DNS query executor for probe_matrix.py.

Reads a JSON query plan on stdin, executes it against one resolver address,
prints the JSON results on stdout.  Runs either on the host (host mode) or
inside the probe container on the isolated docker network (docker mode), so no
query ever leaves the lab.  Standalone on purpose: needs only dnslib.
"""
import json
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "vendor"))

from dnslib import DNSRecord, QTYPE, RCODE  # noqa: E402

RCODE_NAME = {getattr(RCODE, n): n for n in
              ("NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED")}


def norm(name):
    return str(name).rstrip(".").lower()


def query(server, port, name, qtype="A", timeout=6, rd=True, tcp=False):
    req = DNSRecord.question(name, qtype)
    req.header.rd = 1 if rd else 0
    t0 = time.time()
    try:
        raw = req.send(server, port, timeout=timeout, tcp=tcp)
        reply = DNSRecord.parse(raw)
    except Exception as exc:
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                "elapsed": round(time.time() - t0, 3), "ts": time.time()}
    out = {"ok": True, "elapsed": round(time.time() - t0, 3), "ts": time.time(),
           "raw_hex": raw.hex(),  # raw wire capture of the response (O10 evidence)
           "rcode": RCODE_NAME.get(reply.header.rcode, str(reply.header.rcode)),
           "aa": bool(reply.header.aa), "ra": bool(reply.header.ra),
           "rd": bool(reply.header.rd), "tc": bool(reply.header.tc),
           "answer": [], "authority": [], "additional": []}
    for section, key in ((reply.rr, "answer"), (reply.auth, "authority"), (reply.ar, "additional")):
        for rr in section:
            out[key].append({"owner": norm(rr.rname), "type": QTYPE[rr.rtype],
                             "ttl": rr.ttl, "data": str(rr.rdata)})
    return out


def main():
    plan = json.load(sys.stdin)
    server, port = plan["server"], int(plan.get("port", 53))
    results = {}
    for step in plan["queries"]:
        if "sleep" in step:
            time.sleep(step["sleep"])
            continue
        key = step["key"]
        wait = step.get("retry_until")
        deadline = time.time() + wait.get("deadline_s", 25) if wait else time.time()
        attempts = 0
        while True:
            attempts += 1
            res = query(server, port, step["name"], step.get("qtype", "A"),
                        timeout=step.get("timeout", 6), rd=step.get("rd", True),
                        tcp=step.get("tcp", False))
            res["attempts"] = attempts
            if not wait:
                break
            ok = res.get("ok") and any(r["data"] == wait.get("answer_contains")
                                       for r in res.get("answer", []))
            if ok or time.time() >= deadline:
                break
            time.sleep(wait.get("interval_s", 1))
        results[key] = res
    json.dump({"server": server, "port": port, "results": results}, sys.stdout)


if __name__ == "__main__":
    main()
