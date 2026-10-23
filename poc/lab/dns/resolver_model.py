#!/usr/bin/env python3
"""
resolver_model.py -- ADDITIONAL-following resolver stand-in (task-9).

An iterative, lab-only resolver whose delegation behavior can be switched
between the two MEASURED behaviors on record:

  --additional-policy reresolve   (default)
      Mainstream behavior measured by the acceptance matrix: when a referral
      carries glue (ADDITIONAL A) for an OUT-OF-BAILIwick NS name, the glue is
      IGNORED and the NS name is re-resolved by ordinary iteration; the answer
      then comes from the real endpoint.  Justification: the resolver probe
      10-27-iterative.json -- 24/24 cells RE-RESOLVE-REAL across BIND 9.18.38 /
      9.18.41 / 9.20.15, Unbound 1.22.0, PowerDNS Recursor 5.1.3 / 4.9.5, with
      the NS-target zone pre-seeded and fully iterative alike (true_ns=1,
      fake_ns=0, drop=0: the poison endpoint is never queried).

  --additional-policy follow
      The measured 1.1.1.1 delegation-level steering: the ADDITIONAL-supplied
      address is used as the delegation target for the WHOLE delegated
      subtree -- every name under the forged referral resolves through that
      endpoint, including negative paths (NXDOMAIN carries that endpoint's own
      zone SOA).  Justification: artifacts/dns-disc-2026-10-27.json -- fresh,
      never-queried names under the forged delegation (disc1 / disc2 /
      www.blog.alice ...) returned the ADDITIONAL-supplied endpoint's answers
      (85.131.199.2) or, for nonexistent names, NXDOMAIN with that endpoint's
      SOA (ns1.static.ne.jp / root.static.ne.jp), while controls outside the
      delegation showed the real zone SOA.  This is a MODEL of one measured
      production behavior; the matrix shows 6/6 open-source implementations do
      the opposite (RE-RESOLVE-REAL).

Both policies share one iterative engine against the existing fixture chain
(lab_dns.py role "root" fake root + --delegate table + provider/thirdparty/
true/fake fixtures); the only difference is what happens to out-of-bailiwick
glue in a referral (resolver_model.py:_choose_target).

Lab-only plumbing: --map VIRT=HOST:PORT translates the virtual record addresses
used in fixtures to reachable endpoints (loopback tests bind high ports; on the
docker lab network no map is needed).  Nothing here ever queries outside the
configured root.
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
    from dnslib import DNSRecord, QTYPE, RCODE, RR, CNAME, A
    from dnslib.server import BaseResolver, DNSServer, DNSLogger
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "vendor"))
    from dnslib import DNSRecord, QTYPE, RCODE, RR, CNAME, A
    from dnslib.server import BaseResolver, DNSServer, DNSLogger

POLICIES = ("reresolve", "follow")


def norm(name):
    return str(name).rstrip(".").lower()


def in_zone(name, zone):
    return name == zone or name.endswith("." + zone)


def parse_addr(spec, default_port=53):
    """Accept ip, ip:port, host#port."""
    spec = spec.strip()
    if "#" in spec:
        host, port = spec.split("#", 1)
        return host.strip(), int(port)
    if ":" in spec:
        host, port = spec.rsplit(":", 1)
        return host.strip(), int(port)
    return spec, default_port


class Delegation:
    def __init__(self, zone, ns_name, addr, poisoned):
        self.zone = zone
        self.ns_name = ns_name
        self.addr = addr
        self.poisoned = poisoned


class ResolverModel(BaseResolver):
    """Iterative resolver with a measurable delegation policy.

    Delegation bookkeeping: referrals are learned as (zone -> ns name/address)
    exactly like a recursive resolver caches delegations.  That is what makes
    the 'follow' policy DELEGATION-LEVEL (per-referral, whole subtree) rather
    than name-specific -- the discriminator shape in
    artifacts/dns-disc-2026-10-27.json.
    """

    def __init__(self, root, additional_policy="reresolve", addr_map=None,
                 max_hops=16, max_depth=6, log=None, timeout=4, roles=None):
        if additional_policy not in POLICIES:
            raise ValueError("unknown additional policy %r" % (additional_policy,))
        self.root_host, self.root_port = root
        self.additional_policy = additional_policy
        self.addr_map = dict(addr_map or {})
        self.max_hops = max_hops
        self.max_depth = max_depth
        self.log_path = log
        self.timeout = timeout
        self.roles = dict(roles or {})
        self.delegations = []
        self.lock = threading.Lock()

    # ------------------------- plumbing -------------------------

    def _endpoint(self, addr):
        """Map a virtual record address to a reachable (host, port)."""
        if isinstance(addr, tuple):
            return addr
        if addr in self.addr_map:
            return self.addr_map[addr]
        return addr, 53

    def _ask(self, addr, qname, qtype, trace):
        host, port = self._endpoint(addr)
        req = DNSRecord.question(qname, QTYPE[qtype])
        req.header.rd = 0  # iteration: we ask authority-level questions
        t0 = time.time()
        try:
            raw = req.send(host, port, timeout=self.timeout)
            resp = DNSRecord.parse(raw)
        except Exception as exc:
            trace.append({"ask": addr, "mapped": "%s:%s" % (host, port), "qname": qname,
                          "qtype": QTYPE[qtype], "error": "%s: %s" % (type(exc).__name__, exc)})
            return None
        step = {"ask": addr, "mapped": "%s:%s" % (host, port), "qname": qname,
                "qtype": QTYPE[qtype], "rcode": resp.header.rcode,
                "aa": bool(resp.header.aa), "elapsed": round(time.time() - t0, 3),
                "answer": [str(rr) for rr in resp.rr][:4],
                "authority": [str(rr) for rr in resp.auth][:4],
                "additional": [str(rr) for rr in resp.ar][:4]}
        trace.append(step)
        return resp

    def _log(self, qname, qtype, trace, verdict):
        if not self.log_path:
            return
        try:
            with self.lock:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"ts": time.time(), "policy": self.additional_policy,
                                         "qname": qname, "qtype": QTYPE[qtype],
                                         "verdict": verdict, "trace": trace}) + "\n")
        except Exception:
            pass

    # ------------------------- delegation table -------------------------

    def _learn(self, zone, ns_name, addr, poisoned):
        with self.lock:
            self.delegations = [d for d in self.delegations if d.zone != zone]
            self.delegations.append(Delegation(zone, ns_name, addr, poisoned))

    def _best_target(self, qname):
        best = None
        with self.lock:
            for d in self.delegations:
                if in_zone(qname, d.zone) and (best is None or len(d.zone) > len(best.zone)):
                    best = d
        if best is None:
            return ".", (self.root_host, self.root_port), None
        return best.zone, best.addr, best

    # ------------------------- referral processing -------------------------

    def _referral(self, resp, qname):
        """Return [(owner, ns_name, glue_ip_or_None)] sorted most-specific first."""
        ns_recs = [(norm(rr.rname), norm(rr.rdata)) for rr in resp.auth if rr.rtype == QTYPE.NS]
        glue = {norm(rr.rname): str(rr.rdata) for rr in resp.ar if rr.rtype == QTYPE.A}
        out = []
        for owner, ns_name in ns_recs:
            if not in_zone(qname, owner):
                continue
            out.append((owner, ns_name, glue.get(ns_name)))
        out.sort(key=lambda t: len(t[0]), reverse=True)
        return out

    def _resolve_ns(self, ns_name, depth, trace):
        """Re-resolve an NS name by ordinary iteration (the reresolve policy)."""
        if depth > self.max_depth:
            return None
        resp = self._resolve(ns_name, QTYPE.A, depth + 1, trace)
        if resp is None:
            return None
        for rr in resp.rr:
            if rr.rtype == QTYPE.A and norm(rr.rname) == ns_name:
                return str(rr.rdata)
        return None

    def _choose_target(self, owner, ns_name, glue_ip, depth, trace):
        """The policy switch.  Returns the address to use as the delegation
        target for names under 'owner' (or None if unresolvable)."""
        in_bailiwick = in_zone(ns_name, owner)
        if glue_ip and in_bailiwick:
            # in-bailiwick glue is ordinary delegation data: both policies use it
            self._learn(owner, ns_name, glue_ip, poisoned=False)
            trace.append({"decision": "use-in-bailiwick-glue", "zone": owner,
                          "ns": ns_name, "addr": glue_ip})
            return glue_ip
        if self.additional_policy == "follow" and glue_ip:
            # POLICY follow -- measured 1.1.1.1 delegation-level steering
            # (artifacts/dns-disc-2026-10-27.json): the ADDITIONAL-supplied
            # address is used as the delegation target for the whole delegated
            # subtree, answer AND negative paths.  Per-referral, not
            # name-specific: artifacts/dns-reprobe2-2026-10-27.json shows the
            # fresh-name steering while cache persistence stays 0/4.
            self._learn(owner, ns_name, glue_ip, poisoned=True)
            trace.append({"decision": "follow-additional-target", "zone": owner,
                          "ns": ns_name, "addr": glue_ip})
            return glue_ip
        # POLICY reresolve -- measured mainstream behavior
        # (the resolver probe: all cells RE-RESOLVE-REAL):
        # out-of-bailiwick glue is ignored and the NS name is re-resolved.
        addr = self._resolve_ns(ns_name, depth + 1, trace)
        if addr:
            self._learn(owner, ns_name, addr, poisoned=False)
        trace.append({"decision": "reresolve-ns-name", "zone": owner, "ns": ns_name,
                      "resolved_to": addr, "ignored_glue": glue_ip})
        return addr

    # ------------------------- iteration -------------------------

    def _resolve(self, qname, qtype, depth, trace):
        zone, target, delegation = self._best_target(qname)
        for hop in range(self.max_hops):
            resp = self._ask(target, qname, qtype, trace)
            if resp is None:
                return None
            if resp.rr or resp.header.rcode in (RCODE.NXDOMAIN,):
                # answer or authoritative negative: whatever the endpoint
                # says (its SOA travels along) is the result for this path
                return resp
            candidates = self._referral(resp, qname)
            if not candidates:
                return resp  # NODATA without delegation
            moved = False
            for owner, ns_name, glue_ip in candidates:
                new_target = self._choose_target(owner, ns_name, glue_ip, depth, trace)
                if new_target:
                    target = new_target
                    moved = True
                    break
            if not moved:
                return None
        return None

    # ------------------------- request handling -------------------------

    def _query_full(self, qname, qtype):
        """Iterative one-shot resolution.  Returns (result dict, collected RR
        list, final response) so the server adapter can rebuild a reply."""
        qname = norm(qname)
        qtype_id = getattr(QTYPE, qtype) if isinstance(qtype, str) else qtype
        trace = []
        collected = []
        final = None
        cur_name, cur_type = qname, qtype_id
        seen = set()
        for _ in range(6):  # CNAME chase budget
            if (cur_name, cur_type) in seen:
                break
            seen.add((cur_name, cur_type))
            final = self._resolve(cur_name, cur_type, 0, trace)
            if final is None:
                self._log(qname, qtype_id, trace, "SERVFAIL")
                return ({"policy": self.additional_policy, "qname": qname,
                         "qtype": QTYPE[qtype_id], "rcode": "SERVFAIL", "answers": [],
                         "endpoint_role": None, "endpoint_addr": None,
                         "steered_by_additional": False, "trace": trace}, [], None)
            collected.extend(final.rr)
            cnames = [rr for rr in final.rr if rr.rtype == QTYPE.CNAME
                      and norm(rr.rname) == cur_name]
            answered = any(rr.rtype == cur_type and norm(rr.rname) == cur_name
                           for rr in final.rr)
            if cnames and not answered:
                cur_name = norm(cnames[0].rdata)
                continue
            break
        endpoint_addr = None
        for step in reversed(trace):
            if step.get("ask"):
                endpoint_addr = step["ask"]
                break
        steered = any(s.get("decision") == "follow-additional-target" for s in trace)
        followed_addrs = {s.get("addr") for s in trace
                          if s.get("decision") == "follow-additional-target"}
        poisoned = (endpoint_addr in followed_addrs) or any(
            d.poisoned and d.addr == endpoint_addr for d in list(self.delegations))
        if self.roles and endpoint_addr in self.roles:
            endpoint_role = self.roles[endpoint_addr]
        else:
            # convention: the endpoint behind a poisoned delegation target is
            # the 'fake' (ADDITIONAL-supplied) endpoint, everything else 'true'
            endpoint_role = "fake" if poisoned else "true"
        def recs(rrs):
            return [{"name": norm(rr.rname), "type": QTYPE[rr.rtype],
                     "address": str(rr.rdata) if rr.rtype == QTYPE.A else None,
                     "data": str(rr.rdata), "ttl": rr.ttl} for rr in rrs]
        answers = recs(collected)
        result = {"policy": self.additional_policy, "qname": qname,
                  "qtype": QTYPE[qtype_id], "rcode": RCODE[final.header.rcode],
                  "answers": answers, "authority": recs(final.auth),
                  "additional": recs(final.ar), "endpoint_role": endpoint_role,
                  "endpoint_addr": endpoint_addr,
                  "steered_by_additional": steered, "trace": trace}
        self._log(qname, qtype_id, trace, "rcode=%s" % result["rcode"])
        return result, collected, final

    def query(self, qname, qtype="A"):
        """Library entry point: resolve one name and return a result dict."""
        return self._query_full(qname, qtype)[0]

    def resolve(self, request, handler):
        result, collected, final = self._query_full(norm(request.q.qname), request.q.qtype)
        reply = request.reply()
        reply.header.aa = 0
        reply.header.ra = 1
        if final is None:
            reply.header.rcode = RCODE.SERVFAIL
            return reply
        reply.header.rcode = final.header.rcode
        for rr in collected:
            reply.add_answer(rr)
        for rr in final.auth:
            reply.add_auth(rr)
        for rr in final.ar:
            reply.add_ar(rr)
        return reply


def resolve(qname, servers, policy="reresolve", timeout=3.0, qtype="A",
            root=None, addr_map=None, roles=None):
    """One-shot library API for the integrated chain (task-10).

    qname    name to resolve (recursive semantics; the model iterates).
    servers  the fixture authority chain, as a list of (host, port) (strings
             like "host#port" / "host:port" are accepted too).  The FIRST
             entry is used as the fake root unless root= is given explicitly.
    policy   "reresolve" (default) or "follow" -- see the module docstring.
    addr_map optional {virt_addr: (host, port)} translation for fixture
             addresses that appear inside DNS data (loopback/high-port labs);
             on a docker lab network with real port 53 leave it None.
    roles    optional {addr: "true"|"fake"} endpoint attribution override;
             by default an endpoint behind a poisoned delegation target is
             reported as "fake", anything else as "true".

    Returns {"policy", "qname", "qtype", "rcode",
             "answers": [{"name", "type", "address", "data", "ttl"}],
             "endpoint_role", "endpoint_addr", "steered_by_additional",
             "trace"} -- endpoint_role/steered_by_additional are the
    chain-demo convenience fields; the trace is full iteration evidence.

    Fixture recipe (the caller starts these; resolver_model never spawns them):
      lab_dns.py --role root       fake root: --zone . --delegate ZONE=NS/IP
                                   for the provider zone and the NS-target
                                   zone (iteration start; use --root to point
                                   the model at it),
      lab_dns.py --role provider   the zone emitting the crafted referral:
                                   --pattern p3 --child-ns <forged-ns-name>
                                   --referral-owner name --third-party <same>
                                   --third-party-ip <poison-addr>
      lab_dns.py --role thirdparty the zone owning the forged NS name; answers
                                   A = the REAL endpoint address,
      lab_dns.py --role true       real endpoint of the delegated child zone
                                   (answers with its --true-ip marker),
      lab_dns.py --role fake       the ADDITIONAL-supplied endpoint (answers
                                   with its --fake-ip marker).
    """
    def as_endpoint(spec):
        return spec if isinstance(spec, tuple) else parse_addr(spec)

    server_list = [as_endpoint(s) for s in (servers or [])]
    root_spec = as_endpoint(root) if root is not None else (server_list[0] if server_list else None)
    if root_spec is None:
        raise ValueError("no fixture root: pass servers=[(host, port)] or root=")
    model = ResolverModel(root=root_spec, additional_policy=policy,
                          addr_map=addr_map or {}, timeout=timeout, roles=roles)
    return model.query(qname, qtype)


def run_server(bind, port, root, additional_policy, addr_map=None, log=None):
    resolver = ResolverModel(parse_addr(root), additional_policy=additional_policy,
                             addr_map=addr_map, log=log)
    logger = DNSLogger(log="-request,-reply,-truncated,-error")
    servers = [DNSServer(resolver, address=bind, port=port, tcp=tcp, logger=logger)
               for tcp in (False, True)]
    for server in servers:
        server.start_thread()
    return resolver, servers


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=15400)
    ap.add_argument("--root", required=True,
                    help="fake root address (ip, ip:port or host#port) to iterate from")
    ap.add_argument("--additional-policy", default="reresolve", choices=list(POLICIES),
                    help="reresolve = measured mainstream behavior (matrix 24/24 "
                         "RE-RESOLVE-REAL); follow = measured 1.1.1.1 delegation-level "
                         "steering (artifacts/dns-disc-2026-10-27.json)")
    ap.add_argument("--map", action="append", default=[],
                    help="lab shim: VIRT=HOST:PORT translation for fixture addresses")
    ap.add_argument("--log", default=None, help="JSONL trace log")
    args = ap.parse_args()

    addr_map = {}
    for entry in args.map:
        virt, target = entry.split("=", 1)
        addr_map[virt.strip()] = parse_addr(target)
    resolver, servers = run_server(args.bind, args.port, args.root,
                                   args.additional_policy, addr_map, args.log)
    print("resolver_model policy=%s root=%s bind=%s:%s map=%s" %
          (args.additional_policy, args.root, args.bind, args.port, addr_map), flush=True)
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
