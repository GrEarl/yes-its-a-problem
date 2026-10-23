#!/usr/bin/env python3
"""
test_resolver_model.py -- unit tests for the ADDITIONAL-following resolver
stand-in (task-9), covering BOTH delegation policies against the lab fixture
chain (lab_dns.py roles root / provider / thirdparty / true / fake):

  reresolve  measured mainstream behavior -- the resolver probe 
             iterative.json, 24/24 RE-RESOLVE-REAL (out-of-bailiwick glue
             ignored, NS name re-resolved, real endpoint answers),
  follow     measured 1.1.1.1 delegation-level steering -- artifacts/dns-disc-
             2026-10-27.json (whole delegated subtree resolves through the
             ADDITIONAL-supplied endpoint, answers AND negative paths with
             that endpoint's SOA) and artifacts/dns-reprobe2-2026-10-27.json
             (fresh-name steering; cache persistence 0/4).

Run: python3 test_resolver_model.py -v
"""
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "vendor"))

import lab_dns  # noqa: E402
import resolver_model  # noqa: E402
from dnslib import DNSRecord, QTYPE, RCODE  # noqa: E402
from dnslib.server import DNSServer, DNSLogger  # noqa: E402

ZONE = "poc.debiru.lab.invalid"
CHILD = "alice"
CHILD_ZONE = CHILD + "." + ZONE
TP_ZONE = "netserv.lab.invalid"
TARGET = "ns-33." + TP_ZONE          # forged NS name (out of bailiwick)
TRIGGER = "www." + CHILD_ZONE
NEGATIVE = "nope." + CHILD_ZONE
TRUE_MARKER = "203.0.113.10"
FAKE_MARKER = "203.0.113.66"

PROVIDER_V = "192.0.2.53"
TP_V = "192.0.2.54"
TRUE_NS_V = "192.0.2.20"
POISON_V = "198.51.100.66"           # the unrelated ADDITIONAL address


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class FixtureChain:
    """The task-9 fixture chain on loopback high ports (see
    resolver_model.resolve.__doc__ for the same recipe on the lab network)."""

    def __init__(self):
        self.ports = {}
        self.servers = []
        self.addr_map = {}

    def start(self):
        logger = DNSLogger(log="-request,-reply,-truncated,-error")
        root_cfg = {"zone": ".", "child": "v", "provider_ns": "a.root.lab.invalid",
                    "true_ip": PROVIDER_V, "fake_ip": POISON_V, "ttl": 300,
                    "delegations": [(ZONE, "ns1." + ZONE, PROVIDER_V),
                                    (TP_ZONE, "ns1." + TP_ZONE, TP_V)]}
        provider_cfg = {"zone": ZONE, "child": CHILD, "provider_ns": "ns1." + ZONE,
                        "child_ns": TARGET, "pattern": "p3", "third_party": TARGET,
                        "third_party_ip": POISON_V, "referral_owner": "name",
                        "true_ip": TRUE_NS_V, "fake_ip": POISON_V, "ttl": 300}
        tp_cfg = {"zone": TP_ZONE, "child": TP_ZONE, "provider_ns": "ns1." + TP_ZONE,
                  "true_ip": TRUE_NS_V, "fake_ip": POISON_V, "ttl": 300}
        true_cfg = {"zone": ZONE, "child": CHILD, "provider_ns": "ns1." + ZONE,
                    "child_ns": "ns-true." + ZONE, "true_ip": TRUE_MARKER,
                    "fake_ip": FAKE_MARKER, "ttl": 300, "nxd_prefix": "nope"}
        fake_cfg = {"zone": ZONE, "child": CHILD, "provider_ns": "ns1." + ZONE,
                    "child_ns": "ns-fake." + ZONE, "true_ip": TRUE_MARKER,
                    "fake_ip": FAKE_MARKER, "ttl": 300, "nxd_prefix": "nope"}
        plan = [("root", root_cfg, PROVIDER_V), ("provider", provider_cfg, PROVIDER_V),
                ("thirdparty", tp_cfg, TP_V), ("true", true_cfg, TRUE_NS_V),
                ("fake", fake_cfg, POISON_V)]
        for role, cfg, virt in plan:
            port = free_port()
            server = DNSServer(lab_dns.LabResolver(cfg, role), address="127.0.0.1",
                               port=port, tcp=True, logger=logger)
            server2 = DNSServer(lab_dns.LabResolver(cfg, role), address="127.0.0.1",
                                port=port, tcp=False, logger=logger)
            for srv in (server, server2):
                srv.start_thread()
            self.servers += [server, server2]
            self.ports[role] = port
            if role != "root":
                self.addr_map[virt] = ("127.0.0.1", port)
        time.sleep(0.4)

    def stop(self):
        for srv in self.servers:
            try:
                srv.stop()
                srv.server.server_close()
            except Exception:
                pass

    @property
    def root(self):
        return ("127.0.0.1", self.ports["root"])


CHAIN = None


def setUpModule():
    global CHAIN
    CHAIN = FixtureChain()
    CHAIN.start()


def tearDownModule():
    CHAIN.stop()


def model(policy):
    return resolver_model.ResolverModel(root=CHAIN.root, additional_policy=policy,
                                        addr_map=CHAIN.addr_map, timeout=4)


class ReresolvePolicyTests(unittest.TestCase):
    """Measured mainstream behavior (matrix 24/24 RE-RESOLVE-REAL)."""

    def test_trigger_answer_comes_from_real_endpoint(self):
        res = model("reresolve").query(TRIGGER)
        self.assertEqual(res["rcode"], "NOERROR")
        self.assertEqual([a["address"] for a in res["answers"]], [TRUE_MARKER])
        self.assertEqual(res["endpoint_role"], "true")
        self.assertFalse(res["steered_by_additional"])
        decisions = [s.get("decision") for s in res["trace"] if s.get("decision")]
        self.assertIn("reresolve-ns-name", decisions)
        self.assertNotIn("follow-additional-target", decisions)

    def test_negative_path_carries_true_endpoint_soa(self):
        res = model("reresolve").query(NEGATIVE)
        self.assertEqual(res["rcode"], "NXDOMAIN")
        soa = [a for a in res["authority"] if a["type"] == "SOA"]
        self.assertTrue(soa, res)
        self.assertTrue(soa[0]["data"].startswith("ns-true." + ZONE), soa)

    def test_unrelated_additional_is_not_cached_as_an_answer(self):
        m = model("reresolve")
        m.query(TRIGGER)  # prime the forged referral
        res = m.query(TARGET)  # independent query for the forged NS name
        self.assertEqual(res["rcode"], "NOERROR")
        self.assertEqual([a["address"] for a in res["answers"]], [TRUE_NS_V])
        self.assertNotIn(POISON_V, [a["address"] for a in res["answers"]])


class FollowPolicyTests(unittest.TestCase):
    """Measured 1.1.1.1 delegation-level steering (dns-disc / dns-reprobe2)."""

    def test_trigger_answer_comes_from_additional_endpoint(self):
        res = model("follow").query(TRIGGER)
        self.assertEqual(res["rcode"], "NOERROR")
        self.assertEqual([a["address"] for a in res["answers"]], [FAKE_MARKER])
        self.assertEqual(res["endpoint_role"], "fake")
        self.assertTrue(res["steered_by_additional"])
        decisions = [s.get("decision") for s in res["trace"] if s.get("decision")]
        self.assertIn("follow-additional-target", decisions)

    def test_negative_paths_steer_too(self):
        # dns-disc shape: a never-queried nonexistent name under the forged
        # delegation answers NXDOMAIN with the ADDITIONAL endpoint's own SOA
        res = model("follow").query(NEGATIVE)
        self.assertEqual(res["rcode"], "NXDOMAIN")
        soa = [a for a in res["authority"] if a["type"] == "SOA"]
        self.assertTrue(soa, res)
        self.assertTrue(soa[0]["data"].startswith("ns-fake." + ZONE), soa)

    def test_learned_delegation_covers_whole_subtree(self):
        # H1 delegation-level model: once a forged delegation is learned for a
        # zone, every name under that subtree (answer and negative paths) uses
        # the ADDITIONAL-supplied target without re-walking the referral.
        m = model("follow")
        m._learn(CHILD_ZONE, TARGET, POISON_V, poisoned=True)
        res = m.query("deep.name." + CHILD_ZONE)
        self.assertEqual(res["endpoint_role"], "fake")
        self.assertEqual(res["rcode"], "NOERROR")
        self.assertEqual([a["address"] for a in res["answers"]], [FAKE_MARKER])
        neg = m.query("nope2." + CHILD_ZONE)
        self.assertEqual(neg["rcode"], "NXDOMAIN")
        soa = [a for a in neg["authority"] if a["type"] == "SOA"]
        self.assertTrue(soa[0]["data"].startswith("ns-fake." + ZONE), soa)
        self.assertEqual(neg["endpoint_role"], "fake")

    def test_delegation_level_not_name_specific(self):
        m = model("follow")
        for name in (TRIGGER, "disc1." + CHILD_ZONE, "disc2." + CHILD_ZONE,
                     "www.blog." + CHILD_ZONE, "gone." + CHILD_ZONE):
            res = m.query(name)
            if res["rcode"] == "NOERROR":
                self.assertEqual([a["address"] for a in res["answers"]], [FAKE_MARKER], name)
            else:
                self.assertEqual(res["rcode"], "NXDOMAIN", name)
                soa = [a for a in res["authority"] if a["type"] == "SOA"]
                self.assertTrue(soa[0]["data"].startswith("ns-fake." + ZONE), name)
            self.assertEqual(res["endpoint_role"], "fake", name)


class LibraryApiTests(unittest.TestCase):
    """The chain-demo (task-10) adapter contract."""

    def test_resolve_returns_documented_shape(self):
        res = resolver_model.resolve(
            TRIGGER, servers=[CHAIN.root], policy="follow",
            addr_map=CHAIN.addr_map,
            roles={POISON_V: "fake", TRUE_NS_V: "true"})
        for key in ("policy", "qname", "qtype", "rcode", "answers", "endpoint_role",
                    "steered_by_additional", "trace"):
            self.assertIn(key, res)
        self.assertEqual(res["policy"], "follow")
        self.assertEqual(res["qtype"], "A")
        self.assertEqual(res["endpoint_role"], "fake")
        self.assertTrue(res["steered_by_additional"])
        self.assertEqual(res["answers"][0]["name"], TRIGGER)
        self.assertEqual(res["answers"][0]["address"], FAKE_MARKER)

    def test_reresolve_api_reports_true_endpoint(self):
        res = resolver_model.resolve(TRIGGER, servers=[CHAIN.root], policy="reresolve",
                                     addr_map=CHAIN.addr_map)
        self.assertEqual(res["endpoint_role"], "true")
        self.assertFalse(res["steered_by_additional"])
        self.assertEqual(res["answers"][0]["address"], TRUE_MARKER)


class DaemonCliTests(unittest.TestCase):
    """resolver_model.py as a daemon (what task-10 wires up)."""

    def _run_daemon(self, policy, port):
        maps = []
        for virt, ep in CHAIN.addr_map.items():
            maps += ["--map", "%s=127.0.0.1:%d" % (virt, ep[1])]
        proc = subprocess.Popen(
            [sys.executable, str(HERE / "resolver_model.py"),
             "--bind", "127.0.0.1", "--port", str(port),
             "--root", "127.0.0.1#%d" % CHAIN.ports["root"],
             "--additional-policy", policy] + maps,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 8
        while time.time() < deadline:
            line = proc.stdout.readline()
            if "ready" in line:
                return proc
            if proc.poll() is not None:
                raise RuntimeError("daemon exited: " + line)
        raise RuntimeError("daemon did not become ready")

    def test_daemon_follow_and_reresolve(self):
        for policy, expected in (("follow", FAKE_MARKER), ("reresolve", TRUE_MARKER)):
            port = free_port()
            proc = self._run_daemon(policy, port)
            try:
                req = DNSRecord.question(TRIGGER)
                reply = DNSRecord.parse(req.send("127.0.0.1", port, timeout=6))
                self.assertEqual(reply.header.rcode, RCODE.NOERROR)
                self.assertEqual([str(rr.rdata) for rr in reply.rr], [expected])
            finally:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
