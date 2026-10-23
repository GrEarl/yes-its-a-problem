#!/usr/bin/env python3
"""test_chain.py - one-path integrated chain regression, lab only.

Run: python3 -B poc/integrated-chain/test_chain.py

Three DNS trigger arms share one chain (TLS -> poisoned update -> decode):

  (a) referral       the crafted referral walked by the task-9 resolver
                     stand-in: policy "follow" steers to the fake endpoint,
                     "reresolve" reaches the true endpoint.
  (b) doh-mitm       a forged-CA certificate for the DoH resolver hostname
                     lets an on-path proxy inject the A answer inside the
                     client's encrypted DNS session - no provider bug needed.
  (c) udp-injection  the plain-UDP response-injection baseline.

Everything is real except the trigger stand-ins and the certificate material:
real TLS handshakes against real lab_http endpoints, the real mock_registry
fixture, real DoH/UDP DNS exchanges, and the real client-side decode/verify
code. Certificate material is synthetic stand-ins shaped like the eMudhra case
(both identities issued by one compromised CA); no key material is read from or
written to secrets/. The update bodies are valid Brotli lab markers - no
malformed stream, no exploit payload.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "poc/vendor"))

import chain_demo
import answer_inject
import doh_mitm


class ChainDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="chain-test-")
        cls.addClassCleanup(cls.work.cleanup)
        cls.dir = Path(cls.work.name)
        cls.material = chain_demo.build_synthetic_material(
            cls.dir, chain_demo.TARGET_NAME,
            extra_sans=[answer_inject.TARGET_NAME, answer_inject.OUT_OF_ZONE_NAME])
        cls.material["work"] = str(cls.dir)
        cls.registry = chain_demo.mock_registry.Registry()
        cls.addClassCleanup(cls.registry.tmp.cleanup)
        cls.registry_dir = cls.dir / "registry"
        chain_demo.mock_registry.export_registry(cls.registry, str(cls.registry_dir))
        cls.pinned = cls.registry.public_key
        cls.endpoints = chain_demo.start_endpoints(cls.material, str(cls.registry_dir),
                                                   port_hint=9701, log_dir=cls.dir / "logs")
        cls.addClassCleanup(chain_demo.stop_endpoints, cls.endpoints)
        cls.by_role = {"fake": cls.endpoints["fake"][:2], "true": cls.endpoints["true"][:2]}
        cls.fixture = chain_demo.DnsFixture()
        cls.fixture.start()
        cls.addClassCleanup(cls.fixture.stop)
        cls.decode_calls = []

    def leg(self, flavor, endpoint, dns_policy="follow", artifact="br", resolver=None,
            target_name=None, **kwargs):
        self.decode_calls.clear()

        def counting_decode(body):
            self.decode_calls.append(body)
            return chain_demo.kirimochi.decode_brotli(body)[0]

        evidence = chain_demo.run_leg(
            flavor, endpoint, target_name or chain_demo.TARGET_NAME,
            dns_policy=dns_policy, artifact=artifact,
            pinned_key_pem=self.pinned,
            compromised_meta=self.material["compromised_meta"],
            trust_root=self.material["roots"],
            endpoints_by_role=self.by_role, resolver=resolver,
            decode_hook=counting_decode, **kwargs)
        evidence["observed_decode_calls"] = len(self.decode_calls)
        return evidence

    @staticmethod
    def stages(evidence):
        return {stage["stage"]: stage for stage in evidence["stages"]}

    def assert_stage_order(self, evidence, expected):
        names = [stage["stage"] for stage in evidence["stages"]]
        self.assertEqual(names, expected)

    # ---- the attack path (trigger arm (a) with an explicit endpoint) -------

    def test_L1_legacy_reaches_the_decoder_on_one_path(self):
        evidence = self.leg("legacy", self.by_role["fake"])
        by_stage = self.stages(evidence)
        self.assert_stage_order(evidence, ["dns", "tls", "update-feed", "update-body"])
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVER_BYPASSED")
        self.assertEqual(by_stage["tls"]["decision"], "TLS_ACCEPTED")
        self.assertEqual(by_stage["tls"]["tls_class"], "forged")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "attacker")
        self.assertEqual(by_stage["update-body"]["decode_calls"], 1)
        self.assertEqual(evidence["observed_decode_calls"], 1)
        self.assertTrue(evidence["chain_complete"])

    def test_L2_hardened_breaks_the_chain_at_tls(self):
        evidence = self.leg("hardened", self.by_role["fake"])
        by_stage = self.stages(evidence)
        self.assert_stage_order(evidence, ["dns", "tls"])
        self.assertEqual(by_stage["tls"]["decision"], "TLS_REJECTED")
        self.assertEqual(by_stage["tls"]["tls_class"], "forged")
        self.assertTrue(by_stage["tls"].get("reason"))
        self.assertEqual(evidence["observed_decode_calls"], 0)
        self.assertFalse(evidence["chain_complete"])

    def test_L3_update_control_survives_the_tls_control(self):
        """If C2 falls, the hardened update policy still blocks the body."""
        evidence = self.leg("legacy-tls-hardened-update", self.by_role["fake"])
        by_stage = self.stages(evidence)
        self.assert_stage_order(evidence, ["dns", "tls", "update-feed", "update-body"])
        self.assertEqual(by_stage["tls"]["decision"], "TLS_ACCEPTED")
        self.assertEqual(by_stage["update-body"]["decision"], "SIG_REJECTED")
        self.assertEqual(by_stage["update-body"]["decode_calls"], 0)
        self.assertEqual(evidence["observed_decode_calls"], 0,
                         "the decoder must not be reached on the hardened update path")

    def test_crl_revocation_alone_rejects_the_forged_chain(self):
        def counting_decode(body):  # pragma: no cover - must never run
            raise AssertionError("decoder must not run")
        evidence = chain_demo.run_leg(
            "legacy", self.by_role["fake"], chain_demo.TARGET_NAME,
            pinned_key_pem=self.pinned,
            compromised_meta=self.material["compromised_meta"],
            crl=self.material["crl"], trust_root=self.material["roots"],
            decode_hook=counting_decode)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["tls"]["decision"], "TLS_REJECTED")

    # ---- required negative controls --------------------------------------

    def test_N0_reresolve_policy_reaches_the_true_endpoint(self):
        resolver = chain_demo.TriggerResolver("referral", fixture=self.fixture)
        evidence = self.leg("legacy", self.by_role["fake"], dns_policy="reresolve",
                            resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_TRUE")
        self.assertEqual(by_stage["dns"]["endpoint_role"], "true")
        self.assertEqual(by_stage["tls"]["tls_class"], "other",
                         "the true endpoint serves the ordinary chain")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "genuine")
        self.assertTrue(evidence["chain_complete"])

    def test_N1_N2_true_endpoint_genuine_flow_in_both_flavors(self):
        for flavor in ("legacy", "hardened"):
            with self.subTest(flavor=flavor):
                evidence = self.leg(flavor, self.by_role["true"], dns_policy="reresolve")
                by_stage = self.stages(evidence)
                self.assertEqual(by_stage["tls"]["decision"], "TLS_ACCEPTED")
                self.assertNotEqual(by_stage["tls"]["tls_class"], "forged")
                self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
                self.assertEqual(by_stage["update-body"]["variant"], "genuine")
                self.assertTrue(evidence["chain_complete"])

    def test_N3_N4_uncompressed_body_accepted_in_both_flavors(self):
        for flavor in ("legacy", "hardened"):
            with self.subTest(flavor=flavor):
                evidence = self.leg(flavor, self.by_role["true"],
                                    dns_policy="reresolve", artifact="plain")
                by_stage = self.stages(evidence)
                self.assertEqual(by_stage["tls"]["decision"], "TLS_ACCEPTED")
                self.assertEqual(by_stage["update-body"]["decision"], "ACCEPTED")
                self.assertEqual(evidence["observed_decode_calls"], 0)
                self.assertTrue(evidence["chain_complete"])

    # ---- trigger arm (a): the forged referral walked by the stand-in ------

    def test_trigger_a_follow_policy_walks_the_forged_referral(self):
        resolver = chain_demo.TriggerResolver("referral", fixture=self.fixture)
        evidence = self.leg("legacy", self.by_role["fake"], dns_policy="follow",
                            resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["trigger"], "referral")
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_FAKE")
        self.assertTrue(by_stage["dns"]["steered_by_additional"])
        self.assertEqual(evidence["leg"]["endpoint_role"], "fake")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "attacker")

    # ---- trigger arm (b): DoH MITM with the forged-CA certificate ---------

    def start_doh(self):
        cert = chain_demo.make_doh_cert(self.dir / "doh", self.material)
        answer_map = doh_mitm.AnswerMap({chain_demo.TARGET_NAME: [chain_demo.FAKE_ADDR]})
        server, thread, port = doh_mitm.start_doh(cert["cert"], cert["key"], answer_map)
        self.addCleanup(server.shutdown)
        return {"host": "127.0.0.1", "port": port, "server_hostname": chain_demo.DOH_HOST}, answer_map

    def test_trigger_b_doh_mitm_injects_the_attacker_answer(self):
        doh, answer_map = self.start_doh()
        resolver = chain_demo.TriggerResolver(
            "doh-mitm", doh=doh, trust_root=self.material["roots"],
            compromised_meta=self.material["compromised_meta"])
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["trigger"], "doh-mitm")
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_FAKE")
        self.assertEqual(by_stage["dns"]["answers"][0]["address"], chain_demo.FAKE_ADDR)
        self.assertEqual(evidence["leg"]["endpoint_role"], "fake")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "attacker")

    def test_trigger_b_hardened_client_refuses_the_forged_doh_certificate(self):
        doh, _ = self.start_doh()
        # The hardened client distrusts the compromised issuer BEFORE believing
        # any answer: the DoH certificate is refused at the TLS layer.
        resolver = chain_demo.TriggerResolver(
            "doh-mitm", doh=doh, trust_root=self.material["roots"],
            compromised_meta=self.material["compromised_meta"])
        def strict_checker(tls_socket):
            return chain_demo.classify_peer(tls_socket, self.material["compromised_meta"])
        import ssl as _ssl
        context = _ssl.create_default_context(cafile=self.material["roots"])
        record = doh_mitm.doh_query(doh["host"], doh["port"], chain_demo.TARGET_NAME, context,
                                    server_hostname=doh["server_hostname"],
                                    peer_checker=strict_checker)
        self.assertEqual(record["decision"], "TLS_REJECTED")
        self.assertEqual(record["doh_cert"]["tls"], "forged")
        self.assertIn("known-compromised", record["reason"])
        # And the hardened leg stops at the DNS stage: nothing is believed.
        evidence = self.leg("hardened", self.by_role["fake"], resolver=resolver)
        self.assertEqual(self.stages(evidence)["dns"]["decision"], "TLS_REJECTED")
        self.assertFalse(evidence["chain_complete"])
        self.assertEqual(evidence["observed_decode_calls"], 0)

    def test_trigger_b_legacy_client_trusts_the_forged_doh_certificate(self):
        """The incident condition: trust without effective revocation."""
        doh, _ = self.start_doh()
        import ssl as _ssl
        context = _ssl.create_default_context(cafile=self.material["roots"])
        record = doh_mitm.doh_query(doh["host"], doh["port"], chain_demo.TARGET_NAME, context,
                                    server_hostname=doh["server_hostname"])
        self.assertEqual(record["decision"], "RESOLVED")
        self.assertEqual(record["answers"][0]["address"], chain_demo.FAKE_ADDR)

    # ---- trigger arm (c): plain-UDP injection baseline --------------------

    def test_trigger_c_udp_injection_baseline(self):
        answer_map = doh_mitm.AnswerMap({chain_demo.TARGET_NAME: [chain_demo.FAKE_ADDR]})
        inject, servers, port = doh_mitm.start_udp(answer_map)
        self.addCleanup(lambda: doh_mitm.stop_udp(servers))
        resolver = chain_demo.TriggerResolver("udp-injection",
                                              udp={"host": "127.0.0.1", "port": port})
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["trigger"], "udp-injection")
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_FAKE")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "attacker")

    # ---- trigger (d): dangling delegation (re-registered NS name) ---------

    def test_trigger_d_dangling_delegation_lands_at_the_attacker(self):
        """One lapsed + re-registered external NS name; NO forged ADDITIONAL."""
        fixture = chain_demo.DnsFixture(mode="dangling")
        fixture.start()
        self.addCleanup(fixture.stop)
        resolver = chain_demo.TriggerResolver("dangling", fixture=fixture)
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["trigger"], "dangling")
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_FAKE")
        self.assertEqual(by_stage["dns"]["policy"], "reresolve")
        self.assertFalse(by_stage["dns"]["steered_by_additional"],
                         "the dangling scenario has no forged ADDITIONAL at all")
        self.assertEqual(evidence["leg"]["endpoint_role"], "fake")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "attacker")

    def test_trigger_d_control_true_operator_keeps_the_ns_name(self):
        """Negative control: same delegation, NS name still operator-owned."""
        fixture = chain_demo.DnsFixture(mode="dangling-control")
        fixture.start()
        self.addCleanup(fixture.stop)
        resolver = chain_demo.TriggerResolver("dangling", fixture=fixture)
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_TRUE")
        self.assertEqual(by_stage["tls"]["tls_class"], "other",
                         "the true operator endpoint serves the ordinary chain")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "genuine")

    # ---- trigger (e): forged HTTPS/SVCB record with the A record correct ---

    def start_svcb(self, with_https_rr):
        records = ({chain_demo.TARGET_NAME: {"priority": 1, "target": ".",
                                             "ipv4hint": [chain_demo.DnsFixture.FAKE_MARKER]}}
                   if with_https_rr else None)
        answer_map = doh_mitm.AnswerMap(
            {chain_demo.TARGET_NAME: [chain_demo.DnsFixture.TRUE_MARKER]},
            https_records=records)
        inject, servers, port = doh_mitm.start_udp(answer_map)
        self.addCleanup(lambda: doh_mitm.stop_udp(servers))
        return {"host": "127.0.0.1", "port": port}

    def test_trigger_e_https_record_redirects_while_the_a_record_is_correct(self):
        udp = self.start_svcb(with_https_rr=True)
        # The causal claim is narrow and checkable: the A answer is the TRUE
        # address; only the forged HTTPS record (RFC 9460) points at the
        # attacker, and an HTTPS-RR-honoring client (Chromium, hence Electron)
        # follows it.
        record = doh_mitm.svcb_query(udp["host"], udp["port"], chain_demo.TARGET_NAME)
        self.assertEqual(record["a_address"], chain_demo.DnsFixture.TRUE_MARKER)
        self.assertTrue(record["redirected"])
        self.assertEqual(record["redirect_via"], "HTTPS RR (RFC 9460) ipv4hint")
        self.assertEqual(record["address"], chain_demo.DnsFixture.FAKE_MARKER)
        resolver = chain_demo.TriggerResolver("svcb", udp=udp)
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["trigger"], "svcb")
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_FAKE")
        self.assertTrue(by_stage["dns"]["redirected"])
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "attacker")

    def test_trigger_e_control_plain_answer_does_not_redirect(self):
        """Negative control: the same A answer without the HTTPS record."""
        udp = self.start_svcb(with_https_rr=False)
        record = doh_mitm.svcb_query(udp["host"], udp["port"], chain_demo.TARGET_NAME)
        self.assertEqual(record["a_address"], chain_demo.DnsFixture.TRUE_MARKER)
        self.assertFalse(record["redirected"])
        self.assertEqual(record["address"], chain_demo.DnsFixture.TRUE_MARKER)
        resolver = chain_demo.TriggerResolver("svcb", udp=udp)
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_TRUE")
        self.assertEqual(by_stage["update-body"]["variant"], "genuine")

    # ---- trigger (f): answer-section cache injection (PowerDNS axis) --------

    def start_answer_inject(self, resolver_class="pdns", poison_owner=None):
        chain, stop = answer_inject.start_answer_inject(
            resolver_class=resolver_class,
            poison_owner=poison_owner or answer_inject.TARGET_NAME,
            prime_delay=1.1, workdir=self.dir)
        self.addCleanup(stop)
        return chain

    def test_trigger_f_fixture_matches_the_measured_p5_shapes(self):
        """The (f) fixture reproduces the exact p5 variants - different-zone
        owner ACCEPT vs out-of-zone REJECT (matrix-2026-10-27-p5)."""
        self.assertEqual(
            answer_inject.owner_kind(answer_inject.TARGET_NAME, answer_inject.PRIME_NAME),
            "different-zone", "the poisoned owner is the measured accepting variant")
        self.assertEqual(
            answer_inject.owner_kind(answer_inject.OUT_OF_ZONE_NAME, answer_inject.PRIME_NAME),
            "out-of-zone", "the out-of-tree owner is the measured rejecting variant")

    def test_trigger_f_pdns_class_caches_the_unsolicited_answer(self):
        chain = self.start_answer_inject(resolver_class="pdns")
        self.assertTrue(chain["backend"], "the resolver backend must be labelled")
        resolver = chain_demo.TriggerResolver("answer-inject", chain=chain)
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver,
                            target_name=answer_inject.TARGET_NAME)
        by_stage = self.stages(evidence)
        self.assert_stage_order(evidence,
                                ["dns-prime", "dns", "tls", "update-feed", "update-body"])
        self.assertEqual(by_stage["dns-prime"]["decision"], "PRIMED")
        # Measured behavior: the RELAYED answer is sanitized - the priming
        # response carries only the query's own owner.
        self.assertEqual([a["name"].rstrip(".") for a in by_stage["dns-prime"]["answers"]],
                         [answer_inject.PRIME_NAME])
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_FAKE")
        proof = by_stage["dns"]["cache_proof"]
        self.assertTrue(proof["cached"], proof)
        self.assertEqual(proof["authoritative_ttl"], 300)
        self.assertLessEqual(proof["ttl_first"], 300)
        self.assertLess(proof["ttl_second"], proof["ttl_first"],
                        "a decaying TTL can only come from a cache (p5 probe: 300 -> 297)")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "attacker")

    def test_trigger_f_unbound_class_rejects_and_reaches_genuine_flow(self):
        chain = self.start_answer_inject(resolver_class="unbound")
        resolver = chain_demo.TriggerResolver("answer-inject", chain=chain)
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver,
                            target_name=answer_inject.TARGET_NAME)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_TRUE",
                         "the measured REJECT class still resolves to the true address")
        self.assertEqual(by_stage["tls"]["tls_class"], "other")
        self.assertEqual(by_stage["update-body"]["decision"], "DECODED")
        self.assertEqual(by_stage["update-body"]["variant"], "genuine")

    def test_trigger_f_unprimed_query_is_nxdomain_or_true(self):
        chain = self.start_answer_inject(resolver_class="pdns")
        record = doh_mitm.udp_query(chain["host"], chain["port"], answer_inject.TARGET_NAME)
        addresses = [a["address"] for a in record.get("answers") or []]
        self.assertNotIn(answer_inject.POISON_ADDR, addresses,
                         "without priming there is no injected answer")
        self.assertIn(addresses, ([], [answer_inject.TRUE_ADDR]))

    def test_trigger_f_out_of_zone_owner_is_rejected(self):
        """The measured REJECT variant on the same PowerDNS-class resolver."""
        chain = self.start_answer_inject(resolver_class="pdns",
                                         poison_owner=answer_inject.OUT_OF_ZONE_NAME)
        resolver = chain_demo.TriggerResolver("answer-inject", chain=chain)
        evidence = self.leg("legacy", self.by_role["fake"], resolver=resolver,
                            target_name=answer_inject.OUT_OF_ZONE_NAME)
        by_stage = self.stages(evidence)
        self.assertEqual(by_stage["dns"]["decision"], "RESOLVED_TRUE",
                         "measured note: 'third-party name still resolves to the true address'")
        self.assertEqual(by_stage["update-body"]["variant"], "genuine")

    # ---- evidence and runtime recording ----------------------------------

    def test_evidence_json_records_per_stage_markers_and_runtimes(self):
        out = self.dir / "evidence"
        resolver = chain_demo.TriggerResolver("referral", fixture=self.fixture)
        chain_demo.run_matrix(self.material, str(self.registry_dir), self.endpoints,
                              pinned_key_pem=self.pinned, out_dir=out, trigger=resolver)
        path = out / "chain-evidence.json"
        self.assertTrue(path.exists())
        data = json.loads(path.read_text())
        self.assertEqual(data["schema"], "integrated-chain/1")
        self.assertIn("python", data["runtimes"])
        self.assertIn("openssl", data["runtimes"])
        self.assertIn("brotli_decoder", data["runtimes"])
        names = [leg["name"] for leg in data["legs"]]
        self.assertIn("L1-attack-legacy", names)
        self.assertIn("N0-reresolve-true-genuine", names)
        self.assertIn("N4-plain-body-hardened", names)
        for run in data["runs"]:
            with self.subTest(leg=run["leg"]["name"]):
                self.assertTrue(run["stages"], "every leg records its stages")
                for stage in run["stages"]:
                    if "decision" in stage:
                        self.assertIn(stage["decision"], chain_demo.DECISIONS)
                self.assertIn("runtimes", run)
                self.assertTrue(Path(run["evidence_file"]).exists())
        decisions = {run["leg"]["name"]: [s.get("decision") for s in run["stages"]]
                     for run in data["runs"]}
        self.assertEqual(decisions["L1-attack-legacy"][-1], "DECODED")
        self.assertEqual(decisions["L2-attack-hardened"][-1], "TLS_REJECTED")
        self.assertEqual(decisions["L3-legacy-tls-hardened-update"][-1], "SIG_REJECTED")
        self.assertEqual(decisions["N0-reresolve-true-genuine"][-1], "DECODED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
