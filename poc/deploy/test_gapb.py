"""Offline tests for the gap-B tester and the VPS-less deployment tool.

Loopback fixtures and synthetic configs only: no provider, tunnel, or registry
service is contacted, and no live run mode is entered.
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gapb_test
import secondary_deploy


def gapb_cfg(**override):
    cfg = {
        "tzone": "t.example",
        "victim_domain": "yourexample.net",
        "serial": 2026102701,
        "hidden_primary_ip": "192.0.2.53",
        "addresses": {"out_of_zone_a": "192.0.2.66",
                      "sub_delegation": "203.0.113.10", "www": "203.0.113.11"},
        "provider": {"adapter": "buddyns", "account": "me@example.net", "api_token": "token",
                     "tsig": None, "axfr_source_ips": ["192.0.2.200"],
                     "ns_names": ["ns1.provider.example"], "ns_ips": ["192.0.2.53"],
                     "ns_port": 53},
        "tenant_b": {"account": "me2@example.net", "ns_name": "ns.victim-own.yourexample.net",
                     "ns_ips": ["192.0.2.53"], "victim_real_ip": "203.0.113.77"},
        "checklist": {"own_names_confirmed": True, "tos_reviewed": True, "notify_vendor": True},
    }
    cfg.update(override)
    return cfg


class GapBZoneTests(unittest.TestCase):
    def test_zone_has_out_of_zone_owner_and_delegation(self):
        cfg = gapb_cfg()
        records = gapb_test.zone_records(cfg)
        owners = {(r["name"], r["type"]): r for r in records}
        self.assertIn(("victim-own.yourexample.net", "A"), owners)
        self.assertEqual(owners[("victim-own.yourexample.net", "A")]["rdata"], "192.0.2.66")
        self.assertIn(("sub.t.example", "NS"), owners)
        self.assertEqual(owners[("sub.t.example", "NS")]["rdata"],
                         "ns.victim-own.yourexample.net")
        text = gapb_test.render_zone(cfg)
        self.assertIn("victim-own.yourexample.net", text)
        self.assertIn("sub.t.example 300 IN NS ns.victim-own.yourexample.net", text)
        clean = gapb_test.render_zone(cfg, include_out_of_zone=False)
        self.assertNotIn("victim-own.yourexample.net 300 IN A", clean)
        self.assertIn("sub.t.example 300 IN NS ns.victim-own.yourexample.net", clean)
        fragment = gapb_test.named_conf_fragment(cfg, ["192.0.2.200"])
        self.assertIn("allow-transfer { 192.0.2.200; }", fragment)

    def test_probe_addresses_stay_in_test_net(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gapb.json"
            cfg = gapb_cfg()
            cfg["addresses"]["out_of_zone_a"] = "8.8.8.8"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(gapb_test.GapBError, "TEST-NET"):
                gapb_test.load_config(path)
            cfg = gapb_cfg()
            cfg["tzone"] = cfg["victim_domain"]
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(gapb_test.GapBError, "two different domains"):
                gapb_test.load_config(path)

    def test_f2_classifies_only_out_of_zone_emission_as_the_vector(self):
        self.assertEqual(gapb_test.classify_additional("ns.victim-own.yourexample.net",
                                                       "sub.t.example", "t.example"), "out-of-zone")
        self.assertEqual(gapb_test.classify_additional("ns.sub.t.example",
                                                       "sub.t.example", "t.example"),
                         "in-delegation-glue")
        self.assertEqual(gapb_test.classify_additional("other.t.example",
                                                       "sub.t.example", "t.example"), "sibling-like")

    def test_verdict_logic_success_partial_negative_abort(self):
        success = {"f1": {"status": "positive"}, "f2": {"status": "positive"}}
        partial = {"f1": {"status": "positive"}, "f2": {"status": "negative"}}
        negative = {"f1": {"status": "negative"}, "f2": {"status": "negative"}}
        self.assertEqual(gapb_test.decide_verdict(success)["verdict"], "SUCCESS")
        self.assertEqual(gapb_test.decide_verdict(partial)["verdict"], "PARTIAL")
        self.assertEqual(gapb_test.decide_verdict(negative)["verdict"], "NEGATIVE")
        self.assertEqual(gapb_test.decide_verdict(success, abort_reason="ToS concern")["verdict"],
                         "ABORT")

    def test_selftest_exercises_all_verdict_paths(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = gapb_test.selftest()
        self.assertEqual(code, 0)
        text = out.getvalue()
        for expected in ("SUCCESS", "PARTIAL", "NEGATIVE", "ABORT", "cross-delegation",
                         "B-victim", "B-contamination", "attribution", "evidence"):
            self.assertIn(expected, text)


class GapBCheckTests(unittest.TestCase):
    def fixture(self, **behavior):
        cfg = gapb_cfg()
        server = gapb_test.FixtureServer(gapb_test.FixtureResolver(cfg, **behavior)).start()
        self.addCleanup(server.stop)
        return cfg, server.target

    def test_checks_and_cross_tenant_helpers_on_loopback_fixtures(self):
        cfg, target = self.fixture(allow_soa=True, store_out_of_zone=True, emit_additional=True)
        results = {"transfer": gapb_test.check_transfer(cfg, [target]),
                   "f1": gapb_test.check_f1(cfg, [target]),
                   "f2": gapb_test.check_f2(cfg, [target], repeats=2)}
        self.assertEqual(results["transfer"]["status"], "positive")
        self.assertEqual(results["f1"]["status"], "positive")
        self.assertEqual(results["f2"]["status"], "positive")
        self.assertEqual(results["f2"]["repeats"], 2)
        self.assertEqual(gapb_test.cross_delegation_check(cfg, results["f2"])["status"], "positive")
        self.assertEqual(gapb_test.b_victim_check(results["f2"], cfg["tenant_b"])["status"],
                         "positive")
        self.assertEqual(
            gapb_test.b_contamination_check(
                [{"answers": [{"type": "A", "value": "203.0.113.77"}]}], cfg["tenant_b"])["status"],
            "positive")
        self.assertEqual(gapb_test.attribution_check(cfg)["status"], "positive")

    def test_negative_controls_distinguish_the_vector(self):
        cfg, emitting = self.fixture(allow_soa=True, store_out_of_zone=True, emit_additional=True)
        _, clean = self.fixture(allow_soa=True, store_out_of_zone=True, emit_additional=False)
        self.assertEqual(gapb_test.control_primary_check(cfg, [emitting])["status"], "positive")
        self.assertEqual(gapb_test.control_variant_check(cfg, [clean])["status"], "positive")
        self.assertEqual(gapb_test.control_variant_check(cfg, [emitting])["status"], "negative")

    def test_evidence_bundle_writes_row_index_and_hashes(self):
        cfg = gapb_cfg()
        results = {"transfer": {"status": "positive"}, "f1": {"status": "positive"},
                   "f2": {"status": "positive"}, "cross_delegation": {"status": "positive"}}
        with tempfile.TemporaryDirectory() as directory:
            row = gapb_test.write_evidence(directory, cfg, results,
                                           {"verdict": "SUCCESS", "action": "-"},
                                           "cross-delegation",
                                           raw_files={"f2-referral-additional.txt": "raw"})
            self.assertTrue(row["f1_store"] and row["f2_emit"])
            self.assertEqual(row["cross_tenant"], "cross-delegation")
            self.assertIn("PowerDNS-class", row["implementation_guess"])
            self.assertEqual(row["vendor_notified_utc"], None)
            bundle = Path(directory)
            self.assertTrue((bundle / "evidence.json").is_file())
            self.assertTrue((bundle / "zone-served.txt").is_file())
            sums = (bundle / "SHA256SUMS.txt").read_text().splitlines()
            self.assertTrue(any(line.endswith("evidence.json") for line in sums))
            index = (bundle / "INDEX.txt").read_text().splitlines()
            self.assertIn("evidence.json", index)

    def test_adapters_are_plan_only_and_fail_closed(self):
        buddy = gapb_test.BuddyNSAdapter({"adapter": "buddyns"})
        plan = buddy.plan({"zone": "t.example", "master_ip": "192.0.2.53"})
        self.assertEqual(plan["api"]["create_secondary_zone"]["url"],
                         "https://www.buddyns.com/api/v2/zone/")
        self.assertIn("not sent", plan["note"])
        with self.assertRaisesRegex(gapb_test.GapBError, "own token|plan-only"):
            buddy.configure({"zone": "t.example"})
        generic = gapb_test.GenericAXFRAdapter({"adapter": "generic-axfr"})
        self.assertTrue(generic.plan({"zone": "t.example"})["console_fallback"])
        with self.assertRaisesRegex(gapb_test.GapBError, "console steps"):
            generic.configure({"zone": "t.example"})
        self.assertEqual(set(gapb_test.ADAPTERS), {"buddyns", "generic-axfr"})

    def test_preflight_fails_closed_until_credentials_and_checklist(self):
        missing = gapb_cfg(provider={"adapter": "buddyns", "account": None, "api_token": None,
                                     "ns_ips": [], "ns_names": []},
                           checklist={"own_names_confirmed": False, "tos_reviewed": False})
        rows = gapb_test.preflight(missing)
        blocked = [r for r in rows if r["status"] == "BLOCKED"]
        self.assertTrue(any("credentials" == r["scope"] for r in blocked))
        self.assertTrue(any("checklist" in r["description"] for r in blocked))
        rows = gapb_test.preflight(gapb_cfg())
        self.assertFalse(any(r["status"] == "BLOCKED" for r in rows))


class SecondaryDeployTests(unittest.TestCase):
    def config(self, **over):
        return secondary_deploy.merge(secondary_deploy.DEFAULTS, over)

    def write_config(self, cfg):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "secondary.json"
        path.write_text(json.dumps(cfg))
        return path

    def test_config_validation_enforces_external_child_ns_contract(self):
        path = self.write_config(self.config(
            child_ns={"name": "ns.lab.yes-its-a-problem.iamwonderingif.com"}))
        with self.assertRaisesRegex(secondary_deploy.DeployError, "OUTSIDE the provider zone"):
            secondary_deploy.load_config(path)
        path = self.write_config(self.config(child_ns={"name": "ns-child.example.com"}))
        with self.assertRaisesRegex(secondary_deploy.DeployError, "inside the domain"):
            secondary_deploy.load_config(path)
        path = self.write_config(self.config(child_ns={"fake_address": "8.8.8.8"}))
        with self.assertRaisesRegex(secondary_deploy.DeployError, "TEST-NET"):
            secondary_deploy.load_config(path)

    def test_plan_renders_roles_zone_tunnels_and_records(self):
        cfg = self.config(child_ns={"true_address": "192.0.2.10", "fake_address": "198.51.100.66"})
        text = secondary_deploy.plan_text(cfg)
        for marker in ("provider", "fake", "true", "cloudflared", "out-of-zone owner",
                       "ns-child.yes-its-a-problem.iamwonderingif.com. 300 IN A 198.51.100.66",
                       "fixture_only_never_a_record", "does not proxy DNS"):
            self.assertIn(marker, text)
        outputs = secondary_deploy.apply_outputs(cfg)
        self.assertEqual(sorted(outputs), ["cloudflared-fake.yml", "cloudflared-true.yml",
                                           "named.conf.fragment", "parent-records.json",
                                           "provider.zone", "role-commands.json"])
        records = json.loads(outputs["parent-records.json"])
        child_rows = [r for r in records["cloudflare_records_to_review"]
                      if r["name"] == "ns-child.yes-its-a-problem.iamwonderingif.com"]
        self.assertEqual([(r["type"], r["content"]) for r in child_rows], [("A", "192.0.2.10")])
        self.assertFalse(any(r.get("content") == "198.51.100.66"
                             for r in records["cloudflare_records_to_review"]))
        self.assertEqual(records["fixture_only_never_a_record"][0]["cloudflare_record"], False)

    def test_role_commands_follow_the_lab_contract(self):
        commands = secondary_deploy.role_commands(self.config())
        self.assertIn("--child-ns ns-child.yes-its-a-problem.iamwonderingif.com",
                      commands["true"]["dns"])
        self.assertIn("--role fake", commands["fake"]["dns"])
        self.assertIn("--forged-sni login.", commands["fake"]["https"])
        self.assertNotIn("--forged-cert", commands["true"]["https"])

    def test_preflight_fails_closed_until_user_credentials(self):
        rows = secondary_deploy.preflight(self.config())
        blocked = [r for r in rows if r["status"] == "BLOCKED"]
        self.assertTrue(any("account/API token missing" in r["description"] for r in blocked))
        self.assertTrue(any("tunnel token" in r["description"] for r in blocked))
        self.assertTrue(any("checklist not attested" in r["description"] for r in blocked))
        ready = self.config(
            secondary={"account": "me@example.net", "api_token": "token", "master_ip": "192.0.2.53",
                       "ns_names": ["ns1.provider.example"], "ns_ips": ["192.0.2.53"]},
            tunnels={"true": {"token": "t"}, "fake": {"token": "t"}},
            checklist={"own_domains_confirmed": True, "tos_reviewed": True},
            local={"normal_fullchain": "/x/fullchain.pem", "normal_key": "/x/key.pem",
                   "forged_fullchain": "/y/fullchain.pem", "forged_key": "/y/key.pem"})
        rows = secondary_deploy.preflight(ready)
        self.assertFalse(any(r["status"] == "BLOCKED" for r in rows))

    def test_apply_needs_execute_and_reviewed_plan(self):
        cfg = self.config(child_ns={"true_address": "192.0.2.10", "fake_address": "198.51.100.66"})
        path = self.write_config(cfg)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            argv = ["secondary_deploy.py", "apply", "--config", str(path), "--out", str(out)]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                self.assertEqual(secondary_deploy.main(), 0)
            self.assertFalse(out.exists())
            ready = self.config(
                secondary={"account": "me@example.net", "api_token": "token",
                           "master_ip": "192.0.2.53", "ns_names": ["ns1.provider.example"],
                           "ns_ips": ["192.0.2.53"]},
                tunnels={"true": {"token": "t"}, "fake": {"token": "t"}},
                checklist={"own_domains_confirmed": True, "tos_reviewed": True},
                local={"normal_fullchain": "/x/fullchain.pem", "normal_key": "/x/key.pem",
                       "forged_fullchain": "/y/fullchain.pem", "forged_key": "/y/key.pem"},
                child_ns={"true_address": "192.0.2.10", "fake_address": "198.51.100.66"})
            path = self.write_config(ready)
            argv = ["secondary_deploy.py", "apply", "--config", str(path), "--out", str(out),
                    "--execute", "--plan-reviewed"]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                self.assertEqual(secondary_deploy.main(), 0)
            self.assertTrue((out / "provider.zone").is_file())
            self.assertTrue((out / "cloudflared-true.yml").is_file())
            self.assertIn("http_status:404", (out / "cloudflared-fake.yml").read_text())

    def test_dry_run_modes_are_offline_and_green(self):
        path = self.write_config(self.config())
        for argv in (["secondary_deploy.py", "plan", "--config", str(path)],
                     ["secondary_deploy.py", "apply", "--config", str(path), "--out", "/tmp/x"]):
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                self.assertEqual(secondary_deploy.main(), 0)
        gapb_path = self.write_config(gapb_cfg())
        with patch.object(sys, "argv", ["gapb_test.py", "plan", "--config", str(gapb_path)]), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(gapb_test.main(), 0)


if __name__ == "__main__":
    unittest.main()
