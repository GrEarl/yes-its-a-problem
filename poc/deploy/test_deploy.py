"""Offline regression tests. Uses freshly generated synthetic keys only."""
import copy
import datetime as dt
import json
import os
import plistlib
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acceptance
import deploy
import material
import remote
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def config():
    cfg = json.loads((deploy.HERE / "config.example.json").read_text())
    # Data-only examples: every SSH/network function is mocked in this suite.
    for role, ip in zip(deploy.ROLES, ("1.1.1.1", "8.8.8.8", "9.9.9.9")):
        cfg["hosts"][role] = {"ipv4": ip, "ssh": "test-" + role}
    # The child-NS contract addresses follow the true/fake VPS inputs.
    cfg["child_ns"]["true_ip"] = cfg["hosts"]["true"]["ipv4"]
    cfg["child_ns"]["fake_ip"] = cfg["hosts"]["fake"]["ipv4"]
    return cfg


class DeploymentTests(unittest.TestCase):
    def test_default_config_is_unassigned_and_preflight_never_connects(self):
        cfg = deploy.load_config(deploy.HERE / "config.example.json")
        with patch.object(deploy.subprocess, "run", side_effect=AssertionError("offline command connected")):
            rows = deploy.check(cfg)
        self.assertTrue(any(r["status"] == "PENDING" and "IPv4" in r["description"] for r in rows))
        self.assertTrue(any(r["scope"] == "external" and r["status"] == "PENDING" for r in rows))

    def test_unsupported_dns_contract_blocks_apply_prerequisites(self):
        with patch.object(deploy, "dns_contract", return_value=False):
            with self.assertRaisesRegex(ValueError, "lacks --child-ns"):
                deploy.require(config(), "dns")

    def test_dns_prerequisites_pass_once_child_ns_inputs_are_assigned(self):
        deploy.require(config(), "dns")

    def test_child_ns_config_fields_drive_the_record_plan(self):
        cfg = config()
        name, (true_ip, fake_ip) = deploy.child_ns_name(cfg), deploy.child_ns_addresses(cfg)
        self.assertEqual(name, deploy.CHILD_NS)
        plan = deploy.cloudflare_records(cfg)
        child_rows = [r for r in plan if r["name"].lower() == name]
        self.assertEqual([(r["type"], r["content"]) for r in child_rows], [("A", true_ip)])
        self.assertFalse(any(r.get("content") == fake_ip for r in plan))
        contract = deploy.child_ns_plan(cfg)
        self.assertTrue(contract["parent_side_a"]["cloudflare_record"])
        self.assertFalse(contract["referral_additional"]["cloudflare_record"])
        self.assertEqual(contract["referral_additional"]["content"], fake_ip)
        for role in deploy.ROLES:
            self.assertIn("--child-ns " + name, deploy.units(cfg, role, "dns")["yip-dns.service"])

    def test_reject_child_ns_inside_provider_zone_and_mismatched_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            cfg = config()
            cfg["child_ns"]["name"] = "ns.true." + deploy.LAB
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "outside the delegated provider zone"):
                deploy.load_config(path)
            cfg = config()
            cfg["child_ns"]["name"] = "ns-child.example.com"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "managed parent zone"):
                deploy.load_config(path)
            cfg = config()
            cfg["child_ns"]["name"] = deploy.PROVIDER_NS
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "provider NS name"):
                deploy.load_config(path)
            cfg = config()
            cfg["child_ns"]["true_ip"] = "1.1.1.1"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "must match hosts.true.ipv4"):
                deploy.load_config(path)
            cfg = config()
            cfg["child_ns"]["fake_ip"] = "192.0.2.1"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "public IPv4 unicast"):
                deploy.load_config(path)
            cfg = config()
            cfg["child_ns"]["fake_ip"] = None
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "assigned together"):
                deploy.load_config(path)

    def test_preflight_child_ns_rows_track_unassigned_vps_inputs(self):
        cfg = deploy.load_config(deploy.HERE / "config.example.json")
        # Isolate from any machine-local deploy state: with an absent state dir
        # the leaf inputs stay unassigned and preflight must stay offline.
        with tempfile.TemporaryDirectory() as td:
            cfg["state_dir"] = os.path.join(td, "absent-state")
            with patch.object(deploy.subprocess, "run", side_effect=AssertionError("offline command connected")):
                rows = deploy.check(cfg)
        self.assertFalse(any(r["status"] == "BLOCKED" for r in rows))
        self.assertTrue(all(r["status"] in ("PASS", "PENDING") for r in rows))
        child_rows = [r for r in rows if "child NS" in r["description"]]
        self.assertTrue(any(r["status"] == "PASS" and "outside the delegated provider zone" in r["description"]
                            for r in child_rows))
        self.assertTrue(all("unassigned" in r["description"] for r in child_rows if r["status"] == "PENDING"))
        full = deploy.check(config())
        self.assertFalse(any(r["status"] == "PENDING" and "child NS" in r["description"] for r in full))
        self.assertTrue(any(r["status"] == "PASS" and "never publishes the contradictory ADDITIONAL" in r["description"]
                            for r in full))

    def test_acceptance_referral_contract_matches_the_lab_dns_fixture(self):
        cfg = config()
        name, (true_ip, fake_ip) = deploy.child_ns_name(cfg), deploy.child_ns_addresses(cfg)
        referral = {"rcode": "NOERROR", "aa": False,
                    "authority": [{"type": "NS", "name": material.CHILD, "value": name + ".", "ttl": 0}],
                    "additional": [{"type": "A", "name": name, "value": fake_ip, "ttl": 0}]}
        parent = {"answers": [{"type": "A", "name": name, "value": true_ip, "ttl": 0}]}
        self.assertEqual(acceptance.child_ns_contract_failures(referral, parent, cfg), [])
        lying = copy.deepcopy(referral)
        lying["additional"] = [{"type": "A", "name": name, "value": true_ip, "ttl": 0}]
        self.assertTrue(any("ADDITIONAL" in f for f in acceptance.child_ns_contract_failures(lying, parent, cfg)))
        in_zone_fixture = copy.deepcopy(referral)
        in_zone_fixture["authority"] = [{"type": "NS", "name": material.CHILD,
                                         "value": "ns.true." + deploy.LAB + ".", "ttl": 0}]
        self.assertTrue(any("external NS name" in f
                            for f in acceptance.child_ns_contract_failures(in_zone_fixture, parent, cfg)))
        missing = copy.deepcopy(referral)
        missing["additional"] = []
        self.assertTrue(any("fake address" in f for f in acceptance.child_ns_contract_failures(missing, parent, cfg)))
        drifted = copy.deepcopy(parent)
        drifted["answers"] = [{"type": "A", "name": name, "value": fake_ip, "ttl": 0}]
        self.assertTrue(any("true address" in f for f in acceptance.child_ns_contract_failures(referral, drifted, cfg)))
        unassigned = config()
        unassigned["child_ns"]["true_ip"] = unassigned["child_ns"]["fake_ip"] = None
        self.assertTrue(acceptance.child_ns_contract_failures(referral, parent, unassigned))

    def test_allowlisted_source_syntax_error_becomes_blocked_row(self):
        cfg = config()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "poc/lab/dns").mkdir(parents=True)
            (root / "poc/lab/dns/lab_dns.py").write_text('ARG = "--child-ns"')
            (root / "poc/lab/http").mkdir(parents=True)
            (root / "poc/lab/http/lab_http.py").write_text("def broken(:")
            with patch.object(deploy, "ROOT", root), patch.object(deploy, "PUBLIC_FILES", ["poc/lab/http/lab_http.py"]):
                rows = deploy.check(cfg)
        row = next(r for r in rows if r["scope"] == "local")
        self.assertEqual(row["status"], "BLOCKED")
        self.assertIn("does not parse", row["description"])

    def test_reject_same_machine_alias_and_documentation_ips(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            cfg = config()
            cfg["hosts"]["fake"]["ssh"] = cfg["hosts"]["true"]["ssh"]
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "distinct SSH"):
                deploy.load_config(path)
            cfg = config()
            cfg["hosts"]["provider"]["ipv4"] = "192.0.2.1"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "public IPv4"):
                deploy.load_config(path)
            cfg["hosts"]["provider"]["ipv4"] = "224.0.0.1"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "unicast"):
                deploy.load_config(path)

    def test_reject_public_or_permissive_state_directory(self):
        cfg = config()
        cfg["state_dir"] = str(deploy.ROOT / "docs/private-state")
        with self.assertRaisesRegex(ValueError, "beneath ignored secrets"):
            deploy.private_state(cfg)
        with tempfile.TemporaryDirectory() as directory:
            cfg["state_dir"] = directory
            os.chmod(directory, 0o755)
            with self.assertRaisesRegex(ValueError, "0700"):
                deploy.private_state(cfg)

    def test_units_use_exact_roles_and_no_request_logging(self):
        for role in deploy.ROLES:
            result = deploy.units(config(), role, "https")
            dns = result["yip-dns.service"]
            self.assertIn("--child-ns " + deploy.child_ns_name(config()), dns)
            self.assertIn("--bind " + config()["hosts"][role]["ipv4"], dns)
            for unit in result.values():
                command = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
                self.assertNotIn("--log", command)
                self.assertIn("ProtectSystem=strict", unit)
                self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE", unit)
            if role == "provider":
                self.assertNotIn("yip-http.service", result)
            else:
                self.assertIn("--registry-dir /opt/yip/poc/deploy/public-registry", result["yip-http.service"])
                self.assertEqual("--forged-cert" in result["yip-http.service"], role == "fake")

    def test_provider_bundle_has_no_leaf_or_registry_material(self):
        payload = deploy.install_payload(config(), "provider", "dns")
        self.assertEqual(payload["certs"], {})
        self.assertTrue(all(f == "LICENSE" or f.startswith("poc/vendor/") or f == "poc/lab/dns/lab_dns.py"
                            for f in payload["files"]))
        self.assertFalse(any("secrets" in f or "recover_keys" in f or "make_leaf" in f for f in remote.PUBLIC_FILES))

    def test_transfer_rejects_path_traversal_and_unlisted_keys(self):
        for name in ("../secret", "/etc/shadow", "secrets/ca.key.pem"):
            with self.assertRaisesRegex(ValueError, "allowlist"):
                remote.decode_files({name: "YWJj"}, remote.PUBLIC_FILES)

    def test_atomic_file_update_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(remote.os, "chown"):
            path = Path(directory) / "challenges.json"
            remote.atomic_write(path, b"{}\n")
            before = path.stat().st_mtime_ns
            remote.atomic_write(path, b"{}\n")
            self.assertEqual(before, path.stat().st_mtime_ns)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "symlink"):
                remote.atomic_write(link, b"changed")

    def test_challenges_publish_same_values_and_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = config()
            cfg["state_dir"] = directory
            sent = []
            def capture(_cfg, role, request):
                sent.append((role, copy.deepcopy(request)))
            env = {"CERTBOT_DOMAIN": material.CHILD, "CERTBOT_VALIDATION": "test_token"}
            with patch.dict(os.environ, env), patch.object(deploy, "remote", side_effect=capture), \
                    patch.object(deploy, "query_txt", return_value={"test_token"}):
                deploy.hook(cfg, "auth")
                deploy.hook(cfg, "auth")
                deploy.hook(cfg, "cleanup")
                deploy.hook(cfg, "cleanup")
            self.assertEqual([r for r, _ in sent], ["true", "fake"] * 4)
            self.assertEqual(sent[0][1]["values"], sent[1][1]["values"])
            self.assertEqual(sent[0][1]["values"], sent[2][1]["values"])
            self.assertEqual(sent[-1][1]["values"], {})

    def test_schedule_only_renders_files_without_starting_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = config()
            cfg["state_dir"] = directory
            with patch.object(deploy, "require"), patch.object(deploy.shutil, "which", return_value="/usr/bin/certbot"), \
                    patch.object(deploy.subprocess, "run", side_effect=AssertionError("scheduler started")):
                deploy.schedule(cfg, Path(directory) / "config with spaces.json")
            data = plistlib.loads((Path(directory) / "schedule/com.yip.renew.plist").read_bytes())
            self.assertEqual(data["ProgramArguments"][-1], "renew")
            self.assertEqual(data["ProgramArguments"][-2], str(Path(directory) / "config with spaces.json"))
            self.assertIn("Persistent=true", (Path(directory) / "schedule/yip-renew.timer").read_text())

    def test_registry_fixture_contains_public_files_only(self):
        directory = deploy.HERE / "public-registry"
        self.assertEqual({p.name for p in directory.iterdir()},
                         {"manifest.json", "manifest.sig.b64", "public_key.pem", "package.tar.gz",
                          "update_feed.json", "update_body.br", "update_body.json",
                          "update_body.attacker.br", "update_body.attacker.json"})
        self.assertFalse(any(b"PRIVATE KEY" in p.read_bytes() for p in directory.iterdir()))


class MaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.now = dt.datetime.now(dt.timezone.utc)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic unit test CA")])
        self.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(self.now - dt.timedelta(days=1)).not_valid_after(self.now + dt.timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(self.ca_key, hashes.SHA256()))

    def tearDown(self):
        self.temp.cleanup()

    def leaf(self, names=None, expired=False):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test leaf")])
        return (x509.CertificateBuilder().subject_name(name).issuer_name(self.ca.subject)
                .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(self.now - dt.timedelta(days=2))
                .not_valid_after(self.now + dt.timedelta(days=-1 if expired else 5))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in
                              (names or ["*." + material.CHILD])]), critical=False)
                .sign(self.ca_key, hashes.SHA256()))

    def inputs(self, leaf=None, key=None, extra=b""):
        cert_path, key_path = self.directory / "fullchain.pem", self.directory / "leaf.key.pem"
        cert_path.write_bytes((leaf or self.leaf()).public_bytes(serialization.Encoding.PEM) +
                              self.ca.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes((key or self.key).private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + extra)
        key_path.chmod(0o600)
        return cert_path, key_path

    def test_valid_synthetic_leaf_and_canonical_private_key(self):
        extra_key = self.ca_key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cert, key, info = material.validate_leaf(*self.inputs(extra=extra_key), "normal", trust=False)
        self.assertEqual(key.count(b"BEGIN PRIVATE KEY"), 1)
        self.assertNotIn(extra_key, key)
        self.assertEqual(info["sans"], ["*." + material.CHILD])
        self.assertEqual(cert.count(b"BEGIN CERTIFICATE"), 2)

    def test_ca_key_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "CA certificates"):
            material.validate_leaf(*self.inputs(leaf=self.ca, key=self.ca_key), "normal", trust=False)

    def test_leaf_reusing_a_ca_key_is_rejected(self):
        self.key = self.ca_key
        with self.assertRaisesRegex(ValueError, "reuses a CA private key"):
            material.validate_leaf(*self.inputs(), "normal", trust=False)

    def test_mismatched_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "do not match"):
            material.validate_leaf(*self.inputs(key=self.ca_key), "normal", trust=False)

    def test_external_sans_and_expired_leaf_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "owned lab names"):
            material.validate_leaf(*self.inputs(leaf=self.leaf(["other.example"])), "normal", trust=False)
        with self.assertRaisesRegex(ValueError, "expired"):
            material.validate_leaf(*self.inputs(leaf=self.leaf(expired=True)), "normal", trust=False)

    def test_insecure_private_key_permissions_are_rejected(self):
        paths = self.inputs()
        paths[1].chmod(0o644)
        with self.assertRaisesRegex(ValueError, "unsafe permissions"):
            material.validate_leaf(*paths, "normal", trust=False)

    def test_unrecognized_forged_issuer_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "published lab intermediate"):
            material.validate_leaf(*self.inputs(leaf=self.leaf(sorted(material.FORGED_NAMES))), "forged")


if __name__ == "__main__":
    unittest.main()
