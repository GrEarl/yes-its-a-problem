#!/usr/bin/env python3
"""VPS-less public deployment for the lab topology.

Local hidden primary + free secondary DNS as the public authority + cloudflared
tunnels for the HTTPS side. It reproduces the provider/fake/true role semantics
of poc/PLAN.md without three VPSs:

  provider  the free secondary DNS slaving this machine's hidden primary for the
            provider zone; its referral carries the child delegation to the
            external NS name and the contradictory ADDITIONAL fixture data.
  fake      local lab_dns/lab_http role "fake" (alternate address, forged leaf on
            login/pay/pkg SNI), HTTPS published through a cloudflared tunnel.
  true      local lab_dns/lab_http role "true" (normal address and leaf); the
            parent-side A record for the child NS name keeps pointing here.

Honest limits (kept in every plan output): cloudflared does not proxy DNS, so
the fake/true child authorities stay loopback fixtures unless a second secondary
or a reachable IP is added; the A values carry the DNS semantics and are TEST-NET
by default; reachability of demo content is via the tunnel hostnames.

Dry-run/plan is mandatory: apply refuses without --execute and a reviewed plan,
and preflight stays fail closed until the runner's own credentials exist. This
tool never contacts a provider or tunnel service from the authoring environment.

Usage:
    python3 poc/deploy/secondary_deploy.py plan --config secondary.json
    python3 poc/deploy/secondary_deploy.py preflight --config secondary.json
    python3 poc/deploy/secondary_deploy.py apply --config secondary.json --out DIR \
        --execute --plan-reviewed
    python3 poc/deploy/secondary_deploy.py serve-primary --config secondary.json --execute
"""
import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from gapb_test import (ADAPTERS, GapBError, is_test_net, named_conf_fragment, norm,
                       render_zone, serial_for, zone_records)

SCHEMA = "secondary-deploy-vpsless/1"

DEFAULTS = {
    "domain": "yes-its-a-problem.iamwonderingif.com",
    "zones": {
        "provider": "lab.yes-its-a-problem.iamwonderingif.com",
        "child": "v.lab.yes-its-a-problem.iamwonderingif.com",
    },
    "child_ns": {
        "name": "ns-child.yes-its-a-problem.iamwonderingif.com",
        "true_address": None,
        "fake_address": None,
    },
    "hidden_primary": {"host": "ns1.hidden.yes-its-a-problem.iamwonderingif.com",
                       "ip": None, "port": 53},
    "secondary": {"adapter": "buddyns", "account": None, "api_token": None,
                  "master_ip": None, "tsig": None, "axfr_source_ips": [],
                  "ns_names": [], "ns_ips": []},
    "tunnels": {
        "true": {"name": "yip-true", "token": None, "credentials_file": None,
                 "hostname": "true.yes-its-a-problem.iamwonderingif.com"},
        "fake": {"name": "yip-fake", "token": None, "credentials_file": None,
                 "hostname": "fake.yes-its-a-problem.iamwonderingif.com"},
    },
    "local": {"primary_port": 5353, "true_dns_port": 5354, "fake_dns_port": 5355,
              "true_https_port": 8443, "fake_https_port": 8444,
              "normal_fullchain": None, "normal_key": None,
              "forged_fullchain": None, "forged_key": None},
    "checklist": {"own_domains_confirmed": False, "tos_reviewed": False,
                  "notify_provider": True},
}


class DeployError(ValueError):
    pass


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

def in_zone(name, zone):
    name, zone = norm(name), norm(zone)
    return name == zone or name.endswith("." + zone)


def merge(base, override):
    out = dict(base)
    for key, value in (override or {}).items():
        out[key] = merge(base[key], value) if isinstance(value, dict) and isinstance(base.get(key), dict) else value
    return out


def load_config(path):
    raw = json.loads(Path(path).read_text()) if path else {}
    cfg = merge(DEFAULTS, raw)
    domain = norm(cfg["domain"])
    provider_zone = norm(cfg["zones"]["provider"])
    child_zone = norm(cfg["zones"]["child"])
    child_ns = norm(cfg["child_ns"]["name"])
    for label, name in (("domain", domain), ("zones.provider", provider_zone),
                        ("zones.child", child_zone), ("child_ns.name", child_ns)):
        if "." not in name:
            raise DeployError(label + " must be a fully qualified name")
    if not in_zone(provider_zone, domain) or provider_zone == domain:
        raise DeployError("zones.provider must sit inside the configured domain")
    if not in_zone(child_zone, provider_zone) or child_zone == provider_zone:
        raise DeployError("zones.child must sit inside the provider zone (lab contract)")
    if not in_zone(child_ns, domain) or in_zone(child_ns, provider_zone):
        raise DeployError("child_ns.name must be an ordinary record inside the domain and "
                          "OUTSIDE the provider zone (external child-NS contract)")
    if in_zone(child_ns, child_zone):
        raise DeployError("child_ns.name must sit outside the delegated child zone")
    for field in ("true_address", "fake_address"):
        value = cfg["child_ns"].get(field)
        if value is not None and not is_test_net(value):
            raise DeployError("child_ns." + field + " must stay in RFC 5737 TEST-NET: " + str(value))
    if cfg["child_ns"].get("true_address") and cfg["child_ns"].get("true_address") == cfg["child_ns"].get("fake_address"):
        raise DeployError("child_ns true_address and fake_address must differ (contradictory fixture)")
    if cfg["secondary"]["adapter"] not in ADAPTERS:
        raise DeployError("secondary.adapter must be one of " + ", ".join(sorted(ADAPTERS)))
    for role in ("true", "fake"):
        for field in ("name", "hostname"):
            if not cfg["tunnels"][role].get(field):
                raise DeployError("tunnels." + role + "." + field + " is required")
    return cfg


# --------------------------------------------------------------------------
# zone data + role map
# --------------------------------------------------------------------------

def provider_zone_cfg(cfg):
    """Shape expected by gapb_test's zone renderer for the provider zone."""
    return {
        "tzone": norm(cfg["zones"]["provider"]),
        "victim_domain": norm(cfg["domain"]),
        "primary_host": norm(cfg["hidden_primary"]["host"]),
        "hidden_primary_ip": cfg["hidden_primary"]["ip"] or "127.0.0.1",
        "addresses": {"out_of_zone_a": cfg["child_ns"]["fake_address"] or "198.51.100.66",
                      "sub_delegation": cfg["child_ns"]["true_address"] or "192.0.2.10",
                      "www": "203.0.113.11"},
        "serial": cfg.get("serial"),
        "ttl": 3600,
    }


def provider_zone_text(cfg):
    """Provider zone with the gap-B shape: child delegation + out-of-zone A owner.

    The out-of-zone A owner (child NS name -> fake address) is the fixture data
    the referral may emit as ADDITIONAL; the parent-side A record for the same
    name stays a real Cloudflare record at the TRUE address (see parent_records).
    """
    zone = norm(cfg["zones"]["provider"])
    child = norm(cfg["zones"]["child"])
    child_ns = norm(cfg["child_ns"]["name"])
    host = norm(cfg["hidden_primary"]["host"])
    fake = cfg["child_ns"]["fake_address"] or "198.51.100.66"
    serial = serial_for(provider_zone_cfg(cfg))
    ns_names = cfg["secondary"].get("ns_names") or ["<PROVIDER_NS_1>", "<PROVIDER_NS_2>"]
    lines = ["$ORIGIN " + zone + ".", "$TTL 3600",
             "@ 3600 IN SOA " + host + " hostmaster." + norm(cfg["domain"]) + ". (",
             "            %d ; serial (YYYYMMDDnn; bump on every edit)" % serial,
             "            3600 900 604800 300 )"]
    for name in ns_names:
        lines.append("@ 3600 IN NS " + name)
    lines.append(host + " 3600 IN A " + (cfg["hidden_primary"]["ip"] or "127.0.0.1"))
    lines.append(child + " 300 IN NS " + child_ns)
    lines.append(child_ns + ". 300 IN A " + fake +
                 "    ; out-of-zone owner: contradictory ADDITIONAL fixture data")
    return "\n".join(lines) + "\n"


def role_map(cfg):
    child_ns = norm(cfg["child_ns"]["name"])
    true_addr = cfg["child_ns"]["true_address"] or "<TEST-NET true>"
    fake_addr = cfg["child_ns"]["fake_address"] or "<TEST-NET fake>"
    return [
        {"role": "provider", "plan_semantics": "authoritative for the provider zone; serves the "
                                               "child delegation; referral ADDITIONAL for " + child_ns + " -> " + fake_addr,
         "vpsless": "free secondary DNS slaving this machine's hidden primary for the provider zone",
         "public": "the secondary provider's NS set (secondary.ns_names/ns_ips)"},
        {"role": "fake", "plan_semantics": "child-zone authority; alternate address " + fake_addr +
                                           " and HTTPS content (forged leaf on login/pay/pkg)",
         "vpsless": "local lab_dns role fake (port %d) + lab_http (port %d)" %
                    (cfg["local"]["fake_dns_port"], cfg["local"]["fake_https_port"]),
         "public": "cloudflared tunnel hostname " + cfg["tunnels"]["fake"]["hostname"] + " (HTTPS only)"},
        {"role": "true", "plan_semantics": "child-zone authority; normal address " + true_addr +
                                           " and HTTPS content; the parent-side A for " + child_ns + " points here",
         "vpsless": "local lab_dns role true (port %d) + lab_http (port %d)" %
                    (cfg["local"]["true_dns_port"], cfg["local"]["true_https_port"]),
         "public": "cloudflared tunnel hostname " + cfg["tunnels"]["true"]["hostname"] + " (HTTPS only)"},
    ]


def parent_records(cfg):
    """Cloudflare rows for the parent zone. The child NS A keeps the TRUE address;
    the contradictory ADDITIONAL value is fixture data and never a record."""
    child_ns = norm(cfg["child_ns"]["name"])
    return [
        {"type": "NS", "name": norm(cfg["zones"]["provider"]),
         "content": ", ".join(cfg["secondary"].get("ns_names") or ["<PROVIDER_NS>"])},
        {"type": "A", "name": child_ns, "content": cfg["child_ns"]["true_address"],
         "proxied": False, "note": "parent-side A: must keep pointing at the TRUE side"},
        {"type": "CNAME", "name": cfg["tunnels"]["true"]["hostname"],
         "content": "<tunnel-target " + cfg["tunnels"]["true"]["name"] + ">", "proxied": True},
        {"type": "CNAME", "name": cfg["tunnels"]["fake"]["hostname"],
         "content": "<tunnel-target " + cfg["tunnels"]["fake"]["name"] + ">", "proxied": True},
    ]


def fixture_only_rows(cfg):
    return [{"type": "ADDITIONAL", "name": norm(cfg["child_ns"]["name"]),
             "content": cfg["child_ns"]["fake_address"],
             "cloudflare_record": False,
             "note": "contradictory referral ADDITIONAL fixture data; never publish this record"}]


def role_commands(cfg):
    child_zone_label = norm(cfg["zones"]["child"]).split(".")[0]
    zone = norm(cfg["zones"]["provider"])
    child_ns = norm(cfg["child_ns"]["name"])
    true_addr = cfg["child_ns"]["true_address"] or "192.0.2.10"
    fake_addr = cfg["child_ns"]["fake_address"] or "198.51.100.66"
    commands = {}
    for role, dns_port, https_port in (("true", cfg["local"]["true_dns_port"], cfg["local"]["true_https_port"]),
                                       ("fake", cfg["local"]["fake_dns_port"], cfg["local"]["fake_https_port"])):
        dns = ["python3", "poc/lab/dns/lab_dns.py", "--role", role, "--bind", "127.0.0.1",
               "--port", str(dns_port), "--zone", zone, "--child", child_zone_label,
               "--provider-ns", norm(cfg["hidden_primary"]["host"]), "--child-ns", child_ns,
               "--true-ip", true_addr, "--fake-ip", fake_addr, "--ttl", "0"]
        http = ["python3", "poc/lab/http/lab_http.py", "--role", role, "--bind", "127.0.0.1",
                "--port", str(https_port), "--cert", str(cfg["local"]["normal_fullchain"] or "<normal-fullchain.pem>"),
                "--key", str(cfg["local"]["normal_key"] or "<normal-key.pem>"),
                "--registry-dir", "poc/deploy/public-registry"]
        if role == "fake":
            http += ["--forged-cert", str(cfg["local"]["forged_fullchain"] or "<forged-fullchain.pem>"),
                     "--forged-key", str(cfg["local"]["forged_key"] or "<forged-key.pem>"),
                     "--forged-sni", "login." + norm(cfg["zones"]["child"]) + "," +
                     "pay." + norm(cfg["zones"]["child"]) + ",pkg." + norm(cfg["zones"]["child"])]
        commands[role] = {"dns": shlex.join(dns), "https": shlex.join(http)}
    return commands


def tunnel_configs(cfg):
    configs = {}
    for role in ("true", "fake"):
        tunnel = cfg["tunnels"][role]
        text = ("tunnel: " + str(tunnel["name"]) + "\n"
                "credentials-file: " + str(tunnel["credentials_file"] or
                                           "<~/.cloudflared/" + str(tunnel["name"]) + ".json>") + "\n"
                "ingress:\n"
                "  - hostname: " + tunnel["hostname"] + "\n"
                "    service: https://127.0.0.1:" + str(cfg["local"][role + "_https_port"]) + "\n"
                "    originRequest:\n"
                "      noTLSVerify: true\n"
                "  - service: http_status:404\n")
        commands = [
            "cloudflared tunnel login",
            "cloudflared tunnel create " + str(tunnel["name"]),
            "cloudflared tunnel route dns " + str(tunnel["name"]) + " " + tunnel["hostname"],
            "cloudflared tunnel --config <this-file> run " + str(tunnel["name"]),
        ]
        configs[role] = {"config_yaml": text, "commands": commands}
    return configs


# --------------------------------------------------------------------------
# preflight (fail closed) + plan + apply
# --------------------------------------------------------------------------

def preflight(cfg):
    rows = []

    def result(scope, status, description):
        rows.append({"scope": scope, "status": status, "description": description})

    secondary = cfg["secondary"]
    if secondary.get("account") and secondary.get("api_token"):
        result("credentials", "PASS", "secondary-DNS account and API token supplied (own account)")
    else:
        result("credentials", "BLOCKED",
               "secondary-DNS account/API token missing: deployment stays disabled (fail closed)")
    tunnels_ready = all(cfg["tunnels"][role].get("token") or cfg["tunnels"][role].get("credentials_file")
                        for role in ("true", "fake"))
    result("credentials", "PASS" if tunnels_ready else "BLOCKED",
           "cloudflared tunnel tokens/credentials present" if tunnels_ready else
           "cloudflared tunnel token or credentials file missing for true/fake: deployment stays disabled")
    checklist = cfg["checklist"]
    if checklist.get("own_domains_confirmed") and checklist.get("tos_reviewed"):
        result("ethics", "PASS", "checklist attested: own domains, ToS reviewed, provider gets notified")
    else:
        result("ethics", "BLOCKED",
               "checklist not attested (own_domains_confirmed/tos_reviewed): deployment stays disabled")
    if secondary.get("master_ip"):
        result("primary", "PASS", "hidden primary reachable at " + secondary["master_ip"])
    else:
        result("primary", "PENDING", "hidden primary IP not assigned (must accept the provider's AXFR)")
    if secondary.get("ns_names") and secondary.get("ns_ips"):
        result("provider", "PASS", "secondary NS set recorded: " + ", ".join(secondary["ns_names"]))
    else:
        result("provider", "PENDING", "secondary NS names/IPs not recorded yet (after registration)")
    for role in ("true", "fake"):
        supplied = all(cfg["local"].get(field) for field in
                       (("normal_fullchain", "normal_key") if role == "true" else
                        ("normal_fullchain", "normal_key", "forged_fullchain", "forged_key")))
        result("https", "PASS" if supplied else "PENDING",
               role + " leaf inputs " + ("supplied" if supplied else "missing (normal" +
                                        ("" if role == "true" else " + forged") + " fullchain and key)"))
    result("local", "PASS", "role commands render from the lab contract (--child-ns)")
    result("external", "PENDING",
           "delegation, AXFR-in, tunnel publishing, and public HTTPS have not been tested here")
    return rows


def plan_text(cfg):
    lines = []
    lines.append("== VPS-less deployment plan (dry run; nothing is contacted) ==")
    lines.append("schema: " + SCHEMA + "   generated: " +
                 datetime.now(timezone.utc).isoformat(timespec="seconds"))
    lines.append("")
    lines.append("== role map (poc/PLAN.md semantics -> VPS-less realization) ==")
    for row in role_map(cfg):
        lines.append(" %-8s %s" % (row["role"], row["plan_semantics"]))
        lines.append("          local : " + row["vpsless"])
        lines.append("          public: " + row["public"])
    lines.append("")
    lines.append("== hidden-primary zone (provider zone with the fixture) ==")
    lines.append(provider_zone_text(cfg).rstrip())
    lines.append("")
    lines.append("== named.conf fragment (BIND alternative; allow-transfer = provider AXFR source IPs) ==")
    transfer = cfg["secondary"].get("axfr_source_ips") or []
    lines.append(named_conf_fragment({"tzone": norm(cfg["zones"]["provider"])}, transfer).rstrip())
    lines.append("")
    lines.append("== hidden primary (tiny built-in server; permissive ingest) ==")
    lines.append("python3 poc/deploy/secondary_deploy.py serve-primary --config <this-config> --execute")
    lines.append("")
    lines.append("== secondary registration (adapter: " + cfg["secondary"]["adapter"] + ") ==")
    adapter = ADAPTERS[cfg["secondary"]["adapter"]](cfg["secondary"])
    lines.append(json.dumps(adapter.plan({"zone": norm(cfg["zones"]["provider"]),
                                          "master_ip": cfg["secondary"].get("master_ip"),
                                          "tsig": cfg["secondary"].get("tsig")}),
                            indent=2, sort_keys=True))
    lines.append("")
    lines.append("== local role services ==")
    for role, commands in role_commands(cfg).items():
        lines.append(" " + role + " dns : " + commands["dns"])
        lines.append(" " + role + " https: " + commands["https"])
    lines.append("")
    lines.append("== cloudflared tunnels (HTTPS only; cloudflared does not proxy DNS) ==")
    for role, spec in tunnel_configs(cfg).items():
        lines.append(" -- " + role + " --")
        lines.append(spec["config_yaml"].rstrip())
        for command in spec["commands"]:
            lines.append("   $ " + command)
    lines.append("")
    lines.append("== parent-zone record plan (owner sets these) ==")
    lines.append(json.dumps({"cloudflare_records_to_review": parent_records(cfg),
                             "fixture_only_never_a_record": fixture_only_rows(cfg),
                             "null_means_unassigned": True},
                            indent=2, sort_keys=True))
    lines.append("")
    lines.append("== limits (kept honest) ==")
    lines.append(" - fake/true child authorities stay loopback fixtures: cloudflared publishes")
    lines.append("   HTTPS only. Publish them publicly only via a second secondary or a")
    lines.append("   reachable IP; until then the child-authority comparison is local.")
    lines.append(" - child_ns A values are RFC 5737 TEST-NET by default and carry DNS semantics;")
    lines.append("   demo content reachability is the tunnel hostnames.")
    lines.append(" - no vendor, registry, or tunnel service is contacted by plan/preflight.")
    return "\n".join(lines) + "\n"


def apply_outputs(cfg):
    """Files apply would write (dry-run safe; no side effects here)."""
    tunnels = tunnel_configs(cfg)
    return {
        "provider.zone": provider_zone_text(cfg),
        "named.conf.fragment": named_conf_fragment(
            {"tzone": norm(cfg["zones"]["provider"])}, cfg["secondary"].get("axfr_source_ips") or []),
        "cloudflared-true.yml": tunnels["true"]["config_yaml"],
        "cloudflared-fake.yml": tunnels["fake"]["config_yaml"],
        "role-commands.json": json.dumps(role_commands(cfg), indent=2, sort_keys=True) + "\n",
        "parent-records.json": json.dumps({"cloudflare_records_to_review": parent_records(cfg),
                                           "fixture_only_never_a_record": fixture_only_rows(cfg)},
                                          indent=2, sort_keys=True) + "\n",
    }


# --------------------------------------------------------------------------
# serve-primary + CLI
# --------------------------------------------------------------------------

def serve_primary(cfg):
    """Run the hidden primary on loopback: permissive ingest, AXFR enabled."""
    from dnslib.server import DNSLogger, DNSServer
    from gapb_test import ZoneResolver
    records = [
        {"name": norm(cfg["zones"]["provider"]), "type": "SOA", "ttl": 3600,
         "rdata": (norm(cfg["hidden_primary"]["host"]),
                   "hostmaster." + norm(cfg["domain"]), serial_for(provider_zone_cfg(cfg)))},
        {"name": norm(cfg["zones"]["provider"]), "type": "NS", "ttl": 3600,
         "rdata": norm(cfg["hidden_primary"]["host"])},
        {"name": norm(cfg["hidden_primary"]["host"]), "type": "A", "ttl": 3600,
         "rdata": cfg["hidden_primary"]["ip"] or "127.0.0.1"},
        {"name": norm(cfg["zones"]["child"]), "type": "NS", "ttl": 300,
         "rdata": norm(cfg["child_ns"]["name"])},
        {"name": norm(cfg["child_ns"]["name"]), "type": "A", "ttl": 300,
         "rdata": cfg["child_ns"]["fake_address"] or "198.51.100.66"},
    ]
    port = int(cfg["hidden_primary"]["port"])
    logger = DNSLogger(log="-request,-reply,-truncated,-error")
    servers = [DNSServer(ZoneResolver(records), address="127.0.0.1", port=port, tcp=tcp, logger=logger)
               for tcp in (False, True)]
    for server in servers:
        server.start_thread()
    print("hidden primary serving " + norm(cfg["zones"]["provider"]) + " on 127.0.0.1:" + str(port))
    print("AXFR enabled (permissive ingest: the provider's ingest is what is under test)")
    import time
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.stop()
            server.server.server_close()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="mandatory dry run: roles, zone, adapters, tunnels, records")
    plan.add_argument("--config", type=Path, default=None)
    pre = sub.add_parser("preflight", help="fail-closed readiness report")
    pre.add_argument("--config", type=Path, default=None)
    apply_cmd = sub.add_parser("apply", help="write artifacts and print the remaining manual steps")
    apply_cmd.add_argument("--config", type=Path, default=None)
    apply_cmd.add_argument("--out", type=Path, required=True)
    apply_cmd.add_argument("--execute", action="store_true")
    apply_cmd.add_argument("--plan-reviewed", action="store_true")
    serve = sub.add_parser("serve-primary", help="run the local hidden primary (loopback)")
    serve.add_argument("--config", type=Path, default=None)
    serve.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.command == "plan":
        print(plan_text(cfg))
        return 0
    if args.command == "preflight":
        rows = preflight(cfg)
        for row in rows:
            print(row["status"] + " [" + row["scope"] + "] " + row["description"])
        print("Dry run only: no provider, tunnel, or registry service was contacted.")
        return 1 if any(row["status"] == "BLOCKED" for row in rows) else 0
    if args.command == "serve-primary":
        if not args.execute:
            print("dry run: the primary is not started. Use --execute on your own machine.")
            print(plan_text(cfg))
            return 0
        return serve_primary(cfg)
    # apply
    rows = preflight(cfg)
    blocked = [row for row in rows if row["status"] == "BLOCKED"]
    if not args.execute or not args.plan_reviewed:
        print("dry run: nothing written. Run 'plan', review it, then apply with "
              "--execute --plan-reviewed on your own account.")
        print(plan_text(cfg))
        return 0
    if blocked:
        raise DeployError("apply refused (fail closed):\n" +
                          "\n".join(row["description"] for row in blocked))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in apply_outputs(cfg).items():
        (args.out / name).write_text(text)
    print("wrote artifacts to " + str(args.out))
    print("remaining manual steps: complete the secondary registration and tunnel commands")
    print("printed by 'plan', set the parent records from parent-records.json, then run the")
    print("acceptance probes. The contradictory ADDITIONAL fixture stays data, never a record.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DeployError, GapBError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
