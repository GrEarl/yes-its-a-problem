# DNS + TLS PoC: design and current limits

[English](PLAN.md) | [日本語](PLAN.ja.md)

## Purpose

This repository is an educational demonstration of two separate ideas: how DNS authority answers can disagree, and how clients classify a server certificate. It does not establish that a general-purpose recursive resolver is vulnerable, nor that the DNS and TLS observations occur on the same connection.

The public case observed on 2026-10-24 is recorded in [README.md](README.md) and the evidence JSON under `../artifacts/`. It involved an external NS name and a differing Additional address. It is not RFC 9471 sibling glue. The bounded observations do not establish generic cache poisoning or tenant takeover.

## Intended names and roles

| Name or role | Intended value |
|---|---|
| Public page | `yes-its-a-problem.iamwonderingif.com` |
| Parent zone | `iamwonderingif.com`, managed in Cloudflare account `grey` |
| Delegated lab zone | `lab.yes-its-a-problem.iamwonderingif.com` |
| Child test zone | `v.lab.yes-its-a-problem.iamwonderingif.com` |
| Parent-side provider NS | `ns1.yes-its-a-problem.iamwonderingif.com` -> IP1 |
| Child NS name in the parent zone | `ns-child.yes-its-a-problem.iamwonderingif.com` -> IP3 |

Three separate Ubuntu 24.04 LTS VPSs are assumed. Each needs a distinct public IPv4 directly assigned to its interface and a separate SSH alias.

| Server | Service and intended behavior |
|---|---|
| IP1 `provider` | Authoritative for `lab...`; serves the delegation for `v.lab...`. The intended fixture includes an Additional address for `ns-child...` that points to IP2. |
| IP2 `fake` | Authoritative for `v.lab...` in the test design; serves the alternate address and HTTPS content. |
| IP3 `true` | Authoritative for `v.lab...`; serves the normal address and HTTPS content. Cloudflare's parent-zone A record for `ns-child...` also points here. |

Cloudflare's parent zone owns the ordinary A records for `ns1...` and `ns-child...`; it delegates `lab...` to `ns1...`. The parent-side `ns-child...` A remains IP3. It must never be changed to IP2. The contradictory Additional record is data returned by the lab authority, not a Cloudflare record.

**Contract implemented (2026-10-24):** `lab_dns.py` accepts `--child-ns`. With it, the provider referral uses an external NS name outside the provider zone plus an unrelated ADDITIONAL A for that name, direct out-of-zone queries for the external name are refused, and the true/fake authorities use the external name. `test_local.sh` scenario 2 exercises this contract on loopback; the older in-zone fixture remains scenario 1. This is still a fixed local fixture: it does not query public resolvers, and no resolver-choice paths are simulated by `simulate.py`.

## HTTPS and certificate behavior

DNS and TLS checks use separate requests. Random probe names use the ordinary ACME wildcard certificate for `*.v.lab...`. The fake HTTPS server is intended to use that certificate for ordinary SNI and to accept a separately supplied, already-issued leaf and matching leaf key for the fixed `login`, `pay`, and `pkg` names. The true server uses only the ordinary certificate. Kirimochi's four fixed public fixture files are served from the existing HTTPS listener.

The TLS endpoint reports the certificate classification and certificate hashes observed by the server. The browser validates the HTTPS connection to the page/API and checks the response shape; it cannot independently compare the remote endpoint's certificate with the server-reported hashes. Local regression uses synthetic test CAs. The deployment tool requires existing leaf inputs and excludes CA private keys, recovery material, and the whole `secrets/` directory from transfer.

The repository includes code that reconstructs compromised eMudhra CA keys from public certificates. Those CAs are revoked. Recovery and signing with those keys are not part of the synthetic test suite. Keep CA private keys off public servers.

## Escalation beyond the demonstrated scope

The deployed threat model is the two demonstrated steps: a resolver-visible
misdirection and a client that accepts a forged certificate, which together
let the attacker read and rewrite the session (the fake server mirrors the
genuine quote values, so the client's data checks pass). The same control of
response bodies escalates to RCE when the body reaches a flawed decoder.
CVE-2026-111497 ("Node2Shell" / "HTTP2Shell") is the current live example:
an out-of-bounds write in the Brotli decoder bundled with Node.js ("an
attacker who can supply Brotli data that an application decompresses with
node:zlib can corrupt process memory"), rated High by Node.js (fixed
22.23.4 / 24.22.1 / 26.12.1) and Critical in GHSA-9v8h-qqgm-4m35 (PyPI
brotli/brotlicffi fixed 1.2.1 / 1.2.1.0), with public profile-pinned RCE
harnesses already available. This repository documents that escalation with
citations (see the repository README) and implements none of it: no exploit
code, no malformed streams, and no Content-Encoding handling in the lab
servers or clients.

## Local checks

Run tests from the repository root. They use local fixtures and synthetic certificates; they do not validate public resolver behavior.

```sh
python3 -B poc/lab/test_lab.py
bash poc/lab/dns/test_local.sh
python3 -B demo/fake-pkg/test_kirimochi.py
node demo/electron-payment/test.js
node docs/test.js
python3 -B -m unittest discover -s poc/deploy -p 'test_*.py' -v
python3 poc/deploy/deploy.py preflight
```

The deployment preflight passes the DNS contract and exits 0; its remaining `PENDING` rows are the unassigned VPS inputs and the unverified external steps. Do not treat any local test pass as completing those external steps.

## Deployment readiness

See [the three-VPS deployment runbook](deploy/README.md) for the full input schema, safety checks, Cloudflare record plan, ordinary ACME DNS-01 hooks, allowed file transfer, services, acceptance commands, and cleanup. No VPS has been contracted. The runbook has not been exercised against real servers.

Public Pages, Cloudflare changes, public delegation, provider permission for inbound UDP/TCP 53, ACME issuance/renewal, supplied certificate inputs, GitHub release CI, browser behavior, and public resolver paths remain unverified. The plan must be updated after a real deployment rather than treating intended behavior as observed evidence.
