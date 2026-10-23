# Yes, it's a problem

[English](README.md) | [日本語](README.ja.md)

A PoC combining DNS delegation responses and TLS certificate verification.

1. A recursive resolver accepts an out-of-bailiwick ADDITIONAL glue record in a delegation response. Instead of resolving the nameserver name separately, it uses the attacker's address.
2. A TLS client accepts a forged certificate. The certificate is signed with a recovered eMudhra intermediate CA private key.

Original research (third party): <https://emudhra.we-have-a-problem.com/>

## Sources and advisories

- [Proof bundle](https://emudhra.we-have-a-problem.com/proof.zip)
- [Published certificate chains](https://emudhra.we-have-a-problem.com/chains.zip)
- [Mozilla incident report](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla dev-security-policy thread](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)
- [Chromium CRLSets](https://www.chromium.org/Home/chromium-security/crlsets/)
- [Patched versions by OS and distribution](https://emudhra.we-have-a-problem.com/#patched-os)

## DNS glue background

- [Cloudflare Community: 1.1.1.1 answers a wrong A record when the authority nameserver has an unrelated ADDITIONAL](https://community.cloudflare.com/t/1-1-1-1-answers-wrong-a-record-when-authority-name-server-has-unrelated-addtional/966458) — community report of the same steering shape this lab reproduces.
- [Rethinking the Security Threats of Stale DNS Glue Records (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-zhang-yunyi-rethinking.pdf) ([presentation](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yunyi-rethinking)) — adjacent work on stale glue; cited for the class of behavior.
- [ISC BIND: Impact of Stricter Glue Checking](https://kb.isc.org/docs/strict-glue) — BIND 9.18.41 / 9.20.15 / 9.21.14 trust glue only when the NS target is a subdomain of the delegation owner; the fix this project asks providers to adopt.

## Post-MITM escalation (CVE-2026-111497, "Node2Shell" / "HTTP2Shell")

- [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) — Brotli decoder out-of-bounds write permits remote code execution.
- [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) — same decoder flaw in the PyPI Brotli package.
- [Imperva: Node2Shell, from Brotli data to remote code execution](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
- Public PoCs: [dimasma0305/CVE-2026-111497-POC](https://github.com/dimasma0305/CVE-2026-111497-POC), [gh0st-nemesis/node2shell-poc](https://github.com/gh0st-nemesis/node2shell-poc), [6mile/node-python2shell](https://github.com/6mile/node-python2shell). Their RCE result is configuration-dependent.

## Use and limits

Run this only against the lab names in this repository or hosts you control.
The eMudhra intermediates used here are revoked; see the linked incident
report for the platform response. No private keys are included, but the
repository does include code that reconstructs the compromised CA key from
its public certificate (the original key generation was flawed). Keep
recovered keys local in ignored `secrets/`; never place the CA key on a
public server. See [SECURITY.md](SECURITY.md).

## Escalation beyond the demonstrated chain

The PoC shows two positions **separately**: the client is steered to an
attacker-controlled server, and the client accepts a forged certificate for
it. Together they would let the attacker read and rewrite the session; they
have not been shown on one connection and one path.

The fake lab server's behaviour is selectable with `--behavior`:
`redirect` (default) keeps the quote genuine and rewrites only the payment;
`observe` mirrors the genuine values so the client's own checks pass while
every value is attacker-supplied; `tamper` rewrites both, which a client
that inspects the payload catches at the quote stage.

The same position *reaches* the precondition for code execution where a
response body is decompressed by a Brotli decoder built from google/brotli
1.0.3-1.2.0 (CVE-2026-111497). The precondition is real; the RCE stage itself
is not produced here and no exploit payload ships. In the payment and package
flows no client decodes `Content-Encoding: br`; the lab-only update flows
reach the decoder on purpose, with a valid Brotli lab marker. An Electron
app's CVE-2026-111497 exposure tracks its **Chromium** version (not bundled
Node): Electron 41 and below (Chromium < 148) is affected, Electron 42 and
above is not. Electron 36 is end-of-support.

## Layout

| Path | Contents |
|---|---|
| `docs/` | DNS and TLS checks. Source for GitHub Pages. |
| `demo/electron-payment/` | Electron transfer screen. Compares a legacy build with a current build. |
| `demo/fake-pkg/` | Kirimochi. English-only package manager demo. |
| `poc/` | DNS lab, HTTP(S) servers, certificate generation, design notes. |
| `.github/workflows/release.yml` | Builds the Electron demos and `kirimochi.pyz`, and publishes a release on `v*` tags. |

## Local checks

Create the leaf certificate first. On the first run, `make_leaf.py` recovers the CA private key from the public CA certificate into `secrets/artifacts/keys`.

    python3 poc/lab/certs/make_leaf.py --days 30

    # DNS loopback check
    bash poc/lab/dns/test_local.sh

    # Mock registry
    python3 demo/fake-pkg/server/mock_registry.py --port 9445 \
      --cert secrets/demo-cert/fullchain.pem \
      --key secrets/demo-cert/leaf.key.pem

    # Package manager
    python3 demo/fake-pkg/src/kirimochi.py install demo-lib \
      --url https://pkg.v.lab.yes-its-a-problem.iamwonderingif.com:9445 \
      --connect 127.0.0.1:9445

Prerequisites: Python 3, `cryptography`, OpenSSL, and `dig`.

Certificates and private keys are written to `secrets/`, which is gitignored.

## Build

Push a tag such as `v0.1.0`. GitHub Actions builds the Electron legacy and hardened builds and `kirimochi.pyz`, then uploads them to a GitHub Release.
